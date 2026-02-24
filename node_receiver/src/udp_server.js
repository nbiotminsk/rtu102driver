import dgram from "node:dgram";
import { decodeDatagram, ProtocolError } from "./protocol.js";

export class UdpTimeoutError extends Error {
  constructor(message = "timeout waiting for UDP datagram") {
    super(message);
    this.name = "UdpTimeoutError";
  }
}

export class UdpReceiverServer {
  constructor(config, writer, logLevel = "info") {
    this.config = config;
    this.writer = writer;
    this.logLevel = logLevel;

    this.socket = null;
    this.running = false;
    this.stopping = false;
    this.fatalError = null;

    this.pendingDatagrams = 0;
    this.processingQueue = Promise.resolve();
    this.runClosed = null;
    this.lastOverflowLogMs = 0;
    this.droppedDatagrams = 0;
  }

  async run(once = false) {
    if (this.running) {
      throw new Error("server already running");
    }

    this.running = true;
    this.stopping = false;
    this.fatalError = null;
    this.pendingDatagrams = 0;
    this.processingQueue = Promise.resolve();
    this.droppedDatagrams = 0;
    this.lastOverflowLogMs = 0;

    const socket = dgram.createSocket("udp4");
    this.socket = socket;

    try {
      await this.#bindSocket(socket);

      if (this.logLevel === "debug") {
        // eslint-disable-next-line no-console
        console.log(`listening on udp://${this.config.listenHost}:${this.config.listenPort}`);
      }

      if (once) {
        const { msg, rinfo } = await this.#waitOneDatagram(socket, 5000);
        await this.handleDatagram(msg, rinfo.address, rinfo.port);
        return;
      }

      this.runClosed = new Promise((resolve) => {
        socket.once("close", resolve);
      });

      socket.on("message", (msg, rinfo) => {
        this.#onMessage(msg, rinfo);
      });

      socket.on("error", (err) => {
        void this.#fail(err);
      });

      await this.runClosed;
      await this.#drainProcessingQueue();

      if (this.fatalError) {
        throw this.fatalError;
      }
    } finally {
      await this.#closeSocketIfOpen();
      await this.#drainProcessingQueue();
      this.socket = null;
      this.runClosed = null;
      this.running = false;
      this.stopping = false;
    }
  }

  async stop() {
    if (!this.running) {
      return;
    }

    this.stopping = true;
    await this.#closeSocketIfOpen();

    if (this.runClosed) {
      await this.runClosed;
    }
    await this.#drainProcessingQueue();
  }

  async handleDatagram(datagram, srcIp, srcPort) {
    const ts = this.writer.utcNowIso();
    const datagramHex = datagram.toString("hex");

    await this.writer.writeRaw({
      ts_utc: ts,
      src_ip: srcIp,
      src_port: srcPort,
      len: datagram.length,
      datagram_hex: datagramHex,
    });

    if (!this.config.decodeEnabled) {
      return;
    }

    try {
      const result = decodeDatagram(datagram, (imei) => this.config.keys.resolveKey(imei));
      await this.#writeDecoded(ts, srcIp, srcPort, result);
      await this.#writeNonfatalErrors(ts, srcIp, srcPort, datagramHex, result);
    } catch (err) {
      if (!(err instanceof ProtocolError)) {
        throw err;
      }
      await this.writer.writeError({
        ts_utc: ts,
        src_ip: srcIp,
        src_port: srcPort,
        stage: err.stage,
        reason: err.reason,
        imei: err.imei,
        datagram_hex: datagramHex,
        details: err.details,
      });
    }
  }

  #maxPendingDatagrams() {
    return this.config.maxPendingDatagrams ?? 1000;
  }

  #onMessage(msg, rinfo) {
    if (this.stopping) {
      return;
    }

    if (this.pendingDatagrams >= this.#maxPendingDatagrams()) {
      this.droppedDatagrams += 1;
      void this.#recordQueueOverflow(msg, rinfo);
      return;
    }

    const datagram = Buffer.from(msg);
    const srcIp = rinfo.address;
    const srcPort = rinfo.port;

    this.pendingDatagrams += 1;
    this.processingQueue = this.processingQueue
      .then(() => this.handleDatagram(datagram, srcIp, srcPort))
      .catch(async (err) => {
        await this.#fail(err);
      })
      .finally(() => {
        this.pendingDatagrams -= 1;
      });
  }

  async #recordQueueOverflow(msg, rinfo) {
    const nowMs = Date.now();
    if (nowMs - this.lastOverflowLogMs < 1000) {
      return;
    }
    this.lastOverflowLogMs = nowMs;

    const datagramHex = Buffer.from(msg).toString("hex");
    try {
      await this.writer.writeError({
        ts_utc: this.writer.utcNowIso(),
        src_ip: rinfo.address,
        src_port: rinfo.port,
        stage: "transport_queue",
        reason: "queue_overflow",
        imei: null,
        datagram_hex: datagramHex,
        details: {
          pending: this.pendingDatagrams,
          max_pending: this.#maxPendingDatagrams(),
          dropped_total: this.droppedDatagrams,
        },
      });
    } catch (err) {
      await this.#fail(err);
    }
  }

  async #writeDecoded(ts, srcIp, srcPort, result) {
    await this.writer.writeDecoded({
      ...result,
      ts_utc: ts,
      src_ip: srcIp,
      src_port: srcPort,
    });
  }

  async #writeNonfatalErrors(ts, srcIp, srcPort, datagramHex, result) {
    for (const err of result.nonfatal_errors) {
      await this.writer.writeError({
        ts_utc: ts,
        src_ip: srcIp,
        src_port: srcPort,
        stage: err.stage ?? "payload_parse",
        reason: err.reason ?? "nonfatal_parse_warning",
        imei: result.imei,
        datagram_hex: datagramHex,
        details: err.details ?? {},
      });
    }
  }

  async #fail(err) {
    if (this.fatalError) {
      return;
    }
    this.fatalError = err instanceof Error ? err : new Error(String(err));
    this.stopping = true;
    await this.#closeSocketIfOpen();
  }

  #bindSocket(socket) {
    return new Promise((resolve, reject) => {
      socket.once("error", reject);
      socket.bind(this.config.listenPort, this.config.listenHost, () => {
        socket.removeListener("error", reject);
        resolve();
      });
    });
  }

  #waitOneDatagram(socket, timeoutMs) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new UdpTimeoutError());
      }, timeoutMs);

      const onError = (err) => {
        cleanup();
        reject(err);
      };

      const onMessage = (msg, rinfo) => {
        cleanup();
        resolve({ msg, rinfo });
      };

      const cleanup = () => {
        clearTimeout(timer);
        socket.off("error", onError);
        socket.off("message", onMessage);
      };

      socket.on("error", onError);
      socket.on("message", onMessage);
    });
  }

  async #closeSocketIfOpen() {
    if (!this.socket) {
      return;
    }
    const socket = this.socket;
    if (typeof socket.closed === "boolean" && socket.closed) {
      return;
    }
    await new Promise((resolve) => {
      const onClose = () => {
        socket.off("close", onClose);
        resolve();
      };
      socket.once("close", onClose);
      try {
        socket.close();
      } catch {
        socket.off("close", onClose);
        resolve();
      }
    });
  }

  async #drainProcessingQueue() {
    try {
      await this.processingQueue;
    } catch {
      // Errors are captured in this.fatalError.
    }
  }
}
