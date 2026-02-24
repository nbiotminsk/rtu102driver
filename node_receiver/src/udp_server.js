import dgram from "node:dgram";
import { decodeDatagram, ProtocolError } from "./protocol.js";

export class UdpReceiverServer {
  constructor(config, writer, logLevel = "info") {
    this.config = config;
    this.writer = writer;
    this.logLevel = logLevel;
  }

  async run(once = false) {
    const socket = dgram.createSocket("udp4");
    await new Promise((resolve, reject) => {
      socket.once("error", reject);
      socket.bind(this.config.listenPort, this.config.listenHost, () => {
        socket.removeListener("error", reject);
        resolve();
      });
    });

    if (this.logLevel === "debug") {
      // eslint-disable-next-line no-console
      console.log(`listening on udp://${this.config.listenHost}:${this.config.listenPort}`);
    }

    if (once) {
      try {
        const { msg, rinfo } = await this.#waitOneDatagram(socket, 5000);
        await this.handleDatagram(msg, rinfo.address, rinfo.port);
      } finally {
        socket.close();
      }
      return;
    }

    socket.on("message", (msg, rinfo) => {
      this.handleDatagram(msg, rinfo.address, rinfo.port).catch(() => {});
    });

    await new Promise((_, reject) => {
      socket.once("error", (err) => {
        socket.close();
        reject(err);
      });
    });
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

  #waitOneDatagram(socket, timeoutMs) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error("timeout waiting for UDP datagram"));
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
}
