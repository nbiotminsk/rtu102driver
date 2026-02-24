import { createWriteStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";

function utcNowIso() {
  return new Date().toISOString();
}

function dateSuffixUTC() {
  const now = new Date();
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, "0");
  const day = String(now.getUTCDate()).padStart(2, "0");
  return `${year}${month}${day}`;
}

function writeLine(stream, line) {
  return new Promise((resolve, reject) => {
    stream.write(line, "utf8", (err) => {
      if (err) {
        reject(err);
        return;
      }
      resolve();
    });
  });
}

function closeStream(stream) {
  return new Promise((resolve, reject) => {
    const onClose = () => {
      cleanup();
      resolve();
    };
    const onError = (err) => {
      cleanup();
      reject(err);
    };
    const cleanup = () => {
      stream.off("close", onClose);
      stream.off("error", onError);
    };

    stream.on("close", onClose);
    stream.on("error", onError);
    stream.end();
  });
}

export class JsonlWriter {
  constructor(logDir) {
    this.logDir = logDir;
    this.ready = mkdir(logDir, { recursive: true });
    this.queue = Promise.resolve();
    this.closed = false;
    this.streamStates = new Map();
  }

  utcNowIso() {
    return utcNowIso();
  }

  async writeRaw(record) {
    return this.#enqueue(() => this.#write("raw", record));
  }

  async writeDecoded(record) {
    return this.#enqueue(() => this.#write("decoded", record));
  }

  async writeError(record) {
    return this.#enqueue(() => this.#write("errors", record));
  }

  async close() {
    if (this.closed) {
      return;
    }
    this.closed = true;

    let pendingError = null;
    try {
      await this.queue;
    } catch (err) {
      pendingError = err;
    }

    for (const state of this.streamStates.values()) {
      await closeStream(state.stream);
    }
    this.streamStates.clear();

    if (pendingError) {
      throw pendingError;
    }
  }

  #enqueue(task) {
    if (this.closed) {
      return Promise.reject(new Error("writer is closed"));
    }
    const next = this.queue.then(task);
    this.queue = next;
    return next;
  }

  async #write(streamName, record) {
    await this.ready;

    const suffix = dateSuffixUTC();
    const stream = await this.#getStream(streamName, suffix);
    await writeLine(stream, `${JSON.stringify(record)}\n`);
  }

  async #getStream(streamName, suffix) {
    const current = this.streamStates.get(streamName);
    if (current && current.suffix === suffix) {
      return current.stream;
    }

    if (current) {
      await closeStream(current.stream);
    }

    const path = join(this.logDir, `${streamName}-${suffix}.jsonl`);
    const stream = createWriteStream(path, {
      flags: "a",
      encoding: "utf8",
      autoClose: true,
    });
    this.streamStates.set(streamName, { suffix, stream });
    return stream;
  }
}
