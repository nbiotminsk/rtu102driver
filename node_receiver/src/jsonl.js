import { mkdir, appendFile } from "node:fs/promises";
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

export class JsonlWriter {
  constructor(logDir) {
    this.logDir = logDir;
    this.ready = mkdir(logDir, { recursive: true });
  }

  utcNowIso() {
    return utcNowIso();
  }

  async writeRaw(record) {
    await this.#write("raw", record);
  }

  async writeDecoded(record) {
    await this.#write("decoded", record);
  }

  async writeError(record) {
    await this.#write("errors", record);
  }

  async #write(stream, record) {
    await this.ready;
    const path = join(this.logDir, `${stream}-${dateSuffixUTC()}.jsonl`);
    await appendFile(path, `${JSON.stringify(record)}\n`, "utf8");
  }
}
