import { readFile } from "node:fs/promises";

function parseHexKey(hexValue, field, allowNull = true) {
  if (hexValue === null || hexValue === undefined) {
    if (allowNull) {
      return null;
    }
    throw new Error(`${field} cannot be null`);
  }
  if (typeof hexValue !== "string") {
    throw new Error(`${field} must be null or hex string`);
  }
  if (hexValue.length !== 32) {
    throw new Error(`${field} must be exactly 32 hex characters`);
  }
  if (!/^[0-9a-fA-F]+$/.test(hexValue)) {
    throw new Error(`${field} must be valid hex`);
  }
  const key = Buffer.from(hexValue, "hex");
  if (key.length !== 16) {
    throw new Error(`${field} must decode to 16 bytes`);
  }
  return key;
}

export async function loadConfig(path) {
  let raw;
  try {
    raw = JSON.parse(await readFile(path, "utf8"));
  } catch (err) {
    if (err && err.code === "ENOENT") {
      throw new Error(`config file not found: ${path}`);
    }
    if (err instanceof SyntaxError) {
      throw new Error(`invalid JSON config: ${err.message}`);
    }
    throw err;
  }

  const listenHost = raw.listen_host ?? "127.0.0.1";
  const listenPort = raw.listen_port ?? 5000;
  const logDir = raw.log_dir ?? "./logs";
  const decodeEnabled = raw.decode_enabled ?? true;
  const maxPendingDatagrams = raw.max_pending_datagrams ?? 1000;
  const keys = raw.keys ?? {};

  if (typeof listenHost !== "string" || listenHost.length === 0) {
    throw new Error("listen_host must be a non-empty string");
  }
  if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) {
    throw new Error("listen_port must be an integer in range 1..65535");
  }
  if (typeof logDir !== "string" || logDir.length === 0) {
    throw new Error("log_dir must be a non-empty string");
  }
  if (typeof decodeEnabled !== "boolean") {
    throw new Error("decode_enabled must be boolean");
  }
  if (!Number.isInteger(maxPendingDatagrams) || maxPendingDatagrams < 1 || maxPendingDatagrams > 100000) {
    throw new Error("max_pending_datagrams must be an integer in range 1..100000");
  }
  if (typeof keys !== "object" || keys === null || Array.isArray(keys)) {
    throw new Error("keys must be an object");
  }

  const defaultKey = parseHexKey(keys.default_hex, "keys.default_hex", true);
  const byImeiRaw = keys.by_imei ?? {};
  if (typeof byImeiRaw !== "object" || byImeiRaw === null || Array.isArray(byImeiRaw)) {
    throw new Error("keys.by_imei must be an object");
  }

  const byImei = new Map();
  for (const [imei, keyHex] of Object.entries(byImeiRaw)) {
    if (!/^\d+$/.test(imei)) {
      throw new Error("keys.by_imei keys must be IMEI strings with digits only");
    }
    byImei.set(imei, parseHexKey(keyHex, `keys.by_imei[${imei}]`, false));
  }

  return {
    listenHost,
    listenPort,
    logDir,
    decodeEnabled,
    maxPendingDatagrams,
    keys: {
      defaultKey,
      byImei,
      resolveKey(imei) {
        if (this.byImei.has(imei)) {
          return this.byImei.get(imei);
        }
        return this.defaultKey;
      },
    },
  };
}
