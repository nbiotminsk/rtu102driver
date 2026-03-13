import { decodeDatagram } from "./protocol.js";
import { parseHexDump } from "./key_probe.js";

function parseCliKey(keyValue) {
  if (typeof keyValue !== "string" || keyValue.length === 0) {
    throw new Error("key is required");
  }
  if (keyValue.length === 16) {
    return Buffer.from(keyValue, "ascii");
  }
  if (keyValue.length === 32 && /^[0-9a-fA-F]+$/.test(keyValue)) {
    return Buffer.from(keyValue, "hex");
  }
  throw new Error("key must be 16 ASCII characters or 32 hex characters");
}

function decodeScalar(item) {
  const buf = Buffer.from(item.data_hex, "hex");
  if (item.len === 1) {
    return buf.readUInt8(0);
  }
  if (item.len === 2) {
    return buf.readUInt16LE(0);
  }
  if (item.len === 4) {
    return buf.readUInt32LE(0);
  }

  const ascii = buf.toString("ascii").replace(/\x00+$/u, "");
  if (ascii.length > 0 && /^[\x20-\x7e]*$/u.test(ascii)) {
    return ascii;
  }
  return null;
}

function formatTelemetry(record) {
  return {
    id: record.id,
    type: record.type,
    count: record.count,
    items: record.items.map((item) => ({
      param_id: item.param_id,
      len: item.len,
      data_hex: item.data_hex,
      value: decodeScalar(item),
    })),
  };
}

function formatRecord(record) {
  if (record.type === "telemetry") {
    return formatTelemetry(record);
  }
  return record;
}

export function decodeDump(rawDump, keyValue) {
  const datagram = parseHexDump(rawDump);
  const key = parseCliKey(keyValue);
  const decoded = decodeDatagram(datagram, () => key);

  return {
    imei: decoded.imei,
    frame_ok: decoded.frame_ok,
    crc_ok: decoded.crc_ok,
    payload_hex: decoded.payload_hex,
    records: decoded.records.map(formatRecord),
    warnings: decoded.warnings,
    nonfatal_errors: decoded.nonfatal_errors,
  };
}
