import { crc16CcittFalse } from "./crc16.js";
import { xteaDecryptEcbLE } from "./xtea.js";

export const FRAME_START = 0xc0;
export const FRAME_END = 0xc2;
export const ESCAPE = 0xc4;

const ESC_DECODE = new Map([
  [0xc1, 0xc0],
  [0xc3, 0xc2],
  [0xc4, 0xc4],
]);

const ESC_ENCODE = new Map([
  [0xc0, Buffer.from([0xc4, 0xc1])],
  [0xc2, Buffer.from([0xc4, 0xc3])],
  [0xc4, Buffer.from([0xc4, 0xc4])],
]);

const EVENT_TYPE_LENGTHS = new Map([
  [0, 4], [1, 4], [2, 4], [3, 4], [6, 4], [7, 1], [8, 1], [9, 1], [10, 1], [11, 1],
  [12, 4], [13, 4], [14, 4], [15, 4], [16, 4], [17, 4], [18, 4], [19, 4], [20, 1], [21, 4],
  [22, 1], [23, 1], [24, 1], [25, 1], [26, 1], [27, 4], [28, 4], [29, 4], [30, 4], [31, 1],
  [32, 1], [33, 1], [37, 4], [38, 4], [39, 4], [40, 4], [41, 4], [42, 4], [43, 4], [44, 1],
  [45, 1], [46, 1], [47, 1], [48, 1], [49, 1], [50, 4], [51, 1],
]);

export class ProtocolError extends Error {
  constructor(stage, reason, details = {}, imei = null) {
    super(`${stage}:${reason}`);
    this.name = "ProtocolError";
    this.stage = stage;
    this.reason = reason;
    this.details = details;
    this.imei = imei;
  }
}

export function stuffPayload(raw) {
  const out = [];
  for (const byte of raw) {
    const escaped = ESC_ENCODE.get(byte);
    if (escaped) {
      out.push(escaped);
    } else {
      out.push(Buffer.from([byte]));
    }
  }
  return Buffer.concat(out);
}

export function unstuffPayload(stuffed) {
  const out = [];
  for (let i = 0; i < stuffed.length; i += 1) {
    const byte = stuffed[i];
    if (byte !== ESCAPE) {
      out.push(byte);
      continue;
    }

    if (i + 1 >= stuffed.length) {
      throw new ProtocolError("unstuff", "dangling_escape_byte", { offset: i });
    }

    const esc = stuffed[i + 1];
    const decoded = ESC_DECODE.get(esc);
    if (decoded === undefined) {
      throw new ProtocolError("unstuff", "invalid_escape_sequence", { offset: i, escape_byte: esc });
    }

    out.push(decoded);
    i += 1;
  }

  return Buffer.from(out);
}

export function parseImei(imeiBytes) {
  if (imeiBytes.length !== 8) {
    throw new ProtocolError("imei", "invalid_imei_bytes_length", { length: imeiBytes.length });
  }
  return imeiBytes.readBigUInt64LE(0).toString(10);
}

export function buildPlainForEncrypt(payload) {
  const padLen = (8 - ((payload.length + 2) % 8)) % 8;
  const padded = Buffer.concat([payload, Buffer.alloc(padLen)]);
  const crc = crc16CcittFalse(padded);
  const crcBuf = Buffer.alloc(2);
  crcBuf.writeUInt16LE(crc, 0);
  return Buffer.concat([padded, crcBuf]);
}

export function buildFrame(imei, encryptedPayload) {
  const imeiBytes = Buffer.alloc(8);
  imeiBytes.writeBigUInt64LE(BigInt(imei), 0);
  const body = Buffer.concat([imeiBytes, encryptedPayload]);
  return Buffer.concat([Buffer.from([FRAME_START]), stuffPayload(body), Buffer.from([FRAME_END])]);
}

export function decodeDatagram(datagram, keyResolver) {
  if (datagram.length < 2) {
    throw new ProtocolError("frame", "too_short", { length: datagram.length });
  }

  if (datagram[0] !== FRAME_START || datagram[datagram.length - 1] !== FRAME_END) {
    throw new ProtocolError("frame", "invalid_boundaries", {
      start: datagram[0],
      end: datagram[datagram.length - 1],
    });
  }

  const body = unstuffPayload(datagram.subarray(1, datagram.length - 1));
  if (body.length < 16) {
    throw new ProtocolError("frame", "body_too_short", { body_len: body.length });
  }

  const imei = parseImei(body.subarray(0, 8));
  const ciphertext = body.subarray(8);

  if (ciphertext.length === 0 || ciphertext.length % 8 !== 0) {
    throw new ProtocolError("xtea", "invalid_ciphertext_length", { cipher_len: ciphertext.length }, imei);
  }

  const key = keyResolver(imei);
  if (!key) {
    throw new ProtocolError("key_lookup", "missing_key_for_imei", { imei }, imei);
  }
  if (key.length !== 16) {
    throw new ProtocolError("key_lookup", "invalid_key_length", { imei, key_len: key.length }, imei);
  }

  let plaintext;
  try {
    plaintext = xteaDecryptEcbLE(ciphertext, key);
  } catch (err) {
    throw new ProtocolError("xtea", "decrypt_failed", { message: String(err.message ?? err) }, imei);
  }

  if (plaintext.length < 2) {
    throw new ProtocolError("crc", "plaintext_too_short", { plain_len: plaintext.length }, imei);
  }

  const crcRecv = plaintext.readUInt16LE(plaintext.length - 2);
  const plainNoCrc = plaintext.subarray(0, plaintext.length - 2);
  const crcCalc = crc16CcittFalse(plainNoCrc);
  if (crcCalc !== crcRecv) {
    throw new ProtocolError(
      "crc",
      "crc_mismatch",
      {
        received: crcRecv,
        calculated: crcCalc,
      },
      imei,
    );
  }

  const parsed = parsePayload(plainNoCrc);
  return {
    imei,
    frame_ok: true,
    crc_ok: true,
    payload_hex: parsed.payload_used.toString("hex"),
    records: parsed.records,
    warnings: parsed.warnings,
    nonfatal_errors: parsed.nonfatal_errors,
  };
}

export function parsePayload(payloadWithPad) {
  const records = [];
  const warnings = [];
  const nonfatalErrors = [];

  let offset = 0;
  while (offset < payloadWithPad.length) {
    if (payloadWithPad[offset] === 0 && allZero(payloadWithPad.subarray(offset))) {
      break;
    }

    const dataId = payloadWithPad[offset];
    offset += 1;

    try {
      const parsed = parseRecord(dataId, payloadWithPad, offset);
      records.push(parsed.record);
      warnings.push(...parsed.warnings);
      nonfatalErrors.push(...parsed.nonfatalErrors);
      offset = parsed.offset;
    } catch (err) {
      warnings.push("payload_parse_error");
      nonfatalErrors.push({
        stage: "payload_parse",
        reason: "record_parse_failed",
        details: {
          data_id: dataId,
          offset,
          message: String(err.message ?? err),
        },
      });
      records.push({
        id: dataId,
        type: "unknown",
        raw_hex: payloadWithPad.subarray(offset).toString("hex"),
        parse_error: String(err.message ?? err),
      });
      offset = payloadWithPad.length;
      break;
    }
  }

  return {
    payload_used: payloadWithPad.subarray(0, offset),
    padding_len: payloadWithPad.length - offset,
    records,
    warnings,
    nonfatal_errors: nonfatalErrors,
  };
}

function parseRecord(dataId, buf, offset) {
  const warnings = [];
  const nonfatalErrors = [];

  if (dataId === 1 || dataId === 6) {
    const [paramId, value, nextOffset] = parseParamLenData(buf, offset);
    return {
      record: {
        id: dataId,
        type: dataId === 1 ? "config_command" : "read_command",
        param_id: paramId,
        len: value.length,
        data_hex: value.toString("hex"),
      },
      offset: nextOffset,
      warnings,
      nonfatalErrors,
    };
  }

  if (dataId === 2) {
    requireLen(buf, offset, 2, "truncated_response");
    const paramId = buf[offset];
    const resultCode = buf[offset + 1];
    return {
      record: {
        id: 2,
        type: "config_response",
        param_id: paramId,
        result_code: resultCode,
      },
      offset: offset + 2,
      warnings,
      nonfatalErrors,
    };
  }

  if (dataId === 3) {
    requireLen(buf, offset, 1, "truncated_archive_seq");
    const seq = buf[offset];
    offset += 1;

    const events = [];
    while (offset < buf.length) {
      if (buf[offset] === 0 && allZero(buf.subarray(offset))) {
        break;
      }

      requireLen(buf, offset, 6, "truncated_event_header");
      const eventCode = buf[offset];
      const eventTime = buf.readUInt32LE(offset + 1);
      const eventDataLen = buf[offset + 5];
      offset += 6;

      requireLen(buf, offset, eventDataLen, "truncated_event_data");
      const eventData = buf.subarray(offset, offset + eventDataLen);
      offset += eventDataLen;

      const parsedEvent = parseEventData(eventData);
      warnings.push(...parsedEvent.warnings);
      nonfatalErrors.push(...parsedEvent.nonfatal_errors);
      events.push({
        event_code: eventCode,
        event_time: eventTime,
        event_data_len: eventDataLen,
        event_data: parsedEvent.entries,
      });
    }

    return {
      record: {
        id: 3,
        type: "archive",
        seq,
        events,
      },
      offset,
      warnings,
      nonfatalErrors,
    };
  }

  if (dataId === 4) {
    requireLen(buf, offset, 1, "truncated_archive_ack");
    const seq = buf[offset];
    return {
      record: {
        id: 4,
        type: "archive_ack",
        seq,
      },
      offset: offset + 1,
      warnings,
      nonfatalErrors,
    };
  }

  if (dataId === 7) {
    requireLen(buf, offset, 3, "truncated_read_response_header");
    const paramId = buf[offset];
    const resultCode = buf[offset + 1];
    const dataLen = buf[offset + 2];
    offset += 3;
    requireLen(buf, offset, dataLen, "truncated_read_response_data");
    const value = buf.subarray(offset, offset + dataLen);
    return {
      record: {
        id: 7,
        type: "read_response",
        param_id: paramId,
        result_code: resultCode,
        len: dataLen,
        data_hex: value.toString("hex"),
      },
      offset: offset + dataLen,
      warnings,
      nonfatalErrors,
    };
  }

  if (dataId === 8) {
    const raw = buf.subarray(offset);
    return {
      record: {
        id: 8,
        type: "auth",
        raw_hex: raw.toString("hex"),
      },
      offset: buf.length,
      warnings,
      nonfatalErrors,
    };
  }

  if (dataId === 9) {
    requireLen(buf, offset, 1, "truncated_telemetry_count");
    const count = buf[offset];
    offset += 1;

    const items = [];
    for (let i = 0; i < count; i += 1) {
      requireLen(buf, offset, 2, "truncated_telemetry_item_header");
      const paramId = buf[offset];
      const dataLen = buf[offset + 1];
      offset += 2;
      requireLen(buf, offset, dataLen, "truncated_telemetry_item_data");
      const value = buf.subarray(offset, offset + dataLen);
      offset += dataLen;
      items.push({
        param_id: paramId,
        len: dataLen,
        data_hex: value.toString("hex"),
      });
    }

    return {
      record: {
        id: 9,
        type: "telemetry",
        count,
        items,
      },
      offset,
      warnings,
      nonfatalErrors,
    };
  }

  if (dataId >= 10 && dataId <= 14) {
    const raw = buf.subarray(offset);
    warnings.push("rtu800_extended_id");
    nonfatalErrors.push({
      stage: "payload_parse",
      reason: "rtu800_extended_id",
      details: { data_id: dataId },
    });
    return {
      record: {
        id: dataId,
        type: "rtu800_extended",
        raw_hex: raw.toString("hex"),
      },
      offset: buf.length,
      warnings,
      nonfatalErrors,
    };
  }

  const raw = buf.subarray(offset);
  warnings.push("unknown_data_id");
  nonfatalErrors.push({
    stage: "payload_parse",
    reason: "unknown_data_id",
    details: { data_id: dataId },
  });
  return {
    record: {
      id: dataId,
      type: "unknown",
      raw_hex: raw.toString("hex"),
    },
    offset: buf.length,
    warnings,
    nonfatalErrors,
  };
}

function parseParamLenData(buf, offset) {
  requireLen(buf, offset, 2, "truncated_param_len_data_header");
  const paramId = buf[offset];
  const dataLen = buf[offset + 1];
  offset += 2;
  requireLen(buf, offset, dataLen, "truncated_param_len_data_value");
  const value = buf.subarray(offset, offset + dataLen);
  return [paramId, value, offset + dataLen];
}

function parseEventData(eventData) {
  const entries = [];
  const warnings = [];
  const nonfatalErrors = [];

  let offset = 0;
  while (offset < eventData.length) {
    const typeId = eventData[offset];
    offset += 1;

    const fixedLen = EVENT_TYPE_LENGTHS.get(typeId);
    if (fixedLen === undefined) {
      warnings.push("unknown_type_id");
      nonfatalErrors.push({
        stage: "payload_parse",
        reason: "unknown_type_id",
        details: { type_id: typeId },
      });
      entries.push({
        type_id: typeId,
        raw_hex: eventData.subarray(offset).toString("hex"),
        unknown: true,
      });
      break;
    }

    if (offset + fixedLen > eventData.length) {
      warnings.push("event_type_len_mismatch");
      nonfatalErrors.push({
        stage: "payload_parse",
        reason: "event_type_len_mismatch",
        details: {
          type_id: typeId,
          expected_len: fixedLen,
          available: eventData.length - offset,
        },
      });
      entries.push({
        type_id: typeId,
        raw_hex: eventData.subarray(offset).toString("hex"),
        len_mismatch: true,
      });
      break;
    }

    const value = eventData.subarray(offset, offset + fixedLen);
    offset += fixedLen;
    entries.push({
      type_id: typeId,
      len: fixedLen,
      raw_hex: value.toString("hex"),
    });
  }

  return {
    entries,
    warnings,
    nonfatal_errors: nonfatalErrors,
  };
}

function allZero(data) {
  for (const byte of data) {
    if (byte !== 0) {
      return false;
    }
  }
  return true;
}

function requireLen(buf, offset, needed, reason) {
  if (offset + needed > buf.length) {
    throw new Error(reason);
  }
}
