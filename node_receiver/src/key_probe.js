import { createHash } from "node:crypto";

import { crc16CcittFalse } from "./crc16.js";
import { parseImei, parsePayload, ProtocolError, unstuffPayload, FRAME_END, FRAME_START } from "./protocol.js";
import { xteaDecryptEcbLE } from "./xtea.js";

function toAsciiPadded16(value) {
  const out = Buffer.alloc(16, 0x00);
  Buffer.from(value, "ascii").copy(out, 0, 0, Math.min(16, value.length));
  return out;
}

function toAsciiRepeated16(value) {
  return Buffer.from(value.repeat(Math.ceil(16 / value.length)).slice(0, 16), "ascii");
}

function toHexDecoded16(value) {
  if (!/^[0-9a-fA-F]{32}$/.test(value)) {
    return null;
  }
  return Buffer.from(value, "hex");
}

function toLeUint64Repeated16(value) {
  if (!/^\d+$/.test(value)) {
    return null;
  }
  try {
    const block = Buffer.alloc(8);
    block.writeBigUInt64LE(BigInt(value), 0);
    return Buffer.concat([block, block]);
  } catch {
    return null;
  }
}

function toBcdPadded16(value) {
  if (!/^\d+$/.test(value)) {
    return null;
  }
  const bcd = Buffer.alloc(Math.ceil(value.length / 2), 0x00);
  for (let i = 0; i < value.length; i += 2) {
    const hi = value.charCodeAt(i) - 48;
    const lo = i + 1 < value.length ? value.charCodeAt(i + 1) - 48 : 0x0f;
    bcd[i >> 1] = ((hi & 0x0f) << 4) | (lo & 0x0f);
  }
  const out = Buffer.alloc(16, 0x00);
  bcd.copy(out, 0, 0, Math.min(16, bcd.length));
  return out;
}

function first16Digest(algorithm, value) {
  return createHash(algorithm).update(value, "utf8").digest().subarray(0, 16);
}

function addCandidate(target, key, source) {
  if (!key || key.length !== 16) {
    return;
  }
  const keyHex = key.toString("hex");
  if (!target.has(keyHex)) {
    target.set(keyHex, source);
  }
}

function addStringForms(target, label, value) {
  if (!value) {
    return;
  }
  addCandidate(target, toAsciiPadded16(value), `${label}:ascii_padded`);
  addCandidate(target, toAsciiRepeated16(value), `${label}:ascii_repeated`);
  addCandidate(target, toHexDecoded16(value), `${label}:hex_literal`);
  addCandidate(target, toLeUint64Repeated16(value), `${label}:uint64le_x2`);
  addCandidate(target, toBcdPadded16(value), `${label}:bcd_padded`);
  addCandidate(target, first16Digest("md5", value), `${label}:md5`);
  addCandidate(target, first16Digest("sha1", value), `${label}:sha1_first16`);
  addCandidate(target, first16Digest("sha256", value), `${label}:sha256_first16`);
}

export function parseHexDump(raw) {
  const prefixed = [...raw.matchAll(/0x([0-9a-f]{2})/gi)].map((match) => match[1]);
  if (prefixed.length > 0) {
    return Buffer.from(prefixed.map((value) => Number.parseInt(value, 16)));
  }

  const compact = raw.replace(/[^0-9a-f]/gi, "");
  if (!compact || compact.length % 2 !== 0) {
    throw new Error("hex dump must contain full bytes");
  }
  return Buffer.from(compact, "hex");
}

export function inspectDatagram(datagram) {
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

  return {
    imei,
    datagramLength: datagram.length,
    bodyLength: body.length,
    ciphertext,
  };
}

export function buildKeyCandidates({ imei, pin, login = "teleofis", password = "0000000000000000", extra = [] }) {
  const candidates = new Map();
  const base = [
    ["imei", imei],
    ["pin", pin],
    ["login", login],
    ["password", password],
    ...extra.map((value, index) => [`extra${index + 1}`, value]),
  ].filter(([, value]) => Boolean(value));

  for (const [label, value] of base) {
    addStringForms(candidates, label, value);
  }

  const comboValues = [];
  for (const [, left] of base) {
    for (const [, right] of base) {
      if (!left || !right) {
        continue;
      }
      comboValues.push(left + right, `${left}:${right}`, `${left}-${right}`, `${left}_${right}`);
    }
  }

  for (const [labelA, valueA] of base) {
    for (const [labelB, valueB] of base) {
      if (!valueA || !valueB) {
        continue;
      }
      addStringForms(candidates, `${labelA}+${labelB}`, valueA + valueB);
      addStringForms(candidates, `${labelA}:${labelB}`, `${valueA}:${valueB}`);
      addStringForms(candidates, `${labelA}-${labelB}`, `${valueA}-${valueB}`);
      addStringForms(candidates, `${labelA}_${labelB}`, `${valueA}_${valueB}`);
    }
  }

  for (const value of comboValues) {
    addCandidate(candidates, first16Digest("md5", value), `combo:${value}:md5`);
    addCandidate(candidates, first16Digest("sha1", value), `combo:${value}:sha1_first16`);
    addCandidate(candidates, first16Digest("sha256", value), `combo:${value}:sha256_first16`);
  }

  return [...candidates.entries()].map(([keyHex, source]) => ({
    keyHex,
    source,
    key: Buffer.from(keyHex, "hex"),
  }));
}

export function probeDatagramKey(datagram, options = {}) {
  const inspected = inspectDatagram(datagram);
  const candidates = buildKeyCandidates({
    imei: options.imei ?? inspected.imei,
    pin: options.pin ?? null,
    login: options.login ?? "teleofis",
    password: options.password ?? "0000000000000000",
    extra: options.extra ?? [],
  });

  const matches = [];
  for (const candidate of candidates) {
    let plaintext;
    try {
      plaintext = xteaDecryptEcbLE(inspected.ciphertext, candidate.key);
    } catch {
      continue;
    }

    const crcReceived = plaintext.readUInt16LE(plaintext.length - 2);
    const plainNoCrc = plaintext.subarray(0, plaintext.length - 2);
    const crcCalculated = crc16CcittFalse(plainNoCrc);
    if (crcReceived !== crcCalculated) {
      continue;
    }

    const parsed = parsePayload(plainNoCrc);
    matches.push({
      source: candidate.source,
      key_hex: candidate.keyHex,
      crc_received: crcReceived,
      crc_calculated: crcCalculated,
      payload_hex: parsed.payload_used.toString("hex"),
      records: parsed.records,
      warnings: parsed.warnings,
    });
  }

  return {
    imei: inspected.imei,
    datagram_length: inspected.datagramLength,
    ciphertext_length: inspected.ciphertext.length,
    candidate_count: candidates.length,
    matches,
  };
}
