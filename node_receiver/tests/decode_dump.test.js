import test from "node:test";
import assert from "node:assert/strict";

import { buildFrame, buildPlainForEncrypt } from "../src/protocol.js";
import { decodeDump } from "../src/decode_dump.js";
import { xteaEncryptEcbLE } from "../src/xtea.js";

test("decodeDump formats telemetry items with scalar values", () => {
  const imei = "867724030459827";
  const key = "1234567891234567";
  const payload = Buffer.from("0901120401000000", "hex");
  const frame = buildFrame(imei, xteaEncryptEcbLE(buildPlainForEncrypt(payload), Buffer.from(key, "ascii")));

  const decoded = decodeDump(frame.toString("hex"), key);
  assert.equal(decoded.imei, imei);
  assert.equal(decoded.records[0].type, "telemetry");
  assert.equal(decoded.records[0].items[0].param_id, 18);
  assert.equal(decoded.records[0].items[0].value, 1);
});
