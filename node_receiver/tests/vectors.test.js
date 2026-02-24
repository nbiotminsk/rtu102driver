import test from "node:test";
import assert from "node:assert/strict";

import { crc16CcittFalse } from "../src/crc16.js";
import {
  buildFrame,
  buildPlainForEncrypt,
  decodeDatagram,
  parseImei,
  parsePayload,
  ProtocolError,
  stuffPayload,
  unstuffPayload,
} from "../src/protocol.js";
import { xteaDecryptEcbLE, xteaEncryptEcbLE } from "../src/xtea.js";

test("byte stuffing roundtrip", () => {
  const raw = Buffer.from([0x00, 0xc0, 0x01, 0xc2, 0x02, 0xc4, 0x03]);
  const stuffed = stuffPayload(raw);
  assert.deepEqual(unstuffPayload(stuffed), raw);
});

test("imei parse vector", () => {
  const imeiBytes = Buffer.from("cb9b558888110300", "hex");
  assert.equal(parseImei(imeiBytes), "863703030668235");
});

test("crc16 reference vector", () => {
  assert.equal(crc16CcittFalse(Buffer.from("123456789", "ascii")), 0x29b1);
});

test("xtea decrypt document vector", () => {
  const key = Buffer.from("79757975797579756f706f706f706f70", "hex");
  const ciphertext = Buffer.from(
    "60614e680e705d0fefcf7ac8102c4452ecb0c85768f2f2dc52415c43a36712f0" +
      "31c9037dafd31f01ecb0c85768f2f2dc7b00be7e5a15fee1e78c63c58c2c6861" +
      "fef9a1c4130a354c846448512e6a97ce4a9005690d1e3808f065c957538e1bac" +
      "87e7228322ab39a6900146786840dc0bc536ad6afb6e4e3267fb045dd9c7e670" +
      "f1c2d2ac1fcc71ad06b7b194de4031f4046744610aafa7b92fd3f392c3a5eeb1" +
      "474ffa60c0587e68ecb0c85768f2f2dc2a88827461b41c99b2539b6bfdcd4325" +
      "be3ced59be7b594addb3366e076f6e470cc41df1eb3a8d93c99eb7bdad5a474c" +
      "33659653762910d0ecb0c85768f2f2dcecb0c85768f2f2dc82e715e7952a79c4" +
      "660074ccc50741cab5eabb873ae706b4c8b008128df0af80fece91741fc5f641" +
      "1145aab35ac9f6e0f8a937baed012d00c3be705a5e8c3440ddc1cd4e0051cccc",
    "hex",
  );

  const plain = xteaDecryptEcbLE(ciphertext, key);
  assert.equal(plain.subarray(0, 14).toString("hex"), "09300004100e00000104f4779559");
  assert.equal(plain.readUInt16LE(plain.length - 2), crc16CcittFalse(plain.subarray(0, -2)));
});

test("encrypt decrypt roundtrip", () => {
  const key = Buffer.from("79757975797579756f706f706f706f70", "hex");
  const payload = Buffer.from("0900", "hex");
  const plain = buildPlainForEncrypt(payload);
  const enc = xteaEncryptEcbLE(plain, key);
  const dec = xteaDecryptEcbLE(enc, key);
  assert.deepEqual(dec, plain);
});

test("parse payload ids", () => {
  const payload = Buffer.from(
    "01010478563412" +
      "020100" +
      "0407" +
      "060300" +
      "07030003313233" +
      "09020101aa0202bbcc",
    "hex",
  );

  const parsed = parsePayload(payload);
  assert.equal(parsed.padding_len, 0);
  assert.deepEqual(
    parsed.records.map((r) => r.id),
    [1, 2, 4, 6, 7, 9],
  );
});

test("parse id3 synthetic event", () => {
  const eventTime = Buffer.alloc(4);
  eventTime.writeUInt32LE(1700000000, 0);
  const eventData = Buffer.from([0, 1, 2, 3, 4, 20, 5]);
  const payload = Buffer.concat([Buffer.from([3, 0x13, 1]), eventTime, Buffer.from([eventData.length]), eventData]);

  const parsed = parsePayload(payload);
  const rec = parsed.records[0];
  assert.equal(rec.id, 3);
  assert.equal(rec.seq, 0x13);
  assert.equal(rec.events[0].event_code, 1);
});

test("build frame boundaries", () => {
  const imei = "863703030668235";
  const frame = buildFrame(imei, Buffer.from("0011223344556677", "hex"));
  assert.equal(frame[0], 0xc0);
  assert.equal(frame[frame.length - 1], 0xc2);
});

test("invalid escape sequence throws protocol error", () => {
  assert.throws(
    () => unstuffPayload(Buffer.from([0xc4, 0x99])),
    (err) => err instanceof ProtocolError && err.stage === "unstuff" && err.reason === "invalid_escape_sequence",
  );
});

test("missing key for imei returns key_lookup error", () => {
  const imei = "863703030668235";
  const key = Buffer.from("79757975797579756f706f706f706f70", "hex");
  const payload = Buffer.from("0900", "hex");
  const plain = buildPlainForEncrypt(payload);
  const frame = buildFrame(imei, xteaEncryptEcbLE(plain, key));

  assert.throws(
    () => decodeDatagram(frame, () => null),
    (err) => err instanceof ProtocolError && err.stage === "key_lookup" && err.reason === "missing_key_for_imei",
  );
});
