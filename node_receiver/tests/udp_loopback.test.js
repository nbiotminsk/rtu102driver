import test from "node:test";
import assert from "node:assert/strict";
import dgram from "node:dgram";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadConfig } from "../src/config.js";
import { crc16CcittFalse } from "../src/crc16.js";
import { JsonlWriter } from "../src/jsonl.js";
import { buildFrame, buildPlainForEncrypt } from "../src/protocol.js";
import { UdpReceiverServer } from "../src/udp_server.js";
import { xteaEncryptEcbLE } from "../src/xtea.js";

function dateSuffixUTC() {
  const now = new Date();
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, "0");
  const day = String(now.getUTCDate()).padStart(2, "0");
  return `${year}${month}${day}`;
}

async function pickPort() {
  const s = dgram.createSocket("udp4");
  await new Promise((resolve) => s.bind(0, "127.0.0.1", resolve));
  const port = s.address().port;
  s.close();
  return port;
}

async function waitFor(predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("timeout waiting for condition");
}

function buildValidDatagram(imei, keyHex) {
  const key = Buffer.from(keyHex, "hex");
  const payload = Buffer.from([9, 0]);
  const plain = buildPlainForEncrypt(payload);
  const encrypted = xteaEncryptEcbLE(plain, key);
  return buildFrame(imei, encrypted);
}

async function readJsonl(path) {
  const raw = await readFile(path, "utf8");
  return raw
    .split(/\r?\n/u)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

test("udp loopback valid frame", async () => {
  const imei = "863703030668235";
  const keyHex = "79757975797579756f706f706f706f70";
  const port = await pickPort();
  const tmpPath = await mkdtemp(join(tmpdir(), "rtu_node_"));
  const logDir = join(tmpPath, "logs");

  const configPath = join(tmpPath, "receiver.json");
  await writeFile(
    configPath,
    JSON.stringify({
      listen_host: "127.0.0.1",
      listen_port: port,
      log_dir: logDir,
      decode_enabled: true,
      keys: {
        default_hex: null,
        by_imei: {
          [imei]: keyHex,
        },
      },
    }),
    "utf8",
  );

  const cfg = await loadConfig(configPath);
  const server = new UdpReceiverServer(cfg, new JsonlWriter(cfg.logDir));

  const serverRun = server.run(true);
  await new Promise((resolve) => setTimeout(resolve, 100));

  const datagram = buildValidDatagram(imei, keyHex);
  const sender = dgram.createSocket("udp4");
  await new Promise((resolve, reject) => {
    sender.send(datagram, port, "127.0.0.1", (err) => {
      sender.close();
      if (err) {
        reject(err);
        return;
      }
      resolve();
    });
  });

  await serverRun;

  const dateSuffix = dateSuffixUTC();
  const rawPath = join(logDir, `raw-${dateSuffix}.jsonl`);
  const decodedPath = join(logDir, `decoded-${dateSuffix}.jsonl`);

  await waitFor(async () => {
    try {
      await readFile(rawPath, "utf8");
      await readFile(decodedPath, "utf8");
      return true;
    } catch {
      return false;
    }
  });

  const rawRecords = await readJsonl(rawPath);
  const decodedRecords = await readJsonl(decodedPath);

  assert.equal(rawRecords.length, 1);
  assert.equal(rawRecords[0].datagram_hex, datagram.toString("hex"));

  assert.equal(decodedRecords.length, 1);
  const decoded = decodedRecords[0];
  assert.equal(decoded.imei, imei);
  assert.equal(decoded.frame_ok, true);
  assert.equal(decoded.crc_ok, true);
  assert.equal(decoded.records[0].id, 9);
});

test("decode errors written", async () => {
  const imei = "863703030668235";
  const keyHex = "79757975797579756f706f706f706f70";
  const tmpPath = await mkdtemp(join(tmpdir(), "rtu_node_"));
  const logDir = join(tmpPath, "logs");

  const cfgPath = join(tmpPath, "cfg.json");
  await writeFile(
    cfgPath,
    JSON.stringify({
      listen_host: "127.0.0.1",
      listen_port: 5001,
      log_dir: logDir,
      decode_enabled: true,
      keys: {
        default_hex: null,
        by_imei: {
          [imei]: keyHex,
        },
      },
    }),
    "utf8",
  );

  const cfg = await loadConfig(cfgPath);
  const writer = new JsonlWriter(cfg.logDir);
  const server = new UdpReceiverServer(cfg, writer);

  await server.handleDatagram(Buffer.from([0, 1, 2]), "127.0.0.1", 11111);

  const key = Buffer.from(keyHex, "hex");
  const payload = Buffer.from([9, 0]);
  const plain = buildPlainForEncrypt(payload);
  const brokenCrc = crc16CcittFalse(plain.subarray(0, -2)) ^ 0xffff;
  const broken = Buffer.concat([plain.subarray(0, -2), Buffer.from([brokenCrc & 0xff, (brokenCrc >> 8) & 0xff])]);
  const badCrcDatagram = buildFrame(imei, xteaEncryptEcbLE(broken, key));
  await server.handleDatagram(badCrcDatagram, "127.0.0.1", 22222);

  const dateSuffix = dateSuffixUTC();
  const errorsPath = join(logDir, `errors-${dateSuffix}.jsonl`);
  const errors = await readJsonl(errorsPath);

  assert.ok(errors.length >= 2);
  const reasons = new Set(errors.map((e) => `${e.stage}:${e.reason}`));
  assert.ok(reasons.has("frame:invalid_boundaries"));
  assert.ok(reasons.has("crc:crc_mismatch"));
});
