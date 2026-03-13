import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadConfig } from "../src/config.js";

test("config loads max_pending_datagrams", async () => {
  const tmpPath = await mkdtemp(join(tmpdir(), "rtu_node_cfg_"));
  const cfgPath = join(tmpPath, "cfg.json");

  await writeFile(
    cfgPath,
    JSON.stringify({
      listen_host: "127.0.0.1",
      listen_port: 5000,
      log_dir: "./logs",
      decode_enabled: true,
      respond_enabled: false,
      max_pending_datagrams: 7,
      keys: {
        default_hex: null,
        by_imei: {},
      },
    }),
    "utf8",
  );

  const cfg = await loadConfig(cfgPath);
  assert.equal(cfg.maxPendingDatagrams, 7);
  assert.equal(cfg.respondEnabled, false);
});

test("config rejects invalid max_pending_datagrams", async () => {
  const tmpPath = await mkdtemp(join(tmpdir(), "rtu_node_cfg_"));
  const cfgPath = join(tmpPath, "cfg-invalid.json");

  await writeFile(
    cfgPath,
    JSON.stringify({
      listen_host: "127.0.0.1",
      listen_port: 5000,
      log_dir: "./logs",
      decode_enabled: true,
      respond_enabled: true,
      max_pending_datagrams: 0,
      keys: {
        default_hex: null,
        by_imei: {},
      },
    }),
    "utf8",
  );

  await assert.rejects(
    loadConfig(cfgPath),
    (err) => String(err.message ?? err).includes("max_pending_datagrams must be an integer in range 1..100000"),
  );
});

test("config rejects invalid respond_enabled", async () => {
  const tmpPath = await mkdtemp(join(tmpdir(), "rtu_node_cfg_"));
  const cfgPath = join(tmpPath, "cfg-invalid-respond.json");

  await writeFile(
    cfgPath,
    JSON.stringify({
      listen_host: "127.0.0.1",
      listen_port: 5000,
      log_dir: "./logs",
      decode_enabled: true,
      respond_enabled: "yes",
      max_pending_datagrams: 10,
      keys: {
        default_hex: null,
        by_imei: {},
      },
    }),
    "utf8",
  );

  await assert.rejects(
    loadConfig(cfgPath),
    (err) => String(err.message ?? err).includes("respond_enabled must be boolean"),
  );
});

test("config accepts 16-character ASCII key", async () => {
  const tmpPath = await mkdtemp(join(tmpdir(), "rtu_node_cfg_"));
  const cfgPath = join(tmpPath, "cfg-ascii-key.json");

  await writeFile(
    cfgPath,
    JSON.stringify({
      listen_host: "127.0.0.1",
      listen_port: 5000,
      log_dir: "./logs",
      decode_enabled: true,
      respond_enabled: true,
      max_pending_datagrams: 10,
      keys: {
        default_hex: "1234567891234567",
        by_imei: {
          "867724030459827": "abcdefgh12345678",
        },
      },
    }),
    "utf8",
  );

  const cfg = await loadConfig(cfgPath);
  assert.equal(cfg.keys.defaultKey.toString("hex"), Buffer.from("1234567891234567", "ascii").toString("hex"));
  assert.equal(
    cfg.keys.resolveKey("867724030459827").toString("hex"),
    Buffer.from("abcdefgh12345678", "ascii").toString("hex"),
  );
});
