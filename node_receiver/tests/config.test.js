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
