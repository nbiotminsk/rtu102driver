import test from "node:test";
import assert from "node:assert/strict";

import { main } from "../src/main.js";

test("main returns 0 for --help", async () => {
  const code = await main(["--help"]);
  assert.equal(code, 0);
});

test("main returns 2 for unknown argument", async () => {
  const code = await main(["--unknown"]);
  assert.equal(code, 2);
});

test("main returns 2 for missing value in --config", async () => {
  const code = await main(["--config"]);
  assert.equal(code, 2);
});

test("main returns 2 for invalid --log-level", async () => {
  const code = await main(["--log-level", "trace"]);
  assert.equal(code, 2);
});

test("main returns 2 for missing config file", async () => {
  const code = await main(["--config", "/tmp/does-not-exist-receiver.json"]);
  assert.equal(code, 2);
});
