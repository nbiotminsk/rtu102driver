#!/usr/bin/env node
import { main } from "../src/main.js";

main(process.argv.slice(2)).then((code) => {
  process.exitCode = code;
}).catch((err) => {
  // eslint-disable-next-line no-console
  console.error(`fatal error: ${String(err?.message ?? err)}`);
  process.exitCode = 1;
});
