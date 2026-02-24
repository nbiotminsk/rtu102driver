import { loadConfig } from "./config.js";
import { JsonlWriter } from "./jsonl.js";
import { UdpReceiverServer } from "./udp_server.js";

function buildArgParser(argv) {
  const args = {
    config: null,
    once: false,
    logLevel: "info",
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--config") {
      args.config = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (token === "--once") {
      args.once = true;
      continue;
    }
    if (token === "--log-level") {
      args.logLevel = argv[i + 1] ?? "info";
      i += 1;
      continue;
    }
    if (token === "-h" || token === "--help") {
      args.help = true;
      continue;
    }
    throw new Error(`unknown argument: ${token}`);
  }

  return args;
}

function printHelp() {
  // eslint-disable-next-line no-console
  console.log("Usage: receiver.js --config <path> [--once] [--log-level info|debug]");
}

export async function main(argv = []) {
  let args;
  try {
    args = buildArgParser(argv);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(String(err.message ?? err));
    printHelp();
    return 2;
  }

  if (args.help) {
    printHelp();
    return 0;
  }

  if (!args.config) {
    // eslint-disable-next-line no-console
    console.error("config error: --config is required");
    printHelp();
    return 2;
  }

  if (!["info", "debug"].includes(args.logLevel)) {
    // eslint-disable-next-line no-console
    console.error("config error: --log-level must be info or debug");
    return 2;
  }

  let config;
  try {
    config = await loadConfig(args.config);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`config error: ${String(err.message ?? err)}`);
    return 2;
  }

  const writer = new JsonlWriter(config.logDir);
  const server = new UdpReceiverServer(config, writer, args.logLevel);

  try {
    await server.run(args.once);
  } catch (err) {
    if (String(err.message ?? err) === "timeout waiting for UDP datagram") {
      // eslint-disable-next-line no-console
      console.error("timeout waiting for UDP datagram");
      return 1;
    }
    // eslint-disable-next-line no-console
    console.error(`socket error: ${String(err.message ?? err)}`);
    return 1;
  }

  return 0;
}
