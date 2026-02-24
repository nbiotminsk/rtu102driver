import { parseArgs } from "node:util";
import { loadConfig } from "./config.js";
import { JsonlWriter } from "./jsonl.js";
import { UdpReceiverServer, UdpTimeoutError } from "./udp_server.js";

function printHelp() {
  // eslint-disable-next-line no-console
  console.log("Usage: receiver.js --config <path> [--once] [--log-level info|debug]");
}

function parseCliArgs(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      config: {
        type: "string",
      },
      once: {
        type: "boolean",
        default: false,
      },
      "log-level": {
        type: "string",
        default: "info",
      },
      help: {
        type: "boolean",
        short: "h",
        default: false,
      },
    },
    strict: true,
    allowPositionals: false,
  });

  return {
    config: values.config ?? null,
    once: values.once,
    logLevel: values["log-level"],
    help: values.help,
  };
}

export async function main(argv = []) {
  let args;
  try {
    args = parseCliArgs(argv);
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

  let signalShutdown = null;
  const onSignal = (signalName) => {
    if (signalShutdown) {
      return;
    }
    signalShutdown = (async () => {
      if (args.logLevel === "debug") {
        // eslint-disable-next-line no-console
        console.error(`received ${signalName}, shutting down`);
      }
      await server.stop();
      await writer.close();
    })();
  };

  const sigintHandler = () => {
    onSignal("SIGINT");
  };
  const sigtermHandler = () => {
    onSignal("SIGTERM");
  };
  process.once("SIGINT", sigintHandler);
  process.once("SIGTERM", sigtermHandler);

  try {
    await server.run(args.once);
  } catch (err) {
    if (err instanceof UdpTimeoutError) {
      // eslint-disable-next-line no-console
      console.error(err.message);
      return 1;
    }
    // eslint-disable-next-line no-console
    console.error(`socket error: ${String(err.message ?? err)}`);
    return 1;
  } finally {
    process.removeListener("SIGINT", sigintHandler);
    process.removeListener("SIGTERM", sigtermHandler);

    if (signalShutdown) {
      try {
        await signalShutdown;
      } catch {
        // ignore signal shutdown errors, handled by run()/writer close path below
      }
    } else {
      await server.stop();
      await writer.close();
    }
  }

  return 0;
}
