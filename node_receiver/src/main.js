import { parseArgs } from "node:util";
import { loadConfig } from "./config.js";
import { decodeDump } from "./decode_dump.js";
import { JsonlWriter } from "./jsonl.js";
import { parseHexDump, probeDatagramKey } from "./key_probe.js";
import { UdpReceiverServer, UdpTimeoutError } from "./udp_server.js";

function printHelp() {
  // eslint-disable-next-line no-console
  console.log(
    "Usage: receiver.js --config <path> [--once] [--log-level info|debug]\n" +
      "   or: receiver.js --probe-dump <hex> [--pin <value>] [--imei <value>] [--login <value>] [--password <value>]\n" +
      "   or: receiver.js --decode-dump <hex> --key <value>",
  );
}

function parseCliArgs(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      config: {
        type: "string",
      },
      "probe-dump": {
        type: "string",
      },
      "decode-dump": {
        type: "string",
      },
      key: {
        type: "string",
      },
      imei: {
        type: "string",
      },
      pin: {
        type: "string",
      },
      login: {
        type: "string",
      },
      password: {
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
    probeDump: values["probe-dump"] ?? null,
    decodeDump: values["decode-dump"] ?? null,
    key: values.key ?? null,
    imei: values.imei ?? null,
    pin: values.pin ?? null,
    login: values.login ?? "teleofis",
    password: values.password ?? "0000000000000000",
    once: values.once,
    logLevel: values["log-level"],
    help: values.help,
  };
}

function runProbe(args) {
  let datagram;
  try {
    datagram = parseHexDump(args.probeDump);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`probe error: ${String(err.message ?? err)}`);
    return 2;
  }

  let result;
  try {
    result = probeDatagramKey(datagram, {
      imei: args.imei,
      pin: args.pin,
      login: args.login,
      password: args.password,
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`probe error: ${String(err.message ?? err)}`);
    return 1;
  }

  // eslint-disable-next-line no-console
  console.log(JSON.stringify(result, null, 2));
  return result.matches.length > 0 ? 0 : 1;
}

function runDecodeDump(args) {
  if (!args.key) {
    // eslint-disable-next-line no-console
    console.error("decode error: --key is required");
    return 2;
  }

  let result;
  try {
    result = decodeDump(args.decodeDump, args.key);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`decode error: ${String(err.message ?? err)}`);
    return 1;
  }

  // eslint-disable-next-line no-console
  console.log(JSON.stringify(result, null, 2));
  return 0;
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

  if (args.probeDump) {
    return runProbe(args);
  }

  if (args.decodeDump) {
    return runDecodeDump(args);
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

  let exitCode = 0;
  try {
    await server.run(args.once);
  } catch (err) {
    if (err instanceof UdpTimeoutError) {
      // eslint-disable-next-line no-console
      console.error(err.message);
      exitCode = 1;
    } else {
      // eslint-disable-next-line no-console
      console.error(`socket error: ${String(err.message ?? err)}`);
      exitCode = 1;
    }
  } finally {
    process.removeListener("SIGINT", sigintHandler);
    process.removeListener("SIGTERM", sigtermHandler);

    try {
      if (signalShutdown) {
        await signalShutdown;
      } else {
        await server.stop();
        await writer.close();
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`shutdown error: ${String(err.message ?? err)}`);
      exitCode = 1;
    }
  }

  return exitCode;
}
