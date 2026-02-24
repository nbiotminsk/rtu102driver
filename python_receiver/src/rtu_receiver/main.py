from __future__ import annotations

import argparse
import sys

from .config import load_config
from .jsonl import JsonlWriter
from .udp_server import UdpReceiverServer


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RTU102 UDP receive-only server")
    parser.add_argument("--config", required=True, help="Path to JSON config")
    parser.add_argument("--once", action="store_true", help="Process one datagram and exit")
    parser.add_argument(
        "--log-level",
        default="info",
        choices=("info", "debug"),
        help="Console log verbosity",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except ValueError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    writer = JsonlWriter(config.log_dir)
    server = UdpReceiverServer(config=config, writer=writer, log_level=args.log_level)

    try:
        server.run(once=args.once)
    except TimeoutError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"socket error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0

    return 0
