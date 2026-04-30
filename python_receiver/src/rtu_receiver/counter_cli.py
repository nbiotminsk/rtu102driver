from __future__ import annotations

import argparse
import sys

from .counter_viewer import decode_packet, extract_counter_values
from .protocol import ProtocolError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Decode RTU102 packet and print counters 1..4")
    parser.add_argument("--key", required=True, help="XTEA key: 16 ASCII chars or 32 hex chars")
    parser.add_argument("--packet", help="Packet hex dump. If omitted, script reads packet from stdin.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        packet_text = args.packet if args.packet is not None else sys.stdin.read()
        decoded = decode_packet(packet_text.strip(), args.key.strip())
        imei, counters, source = extract_counter_values(decoded)
    except (ValueError, ProtocolError) as exc:
        print(f"Decode error: {exc}")
        return 1

    print(f"IMEI: {imei}")
    print(f"Source: {source}")
    print(f"Counter 1: {counters[0]}")
    print(f"Counter 2: {counters[1]}")
    print(f"Counter 3: {counters[2]}")
    print(f"Counter 4: {counters[3]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
