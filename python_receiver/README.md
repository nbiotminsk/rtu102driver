# RTU102 Python Receiver

Receive-only UDP server for TELEOFIS RTU102 protocol.

## Features

- UDP listener (default `127.0.0.1:5000`)
- Frame checks: `0xC0...0xC2`, byte unstuffing
- IMEI extraction (`uint64 LE`)
- XTEA-ECB decryption (32 rounds, LE words)
- CRC16-CCITT verification (`poly=0x1021`, `init=0xFFFF`)
- Payload parsing for IDs `1,2,3,4,6,7,9`
- Raw passthrough for IDs `8` and `10..14`
- JSONL logs: `raw-*`, `decoded-*`, `errors-*`
- No outgoing UDP responses

## Requirements

- Python 3.12+

## Config

Use `config/receiver.example.json` as template.

Key fields:

- `listen_host`
- `listen_port`
- `log_dir`
- `decode_enabled`
- `keys.default_hex`
- `keys.by_imei` (map IMEI to 16-byte key in hex)

### IMEI and encryption key

`keys.by_imei` is a dictionary:

- key = IMEI of device (string with digits)
- value = XTEA key in hex (`32` hex chars = `16` bytes)

Example:

```json
{
  "keys": {
    "default_hex": null,
    "by_imei": {
      "863703030668235": "4f9c2d0ab3e17c55a8d2f0b19c6e4a73"
    }
  }
}
```

Generate a strong key:

```bash
openssl rand -hex 16
```

Important:

- Do not invent predictable keys (`1234...`, dates, IMEI-based patterns).
- Device key in TELEOFIS configurator and server key in JSON must be identical.
- Prefer unique key per IMEI.

## Run

Install package in editable mode first:

```bash
python3 -m pip install --user -e .
```

Then run:

```bash
python3 -m rtu_receiver --config ./config/receiver.example.json
```

One datagram mode (for tests):

```bash
python3 -m rtu_receiver --config ./config/receiver.example.json --once --log-level debug
```

## Tests

Install dev deps and run:

```bash
python3 -m pip install --user -e .[dev]
python3 -m pytest
```

## systemd

Example unit: `systemd/rtu102-python-receiver.service`

Adjust paths before installation.

## cPanel notes

- Shared cPanel hosting usually cannot run this receiver as a stable service:
  - no `systemd`,
  - restricted long-running processes,
  - often restricted UDP sockets.
- VPS with cPanel and root access is suitable.
- For public receive from device use:
  - `listen_host: "0.0.0.0"` (not `127.0.0.1`),
  - open UDP port in firewall/security group.
