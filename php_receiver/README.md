# RTU102 PHP Receiver

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

- PHP 8.3+
- `ext-sockets`
- Composer

## Install

```bash
composer install
```

## Config

Use `config/receiver.example.json` as template.

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

```bash
php bin/receiver.php --config ./config/receiver.example.json
```

One datagram mode:

```bash
php bin/receiver.php --config ./config/receiver.example.json --once --log-level debug
```

## Tests

```bash
composer test
```

## systemd

Example unit: `systemd/rtu102-php-receiver.service`

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
