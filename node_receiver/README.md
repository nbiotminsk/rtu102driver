# RTU102 Node.js Receiver

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

- Node.js 22+

## Config

Use `config/receiver.example.json` as template.

Key fields:

- `listen_host`
- `listen_port`
- `log_dir`
- `decode_enabled`
- `keys.default_hex`
- `keys.by_imei` (map IMEI to 16-byte key in hex)

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

### Ключ в конфигураторе устройства

В поле `Ключ` укажите XTEA-ключ:

- `32` hex-символа (`16` байт),
- без пробелов,
- без `0x`.

Пример:

```text
4f9c2d0ab3e17c55a8d2f0b19c6e4a73
```

Ключ на устройстве и ключ в серверном JSON должны быть одинаковыми.

## Run

```bash
cd /Users/nikolaj/Projects/RTU102_driver/rtu102driver/node_receiver
npm install
node ./bin/receiver.js --config ./config/receiver.example.json
```

One datagram mode:

```bash
node ./bin/receiver.js --config ./config/receiver.example.json --once --log-level debug
```

## Run On Server (24/7)

1. Check Node.js version:

```bash
node -v
```

Required: `v22.x`.

2. Deploy app:

```bash
sudo mkdir -p /opt/rtu102
sudo cp -R /Users/nikolaj/Projects/RTU102_driver/rtu102driver/node_receiver /opt/rtu102/
cd /opt/rtu102/node_receiver
npm install --omit=dev
```

3. Create production config `/opt/rtu102/node_receiver/config/receiver.json`:

```json
{
  "listen_host": "0.0.0.0",
  "listen_port": 5000,
  "log_dir": "/var/log/rtu102",
  "decode_enabled": true,
  "keys": {
    "default_hex": null,
    "by_imei": {
      "863703030668235": "YOUR_32_HEX_KEY"
    }
  }
}
```

4. Create service user and log directory:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin rtu || true
sudo mkdir -p /var/log/rtu102
sudo chown -R rtu:rtu /var/log/rtu102 /opt/rtu102/node_receiver
```

5. Install and start systemd service:

```bash
sudo cp /opt/rtu102/node_receiver/systemd/rtu102-node-receiver.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rtu102-node-receiver
```

6. Open UDP port:

```bash
sudo ufw allow 5000/udp
```

If you use a cloud VPS, also open `5000/udp` in cloud firewall/security group.

7. Check status:

```bash
sudo systemctl status rtu102-node-receiver
journalctl -u rtu102-node-receiver -f
```

## Tests

```bash
npm test
```

## systemd

Example unit: `systemd/rtu102-node-receiver.service`

Adjust paths before installation.
