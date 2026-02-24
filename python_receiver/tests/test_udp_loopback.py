from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

from rtu_receiver.config import load_config
from rtu_receiver.crc16 import crc16_ccitt_false
from rtu_receiver.jsonl import JsonlWriter
from rtu_receiver.protocol import build_frame, build_plain_for_encrypt
from rtu_receiver.udp_server import UdpReceiverServer
from rtu_receiver.xtea import xtea_encrypt_ecb_le


def _pick_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for(predicate, timeout: float = 2.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("timeout waiting for condition")


def _build_valid_datagram(imei: str, key_hex: str) -> bytes:
    key = bytes.fromhex(key_hex)
    payload = bytes([9, 0])  # ID=9 telemetry with 0 items
    plain = build_plain_for_encrypt(payload)
    encrypted = xtea_encrypt_ecb_le(plain, key)
    return build_frame(imei, encrypted)


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_udp_loopback_valid_frame(tmp_path: Path) -> None:
    imei = "863703030668235"
    key_hex = "79757975797579756f706f706f706f70"
    port = _pick_port()
    log_dir = tmp_path / "logs"

    config_path = tmp_path / "receiver.json"
    config_path.write_text(
        json.dumps(
            {
                "listen_host": "127.0.0.1",
                "listen_port": port,
                "log_dir": str(log_dir),
                "decode_enabled": True,
                "keys": {
                    "default_hex": None,
                    "by_imei": {
                        imei: key_hex,
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    cfg = load_config(config_path)
    server = UdpReceiverServer(cfg, JsonlWriter(cfg.log_dir))

    server_error: list[BaseException] = []

    def _runner() -> None:
        try:
            server.run(once=True)
        except BaseException as exc:  # noqa: BLE001
            server_error.append(exc)

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    time.sleep(0.1)

    datagram = _build_valid_datagram(imei, key_hex)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.sendto(datagram, ("127.0.0.1", port))

    thread.join(timeout=3)
    if thread.is_alive():
        raise AssertionError("server thread did not finish")
    if server_error:
        raise AssertionError(f"server error: {server_error[0]}")

    date_suffix = time.strftime("%Y%m%d", time.gmtime())
    raw_path = log_dir / f"raw-{date_suffix}.jsonl"
    decoded_path = log_dir / f"decoded-{date_suffix}.jsonl"

    _wait_for(lambda: raw_path.exists() and decoded_path.exists())

    raw_records = _read_jsonl(raw_path)
    decoded_records = _read_jsonl(decoded_path)

    assert len(raw_records) == 1
    assert raw_records[0]["datagram_hex"] == datagram.hex()

    assert len(decoded_records) == 1
    decoded = decoded_records[0]
    assert decoded["imei"] == imei
    assert decoded["frame_ok"] is True
    assert decoded["crc_ok"] is True
    assert decoded["records"][0]["id"] == 9


def test_decode_errors_written(tmp_path: Path) -> None:
    imei = "863703030668235"
    key_hex = "79757975797579756f706f706f706f70"
    log_dir = tmp_path / "logs"

    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(
        json.dumps(
            {
                "listen_host": "127.0.0.1",
                "listen_port": 5001,
                "log_dir": str(log_dir),
                "decode_enabled": True,
                "keys": {
                    "default_hex": None,
                    "by_imei": {
                        imei: key_hex,
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    cfg = load_config(cfg_path)
    writer = JsonlWriter(cfg.log_dir)
    server = UdpReceiverServer(cfg, writer)

    # Bad frame (no C0/C2)
    server.handle_datagram(b"\x00\x01\x02", "127.0.0.1", 11111)

    # Good frame, but wrong CRC.
    key = bytes.fromhex(key_hex)
    payload = bytes([9, 0])
    plain = build_plain_for_encrypt(payload)
    broken = plain[:-2] + ((crc16_ccitt_false(plain[:-2]) ^ 0xFFFF).to_bytes(2, "little"))
    bad_crc_datagram = build_frame(imei, xtea_encrypt_ecb_le(broken, key))
    server.handle_datagram(bad_crc_datagram, "127.0.0.1", 22222)

    date_suffix = time.strftime("%Y%m%d", time.gmtime())
    errors_path = log_dir / f"errors-{date_suffix}.jsonl"
    errors = _read_jsonl(errors_path)

    assert len(errors) >= 2
    reasons = {(e["stage"], e["reason"]) for e in errors}
    assert ("frame", "invalid_boundaries") in reasons
    assert ("crc", "crc_mismatch") in reasons
