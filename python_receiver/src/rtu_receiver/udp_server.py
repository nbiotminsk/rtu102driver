from __future__ import annotations

import socket
from dataclasses import asdict
from typing import Optional

from .config import ReceiverConfig
from .jsonl import JsonlWriter
from .protocol import DecodeResult, ProtocolError, decode_datagram


class UdpReceiverServer:
    def __init__(self, config: ReceiverConfig, writer: JsonlWriter, log_level: str = "info") -> None:
        self.config = config
        self.writer = writer
        self.log_level = log_level

    def run(self, once: bool = False) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((self.config.listen_host, self.config.listen_port))
            if once:
                sock.settimeout(5.0)
            if self.log_level == "debug":
                print(f"listening on udp://{self.config.listen_host}:{self.config.listen_port}")

            while True:
                try:
                    datagram, (src_ip, src_port) = sock.recvfrom(65535)
                except socket.timeout:
                    raise TimeoutError("timeout waiting for UDP datagram")
                self.handle_datagram(datagram, src_ip, src_port)
                if once:
                    break

    def handle_datagram(self, datagram: bytes, src_ip: str, src_port: int) -> None:
        ts = self.writer.utc_now_iso()
        datagram_hex = datagram.hex()

        self.writer.write_raw(
            {
                "ts_utc": ts,
                "src_ip": src_ip,
                "src_port": src_port,
                "len": len(datagram),
                "datagram_hex": datagram_hex,
            }
        )

        if not self.config.decode_enabled:
            return

        try:
            result = decode_datagram(datagram, self.config.keys.resolve_key)
            self._write_decoded(ts, src_ip, src_port, result)
            self._write_nonfatal_errors(ts, src_ip, src_port, datagram_hex, result)
        except ProtocolError as exc:
            self.writer.write_error(
                {
                    "ts_utc": ts,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "stage": exc.stage,
                    "reason": exc.reason,
                    "imei": exc.imei,
                    "datagram_hex": datagram_hex,
                    "details": exc.details,
                }
            )

    def _write_decoded(self, ts: str, src_ip: str, src_port: int, result: DecodeResult) -> None:
        payload = asdict(result)
        payload.update(
            {
                "ts_utc": ts,
                "src_ip": src_ip,
                "src_port": src_port,
            }
        )
        self.writer.write_decoded(payload)

    def _write_nonfatal_errors(
        self,
        ts: str,
        src_ip: str,
        src_port: int,
        datagram_hex: str,
        result: DecodeResult,
    ) -> None:
        for err in result.nonfatal_errors:
            self.writer.write_error(
                {
                    "ts_utc": ts,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "stage": err.get("stage", "payload_parse"),
                    "reason": err.get("reason", "nonfatal_parse_warning"),
                    "imei": result.imei,
                    "datagram_hex": datagram_hex,
                    "details": err.get("details", {}),
                }
            )
