from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


@dataclass
class KeyConfig:
    default_key: Optional[bytes]
    by_imei: Dict[str, bytes]

    def resolve_key(self, imei: str) -> Optional[bytes]:
        key = self.by_imei.get(imei)
        if key is not None:
            return key
        return self.default_key


@dataclass
class ReceiverConfig:
    listen_host: str
    listen_port: int
    log_dir: Path
    decode_enabled: bool
    keys: KeyConfig


def _parse_hex_key(hex_value: Optional[str], field: str) -> Optional[bytes]:
    if hex_value is None:
        return None
    if not isinstance(hex_value, str):
        raise ValueError(f"{field} must be null or hex string")
    if len(hex_value) != 32:
        raise ValueError(f"{field} must be exactly 32 hex characters")
    try:
        key = bytes.fromhex(hex_value)
    except ValueError as exc:
        raise ValueError(f"{field} must be valid hex") from exc
    if len(key) != 16:
        raise ValueError(f"{field} must decode to 16 bytes")
    return key


def load_config(path: str | Path) -> ReceiverConfig:
    cfg_path = Path(path)
    if not cfg_path.exists():
        raise ValueError(f"config file not found: {cfg_path}")

    try:
        raw = json.loads(cfg_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON config: {exc}") from exc

    listen_host = raw.get("listen_host", "127.0.0.1")
    listen_port = raw.get("listen_port", 5000)
    log_dir = raw.get("log_dir", "./logs")
    decode_enabled = raw.get("decode_enabled", True)
    keys = raw.get("keys", {})

    if not isinstance(listen_host, str) or not listen_host:
        raise ValueError("listen_host must be a non-empty string")
    if not isinstance(listen_port, int) or not (1 <= listen_port <= 65535):
        raise ValueError("listen_port must be an integer in range 1..65535")
    if not isinstance(log_dir, str) or not log_dir:
        raise ValueError("log_dir must be a non-empty string")
    if not isinstance(decode_enabled, bool):
        raise ValueError("decode_enabled must be boolean")
    if not isinstance(keys, dict):
        raise ValueError("keys must be an object")

    default_key = _parse_hex_key(keys.get("default_hex"), "keys.default_hex")

    by_imei_raw = keys.get("by_imei", {})
    if not isinstance(by_imei_raw, dict):
        raise ValueError("keys.by_imei must be an object")

    by_imei: Dict[str, bytes] = {}
    for imei, key_hex in by_imei_raw.items():
        if not isinstance(imei, str) or not imei.isdigit():
            raise ValueError("keys.by_imei keys must be IMEI strings with digits only")
        by_imei[imei] = _parse_hex_key(key_hex, f"keys.by_imei[{imei}]")  # type: ignore[arg-type]
        if by_imei[imei] is None:
            raise ValueError(f"keys.by_imei[{imei}] cannot be null")

    return ReceiverConfig(
        listen_host=listen_host,
        listen_port=listen_port,
        log_dir=Path(log_dir),
        decode_enabled=decode_enabled,
        keys=KeyConfig(default_key=default_key, by_imei=by_imei),
    )
