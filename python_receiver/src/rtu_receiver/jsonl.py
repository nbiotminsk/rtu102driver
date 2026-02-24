from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


class JsonlWriter:
    def __init__(self, log_dir: Path) -> None:
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def utc_now_iso() -> str:
        return datetime.now(tz=timezone.utc).isoformat()

    def write_raw(self, record: Dict[str, Any]) -> None:
        self._write("raw", record)

    def write_decoded(self, record: Dict[str, Any]) -> None:
        self._write("decoded", record)

    def write_error(self, record: Dict[str, Any]) -> None:
        self._write("errors", record)

    def _write(self, stream: str, record: Dict[str, Any]) -> None:
        date_suffix = datetime.now(tz=timezone.utc).strftime("%Y%m%d")
        path = self.log_dir / f"{stream}-{date_suffix}.jsonl"
        with path.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
