from __future__ import annotations

import re
import tkinter as tk
from tkinter import messagebox

from .protocol import DecodeResult, ProtocolError, decode_datagram


HEX_BYTE_RE = re.compile(r"0x([0-9a-fA-F]{2})")


def parse_hex_dump(raw: str) -> bytes:
    prefixed = HEX_BYTE_RE.findall(raw)
    if prefixed:
        return bytes(int(value, 16) for value in prefixed)

    compact = re.sub(r"[^0-9a-fA-F]", "", raw)
    if not compact or len(compact) % 2 != 0:
        raise ValueError("hex dump must contain full bytes")
    return bytes.fromhex(compact)


def parse_key(raw: str) -> bytes:
    value = raw.strip()
    if len(value) == 16:
        return value.encode("ascii")
    if len(value) == 32 and all(ch in "0123456789abcdefABCDEF" for ch in value):
        key = bytes.fromhex(value)
        if len(key) == 16:
            return key
    raise ValueError("key must be 16 ASCII characters or 32 hex characters")


def decode_packet(packet_text: str, key_text: str) -> DecodeResult:
    datagram = parse_hex_dump(packet_text)
    key = parse_key(key_text)
    return decode_datagram(datagram, lambda _imei: key)


def extract_counter_values(decoded: DecodeResult) -> tuple[str, list[int], str]:
    for record in decoded.records:
        if record.get("type") == "telemetry":
            counters = _counters_from_telemetry(record)
            return decoded.imei, counters, "telemetry"
        if record.get("type") == "archive":
            counters = _counters_from_archive(record)
            return decoded.imei, counters, "archive"
    raise ValueError("packet does not contain telemetry or archive data with counters")


def _counters_from_telemetry(record: dict) -> list[int]:
    items = {item["param_id"]: bytes.fromhex(item["data_hex"]) for item in record.get("items", [])}

    packed = items.get(2)
    if packed and len(packed) >= 16:
        return [int.from_bytes(packed[index * 4 : (index + 1) * 4], "little") for index in range(4)]

    counters = []
    for param_id in (18, 19, 20, 21):
        value = items.get(param_id)
        if value is None or len(value) != 4:
            raise ValueError("telemetry does not contain all four counters")
        counters.append(int.from_bytes(value, "little"))
    return counters


def _counters_from_archive(record: dict) -> list[int]:
    latest = [None, None, None, None]
    for event in record.get("events", []):
        for entry in event.get("event_data", []):
            type_id = entry.get("type_id")
            if type_id in (0, 1, 2, 3):
                latest[type_id] = int.from_bytes(bytes.fromhex(entry["data_hex"]), "little")

    if any(value is None for value in latest):
        raise ValueError("archive does not contain all four counters")
    return [int(value) for value in latest]


class CounterViewerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("RTU102 Counter Decoder")
        self.root.geometry("900x700")
        self.root.minsize(700, 500)

        frame = tk.Frame(root, padx=12, pady=12)
        frame.pack(fill=tk.BOTH, expand=True)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)

        tk.Label(frame, text="XTEA key", anchor="w").grid(row=0, column=0, sticky="ew")
        self.key_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.key_var).grid(row=1, column=0, sticky="ew", pady=(4, 12))

        tk.Label(frame, text="Packet hex dump", anchor="w").grid(row=2, column=0, sticky="ew")
        self.packet_text = tk.Text(frame, wrap=tk.WORD, height=18, relief=tk.SOLID, borderwidth=1)
        self.packet_text.grid(row=3, column=0, sticky="nsew", pady=(4, 12))

        button_row = tk.Frame(frame)
        button_row.grid(row=4, column=0, sticky="w", pady=(0, 12))
        tk.Button(button_row, text="Decode", command=self.decode).pack(side=tk.LEFT)
        tk.Button(button_row, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=(8, 0))

        self.result_var = tk.StringVar(value="Insert packet and key, then press Decode.")
        self.result_label = tk.Label(
            frame,
            textvariable=self.result_var,
            justify=tk.LEFT,
            anchor="nw",
            relief=tk.SOLID,
            borderwidth=1,
            padx=8,
            pady=8,
        )
        self.result_label.grid(row=5, column=0, sticky="nsew")

    def clear(self) -> None:
        self.key_var.set("")
        self.packet_text.delete("1.0", tk.END)
        self.result_var.set("Insert packet and key, then press Decode.")

    def decode(self) -> None:
        packet_text = self.packet_text.get("1.0", tk.END).strip()
        key_text = self.key_var.get().strip()
        try:
            decoded = decode_packet(packet_text, key_text)
            imei, counters, source = extract_counter_values(decoded)
        except (ValueError, ProtocolError) as exc:
            messagebox.showerror("Decode error", str(exc))
            return

        self.result_var.set(
            "\n".join(
                [
                    f"IMEI: {imei}",
                    f"Source: {source}",
                    f"Counter 1: {counters[0]}",
                    f"Counter 2: {counters[1]}",
                    f"Counter 3: {counters[2]}",
                    f"Counter 4: {counters[3]}",
                ]
            )
        )


def main() -> int:
    root = tk.Tk()
    CounterViewerApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
