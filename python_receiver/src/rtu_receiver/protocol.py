from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .crc16 import crc16_ccitt_false
from .xtea import xtea_decrypt_ecb_le

FRAME_START = 0xC0
FRAME_END = 0xC2
ESCAPE = 0xC4

_ESC_DECODE = {
    0xC1: 0xC0,
    0xC3: 0xC2,
    0xC4: 0xC4,
}

_ESC_ENCODE = {
    0xC0: bytes((0xC4, 0xC1)),
    0xC2: bytes((0xC4, 0xC3)),
    0xC4: bytes((0xC4, 0xC4)),
}

# Documented fixed lengths of type_id in ID=3 event_data blocks.
EVENT_TYPE_LENGTHS: Dict[int, int] = {
    0: 4,
    1: 4,
    2: 4,
    3: 4,
    6: 4,
    7: 1,
    8: 1,
    9: 1,
    10: 1,
    11: 1,
    12: 4,
    13: 4,
    14: 4,
    15: 4,
    16: 4,
    17: 4,
    18: 4,
    19: 4,
    20: 1,
    21: 4,
    22: 1,
    23: 1,
    24: 1,
    25: 1,
    26: 1,
    27: 4,
    28: 4,
    29: 4,
    30: 4,
    31: 1,
    32: 1,
    33: 1,
    37: 4,
    38: 4,
    39: 4,
    40: 4,
    41: 4,
    42: 4,
    43: 4,
    44: 1,
    45: 1,
    46: 1,
    47: 1,
    48: 1,
    49: 1,
    50: 4,
    51: 1,
}


@dataclass
class ProtocolError(Exception):
    stage: str
    reason: str
    details: Dict[str, Any]
    imei: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.stage}:{self.reason}"


@dataclass
class DecodeResult:
    imei: str
    frame_ok: bool
    crc_ok: bool
    payload_hex: str
    records: List[Dict[str, Any]]
    warnings: List[str]
    nonfatal_errors: List[Dict[str, Any]]


def stuff_payload(raw: bytes) -> bytes:
    out = bytearray()
    for byte in raw:
        escaped = _ESC_ENCODE.get(byte)
        if escaped is None:
            out.append(byte)
        else:
            out.extend(escaped)
    return bytes(out)


def unstuff_payload(stuffed: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(stuffed):
        byte = stuffed[i]
        if byte != ESCAPE:
            out.append(byte)
            i += 1
            continue

        if i + 1 >= len(stuffed):
            raise ProtocolError(
                stage="unstuff",
                reason="dangling_escape_byte",
                details={"offset": i},
            )

        esc = stuffed[i + 1]
        decoded = _ESC_DECODE.get(esc)
        if decoded is None:
            raise ProtocolError(
                stage="unstuff",
                reason="invalid_escape_sequence",
                details={"offset": i, "escape_byte": esc},
            )

        out.append(decoded)
        i += 2

    return bytes(out)


def parse_imei(imei_bytes: bytes) -> str:
    if len(imei_bytes) != 8:
        raise ProtocolError(
            stage="imei",
            reason="invalid_imei_bytes_length",
            details={"length": len(imei_bytes)},
        )
    return str(int.from_bytes(imei_bytes, "little", signed=False))


def build_plain_for_encrypt(payload: bytes) -> bytes:
    pad_len = (8 - ((len(payload) + 2) % 8)) % 8
    padded = payload + (b"\x00" * pad_len)
    crc = crc16_ccitt_false(padded)
    return padded + crc.to_bytes(2, "little")


def build_frame(imei: str, encrypted_payload: bytes) -> bytes:
    imei_bytes = int(imei).to_bytes(8, "little", signed=False)
    body = imei_bytes + encrypted_payload
    return bytes((FRAME_START,)) + stuff_payload(body) + bytes((FRAME_END,))


def decode_datagram(datagram: bytes, key_resolver: Callable[[str], Optional[bytes]]) -> DecodeResult:
    if len(datagram) < 2:
        raise ProtocolError(
            stage="frame",
            reason="too_short",
            details={"length": len(datagram)},
        )

    if datagram[0] != FRAME_START or datagram[-1] != FRAME_END:
        raise ProtocolError(
            stage="frame",
            reason="invalid_boundaries",
            details={
                "start": datagram[0],
                "end": datagram[-1],
            },
        )

    stuffed_body = datagram[1:-1]
    body = unstuff_payload(stuffed_body)

    if len(body) < 16:
        raise ProtocolError(
            stage="frame",
            reason="body_too_short",
            details={"body_len": len(body)},
        )

    imei = parse_imei(body[:8])
    ciphertext = body[8:]

    if not ciphertext or len(ciphertext) % 8 != 0:
        raise ProtocolError(
            stage="xtea",
            reason="invalid_ciphertext_length",
            details={"cipher_len": len(ciphertext)},
            imei=imei,
        )

    key = key_resolver(imei)
    if key is None:
        raise ProtocolError(
            stage="key_lookup",
            reason="missing_key_for_imei",
            details={"imei": imei},
            imei=imei,
        )
    if len(key) != 16:
        raise ProtocolError(
            stage="key_lookup",
            reason="invalid_key_length",
            details={"imei": imei, "key_len": len(key)},
            imei=imei,
        )

    try:
        plaintext = xtea_decrypt_ecb_le(ciphertext, key)
    except ValueError as exc:
        raise ProtocolError(
            stage="xtea",
            reason="decrypt_failed",
            details={"message": str(exc)},
            imei=imei,
        ) from exc

    if len(plaintext) < 2:
        raise ProtocolError(
            stage="crc",
            reason="plaintext_too_short",
            details={"plain_len": len(plaintext)},
            imei=imei,
        )

    crc_recv = int.from_bytes(plaintext[-2:], "little", signed=False)
    plain_no_crc = plaintext[:-2]
    crc_calc = crc16_ccitt_false(plain_no_crc)
    if crc_calc != crc_recv:
        raise ProtocolError(
            stage="crc",
            reason="crc_mismatch",
            details={
                "received": crc_recv,
                "calculated": crc_calc,
            },
            imei=imei,
        )

    parsed = parse_payload(plain_no_crc)

    return DecodeResult(
        imei=imei,
        frame_ok=True,
        crc_ok=True,
        payload_hex=parsed["payload_used"].hex(),
        records=parsed["records"],
        warnings=parsed["warnings"],
        nonfatal_errors=parsed["nonfatal_errors"],
    )


def parse_payload(payload_with_pad: bytes) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    warnings: List[str] = []
    nonfatal_errors: List[Dict[str, Any]] = []

    offset = 0
    while offset < len(payload_with_pad):
        if payload_with_pad[offset] == 0 and _all_zero(payload_with_pad[offset:]):
            break

        data_id = payload_with_pad[offset]
        offset += 1

        try:
            record, offset, parse_warnings, parse_errors = _parse_record(data_id, payload_with_pad, offset)
        except ValueError as exc:
            warnings.append("payload_parse_error")
            nonfatal_errors.append(
                {
                    "stage": "payload_parse",
                    "reason": "record_parse_failed",
                    "details": {
                        "data_id": data_id,
                        "offset": offset,
                        "message": str(exc),
                    },
                }
            )
            records.append(
                {
                    "id": data_id,
                    "type": "unknown",
                    "raw_hex": payload_with_pad[offset:].hex(),
                    "parse_error": str(exc),
                }
            )
            offset = len(payload_with_pad)
            break

        records.append(record)
        warnings.extend(parse_warnings)
        nonfatal_errors.extend(parse_errors)

    return {
        "payload_used": payload_with_pad[:offset],
        "padding_len": len(payload_with_pad) - offset,
        "records": records,
        "warnings": warnings,
        "nonfatal_errors": nonfatal_errors,
    }


def _parse_record(data_id: int, buf: bytes, offset: int) -> tuple[Dict[str, Any], int, List[str], List[Dict[str, Any]]]:
    warnings: List[str] = []
    nonfatal_errors: List[Dict[str, Any]] = []

    if data_id in (1, 6):
        param_id, value, offset = _parse_param_len_data(buf, offset)
        return (
            {
                "id": data_id,
                "type": "config_command" if data_id == 1 else "read_command",
                "param_id": param_id,
                "len": len(value),
                "data_hex": value.hex(),
            },
            offset,
            warnings,
            nonfatal_errors,
        )

    if data_id == 2:
        _require_len(buf, offset, 2, "truncated_response")
        param_id = buf[offset]
        result_code = buf[offset + 1]
        return (
            {
                "id": 2,
                "type": "config_response",
                "param_id": param_id,
                "result_code": result_code,
            },
            offset + 2,
            warnings,
            nonfatal_errors,
        )

    if data_id == 3:
        _require_len(buf, offset, 1, "truncated_archive_seq")
        seq = buf[offset]
        offset += 1

        events: List[Dict[str, Any]] = []
        while offset < len(buf):
            if buf[offset] == 0 and _all_zero(buf[offset:]):
                break

            _require_len(buf, offset, 6, "truncated_event_header")
            event_code = buf[offset]
            event_time = int.from_bytes(buf[offset + 1 : offset + 5], "little", signed=False)
            event_data_len = buf[offset + 5]
            offset += 6

            _require_len(buf, offset, event_data_len, "truncated_event_data")
            event_data = buf[offset : offset + event_data_len]
            offset += event_data_len

            parsed_event = _parse_event_data(event_data)
            warnings.extend(parsed_event["warnings"])
            nonfatal_errors.extend(parsed_event["nonfatal_errors"])
            events.append(
                {
                    "event_code": event_code,
                    "event_time": event_time,
                    "event_data_len": event_data_len,
                    "event_data": parsed_event["entries"],
                }
            )

        return (
            {
                "id": 3,
                "type": "archive",
                "seq": seq,
                "events": events,
            },
            offset,
            warnings,
            nonfatal_errors,
        )

    if data_id == 4:
        _require_len(buf, offset, 1, "truncated_archive_ack")
        seq = buf[offset]
        return (
            {
                "id": 4,
                "type": "archive_ack",
                "seq": seq,
            },
            offset + 1,
            warnings,
            nonfatal_errors,
        )

    if data_id == 7:
        _require_len(buf, offset, 3, "truncated_read_response_header")
        param_id = buf[offset]
        result_code = buf[offset + 1]
        data_len = buf[offset + 2]
        offset += 3
        _require_len(buf, offset, data_len, "truncated_read_response_data")
        value = buf[offset : offset + data_len]
        return (
            {
                "id": 7,
                "type": "read_response",
                "param_id": param_id,
                "result_code": result_code,
                "len": data_len,
                "data_hex": value.hex(),
            },
            offset + data_len,
            warnings,
            nonfatal_errors,
        )

    if data_id == 8:
        raw = buf[offset:]
        return (
            {
                "id": 8,
                "type": "auth",
                "raw_hex": raw.hex(),
            },
            len(buf),
            warnings,
            nonfatal_errors,
        )

    if data_id == 9:
        _require_len(buf, offset, 1, "truncated_telemetry_count")
        count = buf[offset]
        offset += 1

        items = []
        for _ in range(count):
            _require_len(buf, offset, 2, "truncated_telemetry_item_header")
            param_id = buf[offset]
            data_len = buf[offset + 1]
            offset += 2
            _require_len(buf, offset, data_len, "truncated_telemetry_item_data")
            value = buf[offset : offset + data_len]
            offset += data_len
            items.append(
                {
                    "param_id": param_id,
                    "len": data_len,
                    "data_hex": value.hex(),
                }
            )

        return (
            {
                "id": 9,
                "type": "telemetry",
                "count": count,
                "items": items,
            },
            offset,
            warnings,
            nonfatal_errors,
        )

    if data_id in (10, 11, 12, 13, 14):
        raw = buf[offset:]
        warnings.append("rtu800_extended_id")
        nonfatal_errors.append(
            {
                "stage": "payload_parse",
                "reason": "rtu800_extended_id",
                "details": {"data_id": data_id},
            }
        )
        return (
            {
                "id": data_id,
                "type": "rtu800_extended",
                "raw_hex": raw.hex(),
            },
            len(buf),
            warnings,
            nonfatal_errors,
        )

    raw = buf[offset:]
    warnings.append("unknown_data_id")
    nonfatal_errors.append(
        {
            "stage": "payload_parse",
            "reason": "unknown_data_id",
            "details": {"data_id": data_id},
        }
    )
    return (
        {
            "id": data_id,
            "type": "unknown",
            "raw_hex": raw.hex(),
        },
        len(buf),
        warnings,
        nonfatal_errors,
    )


def _parse_param_len_data(buf: bytes, offset: int) -> tuple[int, bytes, int]:
    _require_len(buf, offset, 2, "truncated_param_len_data_header")
    param_id = buf[offset]
    data_len = buf[offset + 1]
    offset += 2
    _require_len(buf, offset, data_len, "truncated_param_len_data_value")
    value = buf[offset : offset + data_len]
    return param_id, value, offset + data_len


def _parse_event_data(event_data: bytes) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    warnings: List[str] = []
    nonfatal_errors: List[Dict[str, Any]] = []

    offset = 0
    while offset < len(event_data):
        type_id = event_data[offset]
        offset += 1

        fixed_len = EVENT_TYPE_LENGTHS.get(type_id)
        if fixed_len is None:
            warnings.append("unknown_type_id")
            nonfatal_errors.append(
                {
                    "stage": "payload_parse",
                    "reason": "unknown_type_id",
                    "details": {"type_id": type_id},
                }
            )
            entries.append(
                {
                    "type_id": type_id,
                    "raw_hex": event_data[offset:].hex(),
                    "unknown": True,
                }
            )
            break

        if offset + fixed_len > len(event_data):
            warnings.append("event_type_len_mismatch")
            nonfatal_errors.append(
                {
                    "stage": "payload_parse",
                    "reason": "event_type_len_mismatch",
                    "details": {
                        "type_id": type_id,
                        "expected_len": fixed_len,
                        "available": len(event_data) - offset,
                    },
                }
            )
            entries.append(
                {
                    "type_id": type_id,
                    "raw_hex": event_data[offset:].hex(),
                    "len_mismatch": True,
                }
            )
            break

        value = event_data[offset : offset + fixed_len]
        offset += fixed_len
        entries.append(
            {
                "type_id": type_id,
                "len": fixed_len,
                "raw_hex": value.hex(),
            }
        )

    return {
        "entries": entries,
        "warnings": warnings,
        "nonfatal_errors": nonfatal_errors,
    }


def _all_zero(data: bytes) -> bool:
    for byte in data:
        if byte != 0:
            return False
    return True


def _require_len(buf: bytes, offset: int, needed: int, reason: str) -> None:
    if offset + needed > len(buf):
        raise ValueError(reason)
