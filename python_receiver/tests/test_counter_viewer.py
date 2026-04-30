from __future__ import annotations

from rtu_receiver.counter_viewer import extract_counter_values
from rtu_receiver.protocol import DecodeResult


def test_extract_counter_values_from_telemetry_param_2() -> None:
    decoded = DecodeResult(
        imei="867724030459827",
        frame_ok=True,
        crc_ok=True,
        payload_hex="",
        records=[
            {
                "id": 9,
                "type": "telemetry",
                "count": 1,
                "items": [
                    {
                        "param_id": 2,
                        "len": 16,
                        "data_hex": "01000000020000000300000004000000",
                    }
                ],
            }
        ],
        warnings=[],
        nonfatal_errors=[],
    )

    imei, counters, source = extract_counter_values(decoded)

    assert imei == "867724030459827"
    assert counters == [1, 2, 3, 4]
    assert source == "telemetry"


def test_extract_counter_values_from_archive() -> None:
    decoded = DecodeResult(
        imei="867724030459827",
        frame_ok=True,
        crc_ok=True,
        payload_hex="",
        records=[
            {
                "id": 3,
                "type": "archive",
                "seq": 7,
                "events": [
                    {
                        "event_code": 1,
                        "event_time": 0,
                        "event_data": [
                            {"type_id": 0, "data_hex": "05000000"},
                            {"type_id": 1, "data_hex": "06000000"},
                            {"type_id": 2, "data_hex": "07000000"},
                            {"type_id": 3, "data_hex": "08000000"},
                        ],
                    }
                ],
            }
        ],
        warnings=[],
        nonfatal_errors=[],
    )

    imei, counters, source = extract_counter_values(decoded)

    assert imei == "867724030459827"
    assert counters == [5, 6, 7, 8]
    assert source == "archive"
