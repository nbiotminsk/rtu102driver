from __future__ import annotations

from rtu_receiver.crc16 import crc16_ccitt_false
from rtu_receiver.protocol import (
    build_frame,
    build_plain_for_encrypt,
    parse_imei,
    parse_payload,
    stuff_payload,
    unstuff_payload,
)
from rtu_receiver.xtea import xtea_decrypt_ecb_le, xtea_encrypt_ecb_le


def test_byte_stuffing_roundtrip() -> None:
    raw = bytes([0x00, 0xC0, 0x01, 0xC2, 0x02, 0xC4, 0x03])
    stuffed = stuff_payload(raw)
    assert unstuff_payload(stuffed) == raw


def test_imei_parse_vector() -> None:
    imei_bytes = bytes.fromhex("cb9b558888110300")
    assert parse_imei(imei_bytes) == "863703030668235"


def test_crc16_reference_vector() -> None:
    assert crc16_ccitt_false(b"123456789") == 0x29B1


def test_xtea_decrypt_document_vector() -> None:
    key = bytes.fromhex("79757975797579756f706f706f706f70")
    ciphertext = bytes.fromhex(
        "60614e680e705d0fefcf7ac8102c4452ecb0c85768f2f2dc52415c43a36712f0"
        "31c9037dafd31f01ecb0c85768f2f2dc7b00be7e5a15fee1e78c63c58c2c6861"
        "fef9a1c4130a354c846448512e6a97ce4a9005690d1e3808f065c957538e1bac"
        "87e7228322ab39a6900146786840dc0bc536ad6afb6e4e3267fb045dd9c7e670"
        "f1c2d2ac1fcc71ad06b7b194de4031f4046744610aafa7b92fd3f392c3a5eeb1"
        "474ffa60c0587e68ecb0c85768f2f2dc2a88827461b41c99b2539b6bfdcd4325"
        "be3ced59be7b594addb3366e076f6e470cc41df1eb3a8d93c99eb7bdad5a474c"
        "33659653762910d0ecb0c85768f2f2dcecb0c85768f2f2dc82e715e7952a79c4"
        "660074ccc50741cab5eabb873ae706b4c8b008128df0af80fece91741fc5f641"
        "1145aab35ac9f6e0f8a937baed012d00c3be705a5e8c3440ddc1cd4e0051cccc"
    )

    plain = xtea_decrypt_ecb_le(ciphertext, key)
    assert plain.startswith(bytes.fromhex("09300004100e00000104f4779559"))
    assert int.from_bytes(plain[-2:], "little") == crc16_ccitt_false(plain[:-2])


def test_encrypt_decrypt_roundtrip() -> None:
    key = bytes.fromhex("79757975797579756f706f706f706f70")
    payload = bytes.fromhex("0900")
    plain = build_plain_for_encrypt(payload)
    enc = xtea_encrypt_ecb_le(plain, key)
    dec = xtea_decrypt_ecb_le(enc, key)
    assert dec == plain


def test_parse_payload_ids() -> None:
    payload = bytes.fromhex(
        "01010478563412"  # ID=1 param=1 len=4
        "020100"          # ID=2 param=1 code=0
        "0407"            # ID=4 seq=7
        "060300"          # ID=6 param=3 len=0
        "07030003313233"  # ID=7 param=3 code=0 len=3 data='123'
        "09020101aa0202bbcc"  # ID=9 count=2
    )

    parsed = parse_payload(payload)
    assert parsed["padding_len"] == 0
    assert [r["id"] for r in parsed["records"]] == [1, 2, 4, 6, 7, 9]


def test_parse_id3_synthetic_event() -> None:
    event_time = (1700000000).to_bytes(4, "little")
    # type 0 (4 bytes) + type 20 (1 byte)
    event_data = bytes([0, 1, 2, 3, 4, 20, 5])
    payload = bytes([3, 0x13, 1]) + event_time + bytes([len(event_data)]) + event_data

    parsed = parse_payload(payload)
    rec = parsed["records"][0]
    assert rec["id"] == 3
    assert rec["seq"] == 0x13
    assert rec["events"][0]["event_code"] == 1


def test_build_frame_boundaries() -> None:
    imei = "863703030668235"
    frame = build_frame(imei, bytes.fromhex("0011223344556677"))
    assert frame[0] == 0xC0
    assert frame[-1] == 0xC2
