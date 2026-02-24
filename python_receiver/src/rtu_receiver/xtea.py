from __future__ import annotations

import struct

_DELTA = 0x9E3779B9
_MASK32 = 0xFFFFFFFF


def _key_to_words_le(key: bytes) -> tuple[int, int, int, int]:
    if len(key) != 16:
        raise ValueError("XTEA key must be 16 bytes")
    return struct.unpack("<4I", key)


def xtea_decrypt_block_le(block8: bytes, key16: bytes, rounds: int = 32) -> bytes:
    if len(block8) != 8:
        raise ValueError("XTEA block must be 8 bytes")
    if rounds <= 0:
        raise ValueError("rounds must be positive")

    v0, v1 = struct.unpack("<2I", block8)
    k0, k1, k2, k3 = _key_to_words_le(key16)
    key_words = (k0, k1, k2, k3)

    summation = (_DELTA * rounds) & _MASK32
    for _ in range(rounds):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (summation + key_words[(summation >> 11) & 3]))) & _MASK32
        summation = (summation - _DELTA) & _MASK32
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (summation + key_words[summation & 3]))) & _MASK32

    return struct.pack("<2I", v0, v1)


def xtea_encrypt_block_le(block8: bytes, key16: bytes, rounds: int = 32) -> bytes:
    if len(block8) != 8:
        raise ValueError("XTEA block must be 8 bytes")
    if rounds <= 0:
        raise ValueError("rounds must be positive")

    v0, v1 = struct.unpack("<2I", block8)
    k0, k1, k2, k3 = _key_to_words_le(key16)
    key_words = (k0, k1, k2, k3)

    summation = 0
    for _ in range(rounds):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (summation + key_words[summation & 3]))) & _MASK32
        summation = (summation + _DELTA) & _MASK32
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (summation + key_words[(summation >> 11) & 3]))) & _MASK32

    return struct.pack("<2I", v0, v1)


def xtea_decrypt_ecb_le(ciphertext: bytes, key16: bytes, rounds: int = 32) -> bytes:
    if not ciphertext or len(ciphertext) % 8 != 0:
        raise ValueError("ciphertext length must be positive and divisible by 8")

    out = bytearray()
    for i in range(0, len(ciphertext), 8):
        out.extend(xtea_decrypt_block_le(ciphertext[i : i + 8], key16, rounds=rounds))
    return bytes(out)


def xtea_encrypt_ecb_le(plaintext: bytes, key16: bytes, rounds: int = 32) -> bytes:
    if not plaintext or len(plaintext) % 8 != 0:
        raise ValueError("plaintext length must be positive and divisible by 8")

    out = bytearray()
    for i in range(0, len(plaintext), 8):
        out.extend(xtea_encrypt_block_le(plaintext[i : i + 8], key16, rounds=rounds))
    return bytes(out)
