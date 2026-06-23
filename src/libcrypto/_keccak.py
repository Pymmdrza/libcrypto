"""Pure Python Keccak-256 implementation.

Ethereum, TRON, and EVM-compatible chains use the original Keccak-256
padding, not the standardized NIST SHA3-256 padding exposed by
``hashlib.sha3_256``.
"""
from __future__ import annotations

from typing import List

_MASK64 = (1 << 64) - 1

_ROUND_CONSTANTS = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]

_ROTATION_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol64(value: int, shift: int) -> int:
    shift &= 63
    if shift == 0:
        return value & _MASK64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f1600(state: List[int]) -> None:
    for round_constant in _ROUND_CONSTANTS:
        c = [
            state[x]
            ^ state[x + 5]
            ^ state[x + 10]
            ^ state[x + 15]
            ^ state[x + 20]
            for x in range(5)
        ]

        d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]

        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]

        b = [0] * 25
        for x in range(5):
            for y in range(5):
                new_x = y
                new_y = (2 * x + 3 * y) % 5
                b[new_x + 5 * new_y] = _rol64(
                    state[x + 5 * y], _ROTATION_OFFSETS[x][y]
                )

        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (
                    b[x + 5 * y]
                    ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])
                ) & _MASK64

        state[0] ^= round_constant


def keccak_256(data: bytes) -> bytes:
    """Return the Keccak-256 digest for *data*.

    This is intentionally not ``hashlib.sha3_256``. The padding byte is
    ``0x01`` for Keccak, while SHA3 uses ``0x06``.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes.")

    rate = 136  # 1088-bit bitrate for Keccak-256.
    state = [0] * 25
    offset = 0

    while offset + rate <= len(data):
        block = data[offset : offset + rate]
        for lane_index in range(rate // 8):
            lane = int.from_bytes(
                block[lane_index * 8 : (lane_index + 1) * 8], "little"
            )
            state[lane_index] ^= lane
        _keccak_f1600(state)
        offset += rate

    block = bytearray(rate)
    remaining = data[offset:]
    block[: len(remaining)] = remaining
    block[len(remaining)] ^= 0x01
    block[-1] ^= 0x80

    for lane_index in range(rate // 8):
        lane = int.from_bytes(
            block[lane_index * 8 : (lane_index + 1) * 8], "little"
        )
        state[lane_index] ^= lane

    _keccak_f1600(state)

    output = bytearray()
    while len(output) < 32:
        for lane_index in range(rate // 8):
            output.extend(state[lane_index].to_bytes(8, "little"))
        if len(output) >= 32:
            break
        _keccak_f1600(state)

    return bytes(output[:32])


__all__ = ["keccak_256"]
