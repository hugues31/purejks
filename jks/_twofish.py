"""Pure-Python Twofish block cipher (single 16-byte block, ECB).

Derived from the pure-Python implementation by Krzysztof Czaplicki and
Mateusz Orzełowski (https://github.com/K-Czaplicki/TwoFish), rewritten to
work on integers instead of binary strings, to compute the key schedule once
per key and to precompute the key-dependent S-boxes combined with the MDS
matrix ("full keying"), which makes it orders of magnitude faster.

Original work: Copyright (c) 2024 Krzysztof Czaplicki, Mateusz Orzełowski,
released under the MIT License (see LICENSE).

Only what pyjks needs is provided: a :class:`Twofish` object exposing
``encrypt(block)`` / ``decrypt(block)`` on single 16-byte blocks, API
compatible with the C-based ``twofish`` package it replaces. Chaining modes
are left to the caller.
"""

from __future__ import annotations

__all__ = ["Twofish"]

_MASK32 = 0xFFFFFFFF


def _rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _ror32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _ror4(x: int) -> int:
    return ((x >> 1) | (x << 3)) & 0xF


def _make_q(t0: list[int], t1: list[int], t2: list[int], t3: list[int]) -> tuple[int, ...]:
    """Build one of the fixed 8-bit permutations q0/q1 as a lookup table."""
    table = []
    for x in range(256):
        a0, b0 = x >> 4, x & 0xF
        a1 = a0 ^ b0
        b1 = (a0 ^ _ror4(b0) ^ (a0 << 3)) & 0xF
        a2, b2 = t0[a1], t1[b1]
        a3 = a2 ^ b2
        b3 = (a2 ^ _ror4(b2) ^ (a2 << 3)) & 0xF
        table.append((t3[b3] << 4) | t2[a3])
    return tuple(table)


_Q0 = _make_q(
    [8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4],
    [14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13],
    [11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1],
    [13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10],
)
_Q1 = _make_q(
    [2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5],
    [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8],
    [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15],
    [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10],
)


def _gf_mul(a: int, b: int, polynomial: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= polynomial
        b >>= 1
    return result


_MDS = ((1, 239, 91, 91), (91, 239, 239, 1), (239, 91, 1, 239), (239, 1, 239, 91))
_MDS_POLY = 0x169

_RS = (
    (1, 164, 85, 135, 90, 88, 219, 158),
    (164, 86, 130, 243, 30, 198, 104, 229),
    (2, 161, 252, 193, 71, 174, 61, 25),
    (164, 85, 135, 90, 88, 219, 158, 3),
)
_RS_POLY = 0x14D

# For each byte position i (0 = least significant) of the input word:
# the q permutation applied at each stage of the h function, from the stage
# that uses list word L[3] down to the one that uses L[0], then the final one.
_Q_BY_STAGE = (
    (_Q1, _Q0, _Q0, _Q1),  # before xor with L[3]
    (_Q1, _Q1, _Q0, _Q0),  # before xor with L[2]
    (_Q0, _Q1, _Q0, _Q1),  # before xor with L[1]
    (_Q0, _Q0, _Q1, _Q1),  # before xor with L[0]
    (_Q1, _Q0, _Q1, _Q0),  # final permutation
)

# MDS column j applied to every possible byte value, as 32-bit words.
_MDS_COLUMNS = tuple(
    tuple(
        _gf_mul(_MDS[0][j], x, _MDS_POLY)
        | (_gf_mul(_MDS[1][j], x, _MDS_POLY) << 8)
        | (_gf_mul(_MDS[2][j], x, _MDS_POLY) << 16)
        | (_gf_mul(_MDS[3][j], x, _MDS_POLY) << 24)
        for x in range(256)
    )
    for j in range(4)
)


def _h_byte(x: int, i: int, words: list[int]) -> int:
    """Run byte ``i`` of the h function input through the q/xor stages."""
    k = len(words)
    for stage in range(4 - k, 4):
        x = _Q_BY_STAGE[stage][i][x] ^ ((words[3 - stage] >> (8 * i)) & 0xFF)
    return _Q_BY_STAGE[4][i][x]


def _h(x: int, words: list[int]) -> int:
    result = 0
    for i in range(4):
        result ^= _MDS_COLUMNS[i][_h_byte((x >> (8 * i)) & 0xFF, i, words)]
    return result


class Twofish:
    """Twofish cipher keyed with a 16, 24 or 32 byte key.

    Keys shorter than 32 bytes whose length is not one of the standard sizes
    are zero-padded to the next standard size, as the specification allows.
    """

    block_size = 16

    def __init__(self, key: bytes) -> None:
        key = bytes(key)
        if not 0 < len(key) <= 32:
            raise ValueError("Twofish key must be 1 to 32 bytes long")
        size = 16 if len(key) <= 16 else 24 if len(key) <= 24 else 32
        key = key.ljust(size, b"\x00")
        k = size // 8

        m = [int.from_bytes(key[4 * i : 4 * i + 4], "little") for i in range(2 * k)]
        me, mo = m[0::2], m[1::2]

        s = []
        for i in range(k):
            chunk = key[8 * i : 8 * i + 8]
            word = 0
            for row in range(4):
                byte = 0
                for col in range(8):
                    byte ^= _gf_mul(_RS[row][col], chunk[col], _RS_POLY)
                word |= byte << (8 * row)
            s.append(word)
        s.reverse()

        rho = 0x01010101
        subkeys = []
        for i in range(20):
            a = _h(2 * i * rho, me)
            b = _rol32(_h((2 * i + 1) * rho, mo), 8)
            subkeys.append((a + b) & _MASK32)
            subkeys.append(_rol32((a + 2 * b) & _MASK32, 9))
        self._k = tuple(subkeys)

        # g(X) = h(X, S) = S0[x0] ^ S1[x1] ^ S2[x2] ^ S3[x3]
        self._s = tuple(tuple(_MDS_COLUMNS[i][_h_byte(x, i, s)] for x in range(256)) for i in range(4))

    def _g_pair(self, a: int, b: int) -> tuple[int, int]:
        s0, s1, s2, s3 = self._s
        t0 = s0[a & 0xFF] ^ s1[(a >> 8) & 0xFF] ^ s2[(a >> 16) & 0xFF] ^ s3[a >> 24]
        # g(ROL(b, 8)) without doing the rotation
        t1 = s0[b >> 24] ^ s1[b & 0xFF] ^ s2[(b >> 8) & 0xFF] ^ s3[(b >> 16) & 0xFF]
        return t0, t1

    def encrypt(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Twofish block must be exactly 16 bytes")
        k = self._k
        a = int.from_bytes(block[0:4], "little") ^ k[0]
        b = int.from_bytes(block[4:8], "little") ^ k[1]
        c = int.from_bytes(block[8:12], "little") ^ k[2]
        d = int.from_bytes(block[12:16], "little") ^ k[3]
        for r in range(16):
            t0, t1 = self._g_pair(a, b)
            c = _ror32(c ^ ((t0 + t1 + k[2 * r + 8]) & _MASK32), 1)
            d = _rol32(d, 1) ^ ((t0 + 2 * t1 + k[2 * r + 9]) & _MASK32)
            if r < 15:
                a, b, c, d = c, d, a, b
        return b"".join((w ^ k[4 + i]).to_bytes(4, "little") for i, w in enumerate((a, b, c, d)))

    def decrypt(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Twofish block must be exactly 16 bytes")
        k = self._k
        a = int.from_bytes(block[0:4], "little") ^ k[4]
        b = int.from_bytes(block[4:8], "little") ^ k[5]
        c = int.from_bytes(block[8:12], "little") ^ k[6]
        d = int.from_bytes(block[12:16], "little") ^ k[7]
        for r in range(15, -1, -1):
            t0, t1 = self._g_pair(a, b)
            c = _rol32(c, 1) ^ ((t0 + t1 + k[2 * r + 8]) & _MASK32)
            d = _ror32(d ^ ((t0 + 2 * t1 + k[2 * r + 9]) & _MASK32), 1)
            if r > 0:
                a, b, c, d = c, d, a, b
        return b"".join((w ^ k[i]).to_bytes(4, "little") for i, w in enumerate((a, b, c, d)))
