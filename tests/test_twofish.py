"""Tests for the bundled pure-Python Twofish implementation (jks._twofish)."""

import os
import sys
import unittest
from pathlib import Path

import jks
from jks._twofish import Twofish

# Known-answer tests from the Twofish paper / reference submission (ecb_tbl.txt)
KAT = [
    ("00000000000000000000000000000000", "00000000000000000000000000000000", "9F589F5CF6122C32B6BFEC2F2AE8C35A"),
    ("9F589F5CF6122C32B6BFEC2F2AE8C35A", "D491DB16E7B1C39E86CB086B789F5419", "019F9809DE1711858FAAC3A3BA20FBC3"),
    (
        "0123456789ABCDEFFEDCBA98765432100011223344556677",
        "00000000000000000000000000000000",
        "CFD1D2E5A9BE9CDF501F13B892BD2248",
    ),
    (
        "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF",
        "00000000000000000000000000000000",
        "37527BE0052334B89F0CFCCAE87CFA20",
    ),
]

# Result of the 49th iteration of the chained test of the reference submission, where each
# plaintext is the previous ciphertext and each key the concatenation of the previous plaintexts.
ITERATED = {
    16: "5D9D4EEFFA9151575524F115815A12E0",
    24: "E75449212BEEF9F4A390BD860A640941",
    32: "37FE26FF1CF66175F5DDF4C33B97A205",
}


class TwofishTests(unittest.TestCase):
    def test_known_answers(self):
        for key, pt, ct in KAT:
            cipher = Twofish(bytes.fromhex(key))
            self.assertEqual(cipher.encrypt(bytes.fromhex(pt)), bytes.fromhex(ct))
            self.assertEqual(cipher.decrypt(bytes.fromhex(ct)), bytes.fromhex(pt))

    def test_iterated(self):
        for key_size, expected in ITERATED.items():
            key, pt = bytes(key_size), bytes(16)
            for _ in range(49):
                ct = Twofish(key).encrypt(pt)
                key = (pt + key)[:key_size]
                pt = ct
            self.assertEqual(ct, bytes.fromhex(expected))

    def test_roundtrip(self):
        for key_size in (16, 24, 32):
            cipher = Twofish(os.urandom(key_size))
            for _ in range(20):
                block = os.urandom(16)
                self.assertEqual(cipher.decrypt(cipher.encrypt(block)), block)

    def test_short_key_is_zero_padded(self):
        self.assertEqual(Twofish(b"\x01").encrypt(bytes(16)), Twofish(b"\x01" + bytes(15)).encrypt(bytes(16)))
        self.assertEqual(Twofish(bytes(20)).encrypt(bytes(16)), Twofish(bytes(24)).encrypt(bytes(16)))

    def test_invalid_input(self):
        self.assertRaises(ValueError, Twofish, b"")
        self.assertRaises(ValueError, Twofish, bytes(33))
        cipher = Twofish(bytes(16))
        self.assertRaises(ValueError, cipher.encrypt, bytes(15))
        self.assertRaises(ValueError, cipher.decrypt, bytes(17))


class PackagingTests(unittest.TestCase):
    @unittest.skipIf(sys.version_info < (3, 11), "tomllib requires Python 3.11+")
    def test_version_matches_pyproject(self):
        if sys.version_info < (3, 11):
            return
        import tomllib

        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        with pyproject.open("rb") as f:
            self.assertEqual(jks.__version__, tomllib.load(f)["project"]["version"])
