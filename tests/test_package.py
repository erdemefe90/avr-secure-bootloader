import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from Tools.image_format import (HEADER_FORMAT, HEADER_OFFSET, HEADER_SIZE,
                                IMAGE_MAGIC, HW_ID, build_package,
                                parse_package, prepare_image,
                                verify_and_decrypt)
from Tools.Flasher.protocol import CMD_ACK, Parser, encode
import struct


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.root = bytes(range(16))
        self.signer = Ed25519PrivateKey.generate()
        self.verifier = self.signer.public_key()
        raw = bytearray(b"\xff" * 373)
        header = struct.pack(HEADER_FORMAT, IMAGE_MAGIC, HW_ID,
                             1, 2, 3, 123, 0,
                             b"Sep 28 2026\0", b"12:34:56\0", b"5.4.0\0",
                             b"\x00" * 12, b"\x00" * 16)
        raw[HEADER_OFFSET:HEADER_OFFSET + HEADER_SIZE] = header
        self.image, self.header = prepare_image(bytes(raw), self.root, b"0123456789ab")
        self.package = build_package(self.image, self.header, self.root, self.signer)

    def test_round_trip(self):
        parsed, pages = parse_package(self.package, self.verifier)
        self.assertEqual(parsed, self.header)
        self.assertEqual(len(pages), len(self.image) // 128)
        self.assertEqual(verify_and_decrypt(self.package, self.verifier, self.root), self.image)

    def test_signature_covers_header_ciphertext_tags_and_length(self):
        for offset in (8, 8 + HEADER_SIZE, 8 + HEADER_SIZE + 128, len(self.package) - 1):
            corrupted = bytearray(self.package)
            corrupted[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                parse_package(bytes(corrupted), self.verifier)
        with self.assertRaises(ValueError):
            parse_package(self.package[:-1], self.verifier)
        with self.assertRaises(ValueError):
            parse_package(self.package, Ed25519PrivateKey.generate().public_key())

    def test_wrong_device_key_rejected_after_signature(self):
        with self.assertRaises(ValueError):
            verify_and_decrypt(self.package, self.verifier, b"x" * 16)


class ProtocolTests(unittest.TestCase):
    def test_fragmentation_noise_and_bad_crc(self):
        parser = Parser()
        packet = encode(CMD_ACK, b"\x03\x00")
        bad = bytearray(packet)
        bad[-1] ^= 1
        self.assertEqual(parser.feed(b"noise" + bytes(bad[:3])), [])
        self.assertEqual(parser.feed(bytes(bad[3:]) + packet[:2]), [])
        result = parser.feed(packet[2:])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].command, CMD_ACK)
        self.assertEqual(result[0].payload, b"\x03\x00")


if __name__ == "__main__":
    unittest.main()
