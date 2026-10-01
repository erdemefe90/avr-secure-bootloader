"""Version 2 signed AVR image format shared by packager and flasher."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import cmac, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"AVR2"
IMAGE_MAGIC = 0xEFEFEFEF
HW_ID = 0x0301
BOOT_START = 0x7000
PAGE_SIZE = 128
HEADER_OFFSET = 0x100
TAG_OFFSET = 52
HEADER_FORMAT = "<IHBBBHH12s9s6s12s16s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
SIGNATURE_SIZE = 64
WIRE_PAGE_SIZE = PAGE_SIZE + 16


@dataclass(frozen=True)
class Header:
    magic: int
    hw_id: int
    sw_major: int
    sw_minor: int
    sw_revision: int
    build: int
    image_size: int
    compile_date: bytes
    compile_time: bytes
    avr_gcc_version: bytes
    nonce: bytes
    tag: bytes

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Header":
        if len(raw) != HEADER_SIZE:
            raise ValueError("invalid image header length")
        header = cls(*struct.unpack(HEADER_FORMAT, raw))
        if (header.magic != IMAGE_MAGIC or header.hw_id != HW_ID or
                header.image_size < HEADER_OFFSET + PAGE_SIZE or
                header.image_size > BOOT_START or header.image_size % PAGE_SIZE):
            raise ValueError("invalid image header or hardware ID")
        return header

    def to_bytes(self) -> bytes:
        return struct.pack(HEADER_FORMAT, self.magic, self.hw_id,
                           self.sw_major, self.sw_minor, self.sw_revision,
                           self.build, self.image_size, self.compile_date,
                           self.compile_time, self.avr_gcc_version,
                           self.nonce, self.tag)

    @property
    def version(self) -> str:
        return f"{self.sw_major}.{self.sw_minor}.{self.sw_revision}+{self.build}"

    @staticmethod
    def _text(value: bytes) -> str:
        return value.split(b"\0", 1)[0].decode("ascii", errors="replace")

    @property
    def compiled(self) -> str:
        return f"{self._text(self.compile_date)} {self._text(self.compile_time)}"

    @property
    def compiler(self) -> str:
        return self._text(self.avr_gcc_version)


def load_device_key(path) -> bytes:
    key = bytes.fromhex(path.read_text().strip())
    if len(key) != 16:
        raise ValueError("device key must be 16 bytes")
    return key


def aes_block(key: bytes, block: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return cipher.update(block) + cipher.finalize()


def derive_keys(root: bytes) -> tuple[bytes, bytes]:
    if len(root) != 16:
        raise ValueError("device key must be 16 bytes")
    return aes_block(root, b"\x02" * 16), aes_block(root, b"\x01" * 16)


def cmac_tag(key: bytes, data: bytes) -> bytes:
    mac = cmac.CMAC(algorithms.AES(key))
    mac.update(data)
    return mac.finalize()


def crypt_image(key: bytes, nonce: bytes, data: bytes) -> bytes:
    if len(nonce) != 12 or len(data) > BOOT_START or len(data) % 16:
        raise ValueError("invalid nonce or image length")
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce + b"\x00" * 4)).encryptor()
    return cipher.update(data) + cipher.finalize()


def prepare_image(hex_image: bytes, root: bytes, nonce: bytes | None = None) -> tuple[bytes, Header]:
    if len(hex_image) < HEADER_OFFSET + HEADER_SIZE or len(hex_image) > BOOT_START:
        raise ValueError("application image exceeds flash map")
    padded = bytearray(hex_image)
    padded.extend(b"\xff" * (-len(padded) % PAGE_SIZE))
    if len(padded) > BOOT_START:
        raise ValueError("application image exceeds boot boundary")
    raw = bytes(padded[HEADER_OFFSET:HEADER_OFFSET + HEADER_SIZE])
    original = Header(*struct.unpack(HEADER_FORMAT, raw))
    if original.magic != IMAGE_MAGIC or original.hw_id != HW_ID:
        raise ValueError("application header is invalid")
    nonce = nonce if nonce is not None else os.urandom(12)
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    header = Header(original.magic, original.hw_id,
                    original.sw_major, original.sw_minor, original.sw_revision,
                    original.build, len(padded), original.compile_date,
                    original.compile_time, original.avr_gcc_version,
                    nonce, b"\x00" * 16)
    padded[HEADER_OFFSET:HEADER_OFFSET + HEADER_SIZE] = header.to_bytes()
    _, mac_key = derive_keys(root)
    tag = cmac_tag(mac_key, b"I" + bytes(padded))
    header = Header(header.magic, header.hw_id,
                    header.sw_major, header.sw_minor, header.sw_revision,
                    header.build, header.image_size, header.compile_date,
                    header.compile_time, header.avr_gcc_version,
                    header.nonce, tag)
    padded[HEADER_OFFSET:HEADER_OFFSET + HEADER_SIZE] = header.to_bytes()
    return bytes(padded), header


def build_package(image: bytes, header: Header, root: bytes, signer) -> bytes:
    enc_key, mac_key = derive_keys(root)
    ciphertext = crypt_image(enc_key, header.nonce, image)
    raw_header = header.to_bytes()
    body = bytearray(MAGIC + struct.pack("<I", len(image)) + raw_header)
    for index in range(len(image) // PAGE_SIZE):
        page = ciphertext[index * PAGE_SIZE:(index + 1) * PAGE_SIZE]
        tag = cmac_tag(mac_key, b"P" + raw_header + struct.pack("<H", index) + page)
        body.extend(page + tag)
    return bytes(body) + signer.sign(bytes(body))


def parse_package(data: bytes, verifier) -> tuple[Header, list[tuple[bytes, bytes]]]:
    if len(data) < 8 + HEADER_SIZE + SIGNATURE_SIZE or data[:4] != MAGIC:
        raise ValueError("invalid package magic or length")
    size = struct.unpack_from("<I", data, 4)[0]
    header = Header.from_bytes(data[8:8 + HEADER_SIZE])
    if size != header.image_size or len(data) != 8 + HEADER_SIZE + (size // PAGE_SIZE) * WIRE_PAGE_SIZE + SIGNATURE_SIZE:
        raise ValueError("package length does not match signed header")
    try:
        verifier.verify(data[-SIGNATURE_SIZE:], data[:-SIGNATURE_SIZE])
    except InvalidSignature as exc:
        raise ValueError("firmware signature is invalid") from exc
    pages = []
    start = 8 + HEADER_SIZE
    for offset in range(start, len(data) - SIGNATURE_SIZE, WIRE_PAGE_SIZE):
        pages.append((data[offset:offset + PAGE_SIZE], data[offset + PAGE_SIZE:offset + WIRE_PAGE_SIZE]))
    return header, pages


def verify_and_decrypt(data: bytes, verifier, root: bytes) -> bytes:
    header, pages = parse_package(data, verifier)
    enc_key, mac_key = derive_keys(root)
    raw_header = header.to_bytes()
    for index, (page, tag) in enumerate(pages):
        expected = cmac_tag(mac_key, b"P" + raw_header + struct.pack("<H", index) + page)
        if expected != tag:
            raise ValueError(f"page {index} CMAC is invalid")
    image = crypt_image(enc_key, header.nonce, b"".join(page for page, _ in pages))
    if image[HEADER_OFFSET:HEADER_OFFSET + HEADER_SIZE] != raw_header:
        raise ValueError("encrypted header does not match signed header")
    check = bytearray(image)
    check[HEADER_OFFSET + TAG_OFFSET:HEADER_OFFSET + HEADER_SIZE] = b"\x00" * 16
    if cmac_tag(mac_key, b"I" + bytes(check)) != header.tag:
        raise ValueError("image CMAC is invalid")
    return image


def load_signer(path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_verifier(path):
    return serialization.load_pem_public_key(path.read_bytes())
