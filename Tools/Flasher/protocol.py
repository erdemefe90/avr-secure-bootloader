"""Small packet codec used by the RS485 flasher."""

from __future__ import annotations

import time
import struct
from dataclasses import dataclass

STX = 0xAA
CMD_HEADER = 0xB0
CMD_BEGIN = 0xB1
CMD_PAGE = 0xB3
CMD_FINISH = 0xB4
CMD_ACK = 0xB5
CMD_NACK = 0xB6
CMD_RESET = 0xB7
CMD_INFO = 0xB8
CMD_LOCK = 0xB9
CMD_SERIAL = 0xBA
SERIAL_SEQ = 0xFFFD
CONTROL_SEQ = 0xFFFE
LOCK_APP_WRITE = 0x04
LOCK_BOOT_WRITE = 0x10

NACK_PACKET = 1
NACK_STATE = 2
NACK_SIZE = 3
NACK_AUTH = 4
NACK_IMAGE = 5
NACK_LOCK = 6

INFO_FORMAT = "<BBBH12s9s16sBBBB"
INFO_SIZE = struct.calcsize(INFO_FORMAT)
SERIAL_SIZE = 16
EMPTY_SERIAL = b"\xff" * SERIAL_SIZE


def encode_serial(value: str) -> bytes:
    """Encode 1..15 UTF-8 bytes, followed by NUL and zero padding."""
    if not value or not value.isprintable():
        raise ValueError("serial must be nonempty printable text without NUL or control characters")
    raw = value.encode("utf-8")
    if len(raw) >= SERIAL_SIZE:
        raise ValueError("serial must be at most 15 UTF-8 bytes (plus the terminating NUL)")
    return raw.ljust(SERIAL_SIZE, b"\0")


def decode_serial(raw: bytes) -> str | None:
    """Read only the string before its NUL; None denotes erased flash."""
    if len(raw) != SERIAL_SIZE:
        raise ValueError("invalid serial field length")
    if raw == EMPTY_SERIAL:
        return None
    end = raw.find(b"\0")
    if end < 1:
        raise ValueError("serial field is empty or has no terminating NUL")
    value = raw[:end].decode("utf-8")
    if not value.isprintable():
        raise ValueError("serial field contains control characters")
    return value


@dataclass(frozen=True)
class DeviceInfo:
    sw_major: int
    sw_minor: int
    sw_revision: int
    build: int
    compile_date: bytes
    compile_time: bytes
    serial: bytes
    low_fuse: int
    high_fuse: int
    extended_fuse: int
    lock_bits: int

    @classmethod
    def from_bytes(cls, raw: bytes) -> "DeviceInfo":
        if len(raw) != INFO_SIZE:
            raise ValueError("invalid bootloader info length")
        return cls(*struct.unpack(INFO_FORMAT, raw))

    @property
    def serial_text(self) -> str | None:
        try:
            return decode_serial(self.serial)
        except ValueError:
            return None

    @property
    def application_writable(self) -> bool:
        return bool(self.lock_bits & LOCK_APP_WRITE)

    @property
    def application_readable(self) -> bool:
        return bool(self.lock_bits & 0x08)

    @property
    def boot_writable(self) -> bool:
        return bool(self.lock_bits & LOCK_BOOT_WRITE)

    @property
    def boot_readable_from_app(self) -> bool:
        return bool(self.lock_bits & 0x20)

    @property
    def blb0_mode(self) -> int:
        return {3: 1, 2: 2, 0: 3, 1: 4}[(self.lock_bits >> 2) & 3]

    @property
    def blb1_mode(self) -> int:
        return {3: 1, 2: 2, 0: 3, 1: 4}[(self.lock_bits >> 4) & 3]

    @property
    def lb_mode(self) -> int | None:
        return {3: 1, 2: 2, 0: 3}.get(self.lock_bits & 3)

    def lock_descriptions(self) -> dict[str, str]:
        bit = lambda index: (self.lock_bits >> index) & 1
        return {
            "blb0": (f"Mode {self.blb0_mode} — BLB02={bit(3)}, BLB01={bit(2)}; "
                     f"App writes: {'enabled' if self.application_writable else 'locked'}; "
                     f"Boot → App reads: {'enabled' if self.application_readable else 'locked'}"),
            "blb1": (f"Mode {self.blb1_mode} — BLB12={bit(5)}, BLB11={bit(4)}; "
                     f"Boot/serial writes: {'enabled' if self.boot_writable else 'locked'}; "
                     f"App → Boot reads: {'enabled' if self.boot_readable_from_app else 'locked'}"),
            "lb": (f"{'Mode ' + str(self.lb_mode) if self.lb_mode else 'Reserved combination'} — "
                   f"LB2={bit(1)}, LB1={bit(0)}; " +
                   {1: "ISP programming/verification enabled", 2: "ISP programming locked",
                    3: "ISP programming/verification locked", None: "do not use"}[self.lb_mode]),
        }


LB_MODE_LABELS = {
    1: "ISP programming / verification enabled",
    2: "block ISP flash / EEPROM programming and fuse writes",
    3: "block ISP flash / EEPROM programming / verification and fuse / lock writes",
}


def lock_mode_mask(info: DeviceInfo, lb_mode: int | None = None) -> int:
    """Program only LB2/LB1, preserving BLB pairs and rejecting bit unlocking."""
    if lb_mode is None:
        return 0
    if lb_mode not in LB_MODE_LABELS:
        raise ValueError(f"LB: invalid lock mode {lb_mode}")
    current = info.lock_bits & 3
    target = {1: 3, 2: 2, 3: 0}[lb_mode]
    if target & ~current:
        raise ValueError(f"LB: Mode {lb_mode} requires unlocking bits with ISP chip erase")
    return current & ~target


def lock_mode_summary(info: DeviceInfo, lb_mode=None) -> str:
    if not lock_mode_mask(info, lb_mode):
        return ""
    current = f"Mode {info.lb_mode}" if info.lb_mode else "Reserved LB2/LB1=01"
    return f"LB2/LB1: {current} → Mode {lb_mode}: {LB_MODE_LABELS[lb_mode]}"


def crc16(data: bytes) -> int:
    value = 0xFFFF
    for byte in data:
        value ^= byte << 8
        for _ in range(8):
            value = ((value << 1) ^ (0x1021 if value & 0x8000 else 0)) & 0xFFFF
    return value


def encode(command: int, payload: bytes = b"") -> bytes:
    if len(payload) > 146:
        raise ValueError("packet payload is too large")
    body = bytes((STX, command, len(payload))) + payload
    return body + crc16(body).to_bytes(2, "little")


@dataclass(frozen=True)
class Packet:
    command: int
    payload: bytes


class Parser:
    def __init__(self):
        self.buffer = bytearray()
        self.last_byte = 0.0

    def feed(self, data: bytes) -> list[Packet]:
        now = time.monotonic()
        if self.buffer and now - self.last_byte > 0.2:
            self.buffer.clear()
        if data:
            self.last_byte = now
            self.buffer.extend(data)
        packets = []
        while self.buffer:
            if self.buffer[0] != STX:
                del self.buffer[0]
                continue
            if len(self.buffer) < 3:
                break
            length = self.buffer[2]
            if length > 146:
                del self.buffer[0]
                continue
            size = 3 + length + 2
            if len(self.buffer) < size:
                break
            raw = bytes(self.buffer[:size])
            if crc16(raw[:-2]) == int.from_bytes(raw[-2:], "little"):
                packets.append(Packet(raw[1], raw[3:-2]))
                del self.buffer[:size]
            else:
                del self.buffer[0]
        return packets
