"""Small packet codec used by the RS485 flasher."""

from __future__ import annotations

import time
from dataclasses import dataclass

STX = 0xAA
CMD_HEADER = 0xB0
CMD_BEGIN = 0xB1
CMD_PAGE = 0xB3
CMD_FINISH = 0xB4
CMD_ACK = 0xB5
CMD_NACK = 0xB6
CMD_RESET = 0xB7

NACK_PACKET = 1
NACK_STATE = 2
NACK_SIZE = 3
NACK_AUTH = 4
NACK_IMAGE = 5


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
