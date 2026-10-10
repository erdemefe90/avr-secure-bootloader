"""Write only the 16-byte device serial over RS485; no Qt or firmware package needed."""

from __future__ import annotations

import argparse
from collections import deque
import math
import sys
import time

import serial

if __package__:
    from .Flasher.protocol import (CMD_ACK, CMD_HEADER, CMD_INFO, CMD_NACK, CMD_SERIAL,
                                  NACK_IMAGE, NACK_LOCK, NACK_PACKET, NACK_SIZE,
                                  NACK_STATE, SERIAL_SEQ, DeviceInfo, Parser, encode,
                                  SERIAL_SIZE, EMPTY_SERIAL, encode_serial, decode_serial)
else:
    from Flasher.protocol import (CMD_ACK, CMD_HEADER, CMD_INFO, CMD_NACK, CMD_SERIAL,
                                 NACK_IMAGE, NACK_LOCK, NACK_PACKET, NACK_SIZE,
                                 NACK_STATE, SERIAL_SEQ, DeviceInfo, Parser, encode,
                                 SERIAL_SIZE, EMPTY_SERIAL, encode_serial, decode_serial)

RETRIES = 5
BOOT_PROBE_DELAY = 0.5


class SerialWriteError(Exception):
    pass


def parse_serial(value: str) -> bytes:
    try:
        return encode_serial(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def positive_timeout(value: str) -> float:
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError("timeout must be a finite positive number")
    return result


class SerialWriter:
    def __init__(self, port, timeout: float = 2.0):
        self.port = port
        self.timeout = timeout
        self.parser = Parser()
        self.packets = deque()

    def _send(self, data: bytes):
        if self.port.write(data) != len(data):
            raise SerialWriteError("serial write was incomplete")

    def _next_packet(self, deadline: float):
        while time.monotonic() < deadline:
            if self.packets:
                return self.packets.popleft()
            data = self.port.read(self.port.in_waiting or 1)
            self.packets.extend(self.parser.feed(data))
        return None

    def connect_bootloader(self):
        deadline = time.monotonic() + max(6.0, self.timeout)
        probe_deadline = time.monotonic() + BOOT_PROBE_DELAY
        header_seen = False
        boot_sent = False
        while time.monotonic() < deadline:
            if not header_seen and not boot_sent and time.monotonic() >= probe_deadline:
                self._send(b"BOOT\n")
                boot_sent = True
            read_deadline = min(deadline, probe_deadline) if not header_seen and not boot_sent else deadline
            packet = self._next_packet(read_deadline)
            if packet is None:
                continue
            if packet.command == CMD_HEADER and len(packet.payload) == 68:
                header_seen = True
            elif header_seen and packet.command == CMD_INFO:
                try:
                    DeviceInfo.from_bytes(packet.payload)
                except ValueError:
                    continue
                # Wait for the full startup/idle burst before transmitting on RS485.
                return
        raise SerialWriteError("bootloader not detected; check the port or enter bootloader mode")

    def _exchange(self, command: int, payload: bytes = b"", expected_serial: bytes | None = None):
        # Drop parsed status left from an earlier request before starting a fresh exchange.
        self.packets.clear()
        mismatch = False
        for _ in range(RETRIES):
            self._send(encode(command, payload))
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                packet = self._next_packet(deadline)
                if packet is None:
                    break
                if command == CMD_INFO and packet.command == CMD_INFO:
                    try:
                        info = DeviceInfo.from_bytes(packet.payload)
                    except ValueError:
                        continue
                    if expected_serial is not None and info.serial != expected_serial:
                        mismatch = True
                        continue
                    return info
                if command == CMD_SERIAL and packet.command == CMD_ACK:
                    if packet.payload == SERIAL_SEQ.to_bytes(2, "little"):
                        return None
                if packet.command == CMD_NACK and len(packet.payload) == 3:
                    seq = int.from_bytes(packet.payload[:2], "little")
                    if seq not in (SERIAL_SEQ, 0xffff):
                        continue
                    reason = packet.payload[2]
                    if reason == NACK_PACKET:
                        break
                    descriptions = {
                        NACK_STATE: "device state/current serial changed, or bootloader lacks serial-write support",
                        NACK_SIZE: "device rejected the serial length",
                        NACK_LOCK: "boot-section writes are locked; serial provisioning requires ISP",
                        NACK_IMAGE: "flash readback failed; retry serial provisioning",
                    }
                    raise SerialWriteError(descriptions.get(reason, f"device rejected request (NACK {reason})"))
        if mismatch:
            raise SerialWriteError("serial readback does not match the requested value")
        raise SerialWriteError(f"no valid response after {RETRIES} attempts")

    def write(self, value: str | bytes, *, replace: bool = False) -> DeviceInfo:
        try:
            if isinstance(value, bytes):
                value = decode_serial(value)
            value = encode_serial(value)
        except (ValueError, TypeError) as exc:
            raise SerialWriteError(str(exc)) from exc
        self.connect_bootloader()
        current = self._exchange(CMD_INFO)
        if current.serial == value:
            return current
        if current.serial != EMPTY_SERIAL and not replace:
            raise SerialWriteError("a serial is already provisioned; use --replace to change it")
        if not current.boot_writable:
            raise SerialWriteError("boot-section writes are locked; serial provisioning requires ISP")
        self._exchange(CMD_SERIAL, current.serial + value)
        return self._exchange(CMD_INFO, expected_serial=value)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="serial port, e.g. COM5 or /dev/ttyUSB0")
    parser.add_argument("--serial", required=True, type=parse_serial, help="serial text, at most 15 UTF-8 bytes; NUL/padding added automatically")
    parser.add_argument("--replace", action="store_true", help="allow replacing an existing serial")
    parser.add_argument("--timeout", type=positive_timeout, default=2.0, help="response timeout in seconds (default: 2)")
    args = parser.parse_args(argv)
    try:
        with serial.Serial(args.port, 115200, timeout=0.05, write_timeout=0.5) as port:
            info = SerialWriter(port, args.timeout).write(args.serial, replace=args.replace)
    except (SerialWriteError, serial.SerialException, OSError) as exc:
        print(f"Serial write failed: {exc}", file=sys.stderr)
        return 1
    print(f"Serial verified: {info.serial_text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
