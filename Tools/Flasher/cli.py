"""Headless controls for the signed AVR flasher."""

from __future__ import annotations

import argparse
from collections import deque
import json
import math
import os
from pathlib import Path
import sys
import time

import serial
import serial.tools.list_ports

if __package__:
    from ..image_format import HEADER_SIZE, PAGE_SIZE, Header
    from .policy import verified_package, flash_block_reason, hardware_warning
    from .protocol import (CMD_ACK, CMD_BEGIN, CMD_FINISH, CMD_HEADER, CMD_INFO, CMD_LOCK,
                           CMD_NACK, CMD_PAGE, CMD_RESET, CONTROL_SEQ, DeviceInfo,
                           NACK_PACKET, Parser, encode, lock_mode_mask, lock_mode_summary)
else:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from image_format import HEADER_SIZE, PAGE_SIZE, Header
    from policy import verified_package, flash_block_reason, hardware_warning
    from protocol import (CMD_ACK, CMD_BEGIN, CMD_FINISH, CMD_HEADER, CMD_INFO, CMD_LOCK,
                          CMD_NACK, CMD_PAGE, CMD_RESET, CONTROL_SEQ, DeviceInfo,
                          NACK_PACKET, Parser, encode, lock_mode_mask, lock_mode_summary)

RETRIES = 5
BOOT_PROBE_DELAY = 0.5
DEFAULT_KEY = Path(__file__).resolve().parents[2] / ".local" / "signing_public.pem"


class FlasherError(Exception):
    pass


class FlasherClient:
    def __init__(self, port, timeout=2.0):
        self.port = port
        self.timeout = timeout
        self.parser = Parser()
        self.packets = deque()
        self.device_header = None
        self.device_info = None
        self.mode = "unknown"

    def send(self, data):
        if self.port.write(data) != len(data):
            raise FlasherError("Serial write was incomplete")

    def receive(self, deadline):
        while time.monotonic() < deadline:
            if self.packets:
                return self.packets.popleft()
            data = self.port.read(self.port.in_waiting or 1)
            self.packets.extend(self.parser.feed(data))
        return None

    def update(self, packet):
        if packet.command == CMD_HEADER:
            if len(packet.payload) != HEADER_SIZE:
                raise FlasherError("Invalid device header length")
            try:
                self.device_header = None if packet.payload == b"\0" * HEADER_SIZE else Header.from_bytes(packet.payload)
            except ValueError as exc:
                raise FlasherError("Invalid device header") from exc
            self.mode = "bootloader"
        elif packet.command == CMD_INFO:
            try:
                self.device_info = DeviceInfo.from_bytes(packet.payload)
            except ValueError:
                return False
        return True

    def connect(self, enter_bootloader=True):
        deadline = time.monotonic() + max(6.0, self.timeout)
        probe_deadline = time.monotonic() + BOOT_PROBE_DELAY
        header_seen = False
        boot_sent = False
        while time.monotonic() < deadline:
            if enter_bootloader and not header_seen and not boot_sent and time.monotonic() >= probe_deadline:
                self.send(b"BOOT\n")
                boot_sent = True
            read_deadline = min(deadline, probe_deadline) if enter_bootloader and not boot_sent and not header_seen else deadline
            packet = self.receive(read_deadline)
            if packet is None:
                continue
            if not self.update(packet):
                continue
            if packet.command == CMD_HEADER:
                header_seen = True
            elif packet.command == CMD_INFO and header_seen:
                # Both packets must finish before the first half-duplex request.
                return
        raise FlasherError("Bootloader transition not confirmed")

    def request(self, command, payload=b"", seq=CONTROL_SEQ, timeout=None):
        self.packets.clear()
        for _ in range(RETRIES):
            self.send(encode(command, payload))
            deadline = time.monotonic() + (timeout if timeout is not None else self.timeout)
            while time.monotonic() < deadline:
                packet = self.receive(deadline)
                if packet is None:
                    break
                if not self.update(packet):
                    continue
                if command == CMD_INFO and packet.command == CMD_INFO:
                    return self.device_info
                if packet.command == CMD_ACK and command != CMD_INFO:
                    if packet.payload == seq.to_bytes(2, "little"):
                        return
                if packet.command == CMD_NACK and len(packet.payload) == 3:
                    received_seq = int.from_bytes(packet.payload[:2], "little")
                    if received_seq not in (seq, 0xffff):
                        continue
                    reason = packet.payload[2]
                    if reason == NACK_PACKET:
                        break
                    name = {2: "state", 3: "size", 4: "authentication", 5: "image", 6: "lock"}.get(reason, "unknown")
                    raise FlasherError(f"Device rejected command 0x{command:02X}: {name} (NACK {reason})")
        raise FlasherError(f"No valid response after {RETRIES} attempts (command 0x{command:02X})")

    def application(self):
        self.packets.clear()
        self.send(encode(CMD_RESET))
        self.mode = "unknown"
        self.device_info = None
        self.device_header = None
        self.parser = Parser()

    def flash(self, header, pages, *, force=False, progress=None):
        reason = flash_block_reason(header, self.device_header, self.device_info, force)
        if reason:
            raise FlasherError(reason)
        if len(pages) * PAGE_SIZE != header.image_size:
            raise FlasherError("Page count does not match the image header")
        warning = hardware_warning(header, self.device_header)
        if warning:
            print(f"Warning: {warning} Continuing flash.", file=sys.stderr)
        self.request(CMD_BEGIN, header.to_bytes(), 0xffff)
        for index, (ciphertext, tag) in enumerate(pages):
            self.request(CMD_PAGE, index.to_bytes(2, "little") + ciphertext + tag, index)
            if progress:
                progress(index + 1, len(pages))
        self.request(CMD_FINISH, len(pages).to_bytes(2, "little"), len(pages), timeout=max(8.0, self.timeout))
        self.device_header = header

    def lock(self, lb_mode=None):
        mask = lock_mode_mask(self.device_info, lb_mode)
        if mask:
            expected = self.device_info.lock_bits & ~mask & 0x3f
            self.request(CMD_LOCK, bytes((mask,)))
            info = self.request(CMD_INFO)
            if info.lock_bits & 0x3f != expected:
                self.device_info = None
                raise FlasherError("Lock readback did not match the requested modes")
        return self.device_info


def device_summary(client):
    result = {"mode": client.mode}
    if client.device_header:
        result["application_version"] = client.device_header.version
        result["hardware_version"] = client.device_header.hardware_version
    info = client.device_info
    if info:
        result.update({
            "bootloader_version": f"{info.sw_major}.{info.sw_minor}.{info.sw_revision}+{info.build}",
            "bootloader_compiled": f"{Header._text(info.compile_date)} {Header._text(info.compile_time)}",
            "serial": info.serial_text, "serial_provisioned": info.serial != b"\xff" * 16,
            "serial_valid": info.serial_text is not None,
            "fuses": {"low": f"0x{info.low_fuse:02X}", "high": f"0x{info.high_fuse:02X}",
                      "extended": f"0x{info.extended_fuse:02X}"},
            "lock_byte": f"0x{info.lock_bits:02X}", "blb0_mode": info.blb0_mode,
            "blb1_mode": info.blb1_mode, "lb_mode": info.lb_mode,
            "lock_groups": info.lock_descriptions(),
        })
    return result


def positive_timeout(value):
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError("timeout must be finite and positive")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("ports", help="list serial ports")
    verify = commands.add_parser("verify", help="verify a signed package without connecting")
    verify.add_argument("--file", required=True, type=Path)
    verify.add_argument("--key", type=Path, default=Path(os.environ.get("AVR_TRUSTED_PUBLIC_KEY", DEFAULT_KEY)))
    for name in ("info", "bootloader", "application", "flash", "lock"):
        sub = commands.add_parser(name)
        sub.add_argument("--port", required=True)
        sub.add_argument("--timeout", type=positive_timeout, default=2.0)
        if name == "flash":
            sub.add_argument("--file", required=True, type=Path)
            sub.add_argument("--key", type=Path, default=Path(os.environ.get("AVR_TRUSTED_PUBLIC_KEY", DEFAULT_KEY)))
            sub.add_argument("--force", action="store_true", help="override only the version policy")
        elif name == "lock":
            sub.add_argument("--lb-mode", type=int, choices=(1, 2, 3), required=True,
                             help="LB2/LB1 ISP protection; BLB0/BLB1 and fuses are read-only")
            sub.add_argument("--yes", action="store_true", help="confirm permanent hardware lock bits")
    args = parser.parse_args(argv)
    if args.command == "lock":
        if not args.yes:
            parser.error("lock requires --yes; unlocking needs ISP chip erase and erases firmware/serial")
    try:
        if args.command == "ports":
            result = [{"port": p.device, "description": p.description} for p in serial.tools.list_ports.comports()]
        else:
            if args.command in ("verify", "flash"):
                # Verify before opening a port or sending BOOT / BEGIN.
                header, pages = verified_package(args.file, args.key)
            if args.command == "verify":
                result = {"signature": "verified", "version": header.version,
                          "image_size": header.image_size, "hardware_version": header.hardware_version}
            else:
                with serial.Serial(args.port, 115200, timeout=0.05, write_timeout=0.5) as port:
                    client = FlasherClient(port, args.timeout)
                    if args.command == "application":
                        client.application()
                    else:
                        client.connect()
                    if args.command == "flash":
                        def progress(done, total):
                            if done == total or done % 16 == 0:
                                print(f"Verified {done}/{total} pages", file=sys.stderr)
                        client.flash(header, pages, force=args.force, progress=progress)
                    elif args.command == "lock":
                        description = lock_mode_summary(client.device_info, args.lb_mode)
                        print(description or "Requested lock modes already set", file=sys.stderr)
                        client.lock(args.lb_mode)
                    result = device_summary(client)
                    if args.command == "application":
                        result.update({"application_start": "requested", "confirmed": False})
                    if args.command == "flash":
                        result.update({"firmware": "verified", "version": header.version,
                                       "image_size": header.image_size, "application_start": "pending"})
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (FlasherError, serial.SerialException, OSError, ValueError, TypeError) as exc:
        print(f"Flasher failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
