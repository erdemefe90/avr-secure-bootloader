import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import select
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from Tools import write_serial
from Tools.Flasher.protocol import (CMD_ACK, CMD_HEADER, CMD_INFO, CMD_NACK, CMD_SERIAL,
                                    INFO_FORMAT, encode_serial, decode_serial, NACK_IMAGE, NACK_LOCK, NACK_PACKET,
                                    NACK_STATE, SERIAL_SEQ, Parser, encode)

ROOT = Path(__file__).resolve().parents[1]
TEXT = "SN-001"
VALUE = encode_serial(TEXT)


class FakePort:
    def __init__(self, current=b"\xff" * 16, locks=0xff, *, app=False):
        self.current = current
        self.locks = locks
        self.rx = bytearray() if app else bytearray(encode(CMD_HEADER, b"\0" * 68))
        self.writes = []
        self.programs = 0
        self.lose_ack = False
        self.packet_nack = False
        self.reject = None
        self.wrong_readback = False
        self.respond = True
        self.closed = False
        if not app:
            self.rx.extend(encode(CMD_INFO, self.info()))

    def info(self):
        return struct.pack(INFO_FORMAT, 1, 1, 0, 1, b"Oct  2 2026", b"12:34:56",
                           self.current, 0xff, 0xd8, 0xfd, self.locks)

    @property
    def in_waiting(self):
        return min(7, len(self.rx))  # exercise fragmented packets

    def read(self, size):
        if not self.rx:
            time.sleep(0.001)
        result = bytes(self.rx[:size])
        del self.rx[:size]
        return result

    def write(self, data):
        self.writes.append(data)
        if not self.respond:
            return len(data)
        if data == b"BOOT\n":
            self.rx.extend(encode(CMD_HEADER, b"\0" * 68))
            self.rx.extend(encode(CMD_INFO, self.info()))
            return len(data)
        packet, = Parser().feed(data)
        if packet.command == CMD_INFO:
            self.rx.extend(encode(CMD_INFO, self.info()))
        elif packet.command == CMD_SERIAL:
            if self.packet_nack:
                self.packet_nack = False
                self.rx.extend(encode(CMD_NACK, b"\xff\xff" + bytes((NACK_PACKET,))))
                return len(data)
            if self.reject:
                self.rx.extend(encode(CMD_NACK, SERIAL_SEQ.to_bytes(2, "little") + bytes((self.reject,))))
                return len(data)
            old, new = packet.payload[:16], packet.payload[16:]
            if self.current != new:
                if self.current != old:
                    raise AssertionError("expected serial in request is stale")
                self.current = new
                self.programs += 1
            if self.lose_ack:
                self.lose_ack = False
            else:
                self.rx.extend(encode(CMD_ACK, SERIAL_SEQ.to_bytes(2, "little")))
            if self.wrong_readback:
                self.current = b"x" * 16
        else:
            raise AssertionError(f"unexpected command: {packet.command}")
        return len(data)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True


class SerialWriterTests(unittest.TestCase):
    def test_input_validation(self):
        self.assertEqual(write_serial.parse_serial(TEXT), VALUE)
        for bad in ("", "x" * 16, "ff" * 16, "A\0B", "SN\n001", "ğ" * 8):
            with self.subTest(bad=bad), self.assertRaises(argparse.ArgumentTypeError):
                write_serial.parse_serial(bad)
        for bad in ("0", "-1", "nan", "inf"):
            with self.subTest(bad=bad), self.assertRaises(argparse.ArgumentTypeError):
                write_serial.positive_timeout(bad)

    def test_text_serial_byte_boundaries_and_utf8(self):
        for text in ("A", "123456789012345", "ç" * 7 + "A"):
            with self.subTest(text=text):
                raw = write_serial.parse_serial(text)
                self.assertEqual(len(raw), 16)
                self.assertEqual(raw[-1], 0)
                self.assertEqual(decode_serial(raw), text)
        self.assertEqual(write_serial.parse_serial("123"), b"123" + b"\0" * 13)
        with self.assertRaises(argparse.ArgumentTypeError):
            write_serial.parse_serial("1234567890123456")

    def test_read_stops_at_nul_without_requiring_zero_padding(self):
        self.assertEqual(decode_serial(b"SN-1\0" + b"\xff" * 11), "SN-1")
        self.assertIsNone(decode_serial(b"\xff" * 16))
        for bad in (b"A" * 16, b"\0" * 16, b"\xff\0" + b"\0" * 14,
                    b"A\n\0" + b"\0" * 13):
            with self.subTest(raw=bad), self.assertRaises(ValueError):
                decode_serial(bad)

    def test_writer_accepts_short_text_without_manual_padding(self):
        port = FakePort()
        info = write_serial.SerialWriter(port, 0.02).write("DEVICE-7")
        self.assertEqual(info.serial_text, "DEVICE-7")
        self.assertEqual(port.current, b"DEVICE-7" + b"\0" * 8)

    def test_write_only_serial_and_verify(self):
        port = FakePort()
        info = write_serial.SerialWriter(port, 0.02).write(VALUE)
        self.assertEqual(info.serial, VALUE)
        self.assertEqual(port.programs, 1)
        packets = [Parser().feed(raw)[0] for raw in port.writes]
        self.assertEqual([p.command for p in packets], [CMD_INFO, CMD_SERIAL, CMD_INFO])
        self.assertEqual(packets[1].payload, b"\xff" * 16 + VALUE)

    def test_silent_application_enters_bootloader(self):
        port = FakePort(app=True)
        write_serial.SerialWriter(port, 0.02).write(VALUE)
        self.assertEqual(port.writes[0], b"BOOT\n")
        self.assertEqual(port.programs, 1)

    def test_existing_serial_requires_replace(self):
        port = FakePort(current=b"a" * 16)
        with self.assertRaisesRegex(write_serial.SerialWriteError, "--replace"):
            write_serial.SerialWriter(port, 0.02).write(VALUE)
        self.assertEqual(port.programs, 0)
        port.rx.extend(encode(CMD_HEADER, b"\0" * 68))
        port.rx.extend(encode(CMD_INFO, port.info()))
        write_serial.SerialWriter(port, 0.02).write(VALUE, replace=True)
        self.assertEqual(port.current, VALUE)

    def test_already_written_value_does_not_require_write_permission(self):
        port = FakePort(current=VALUE, locks=0xef)
        info = write_serial.SerialWriter(port, 0.02).write(VALUE)
        self.assertEqual(info.serial, VALUE)
        self.assertEqual(port.programs, 0)

    def test_locked_boot_section_is_rejected(self):
        port = FakePort(locks=0xef)
        with self.assertRaisesRegex(write_serial.SerialWriteError, "locked"):
            write_serial.SerialWriter(port, 0.02).write(VALUE)
        self.assertEqual(port.programs, 0)

    def test_lost_ack_retries_same_request(self):
        port = FakePort()
        port.lose_ack = True
        write_serial.SerialWriter(port, 0.01).write(VALUE)
        requests = [raw for raw in port.writes if raw[1] == CMD_SERIAL]
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0], requests[1])
        self.assertEqual(port.programs, 1)

    def test_packet_nack_retries_but_state_lock_image_nacks_stop(self):
        port = FakePort()
        port.packet_nack = True
        write_serial.SerialWriter(port, 0.02).write(VALUE)
        self.assertEqual(port.programs, 1)
        for reason in (NACK_STATE, NACK_LOCK, NACK_IMAGE):
            with self.subTest(reason=reason):
                port = FakePort()
                port.reject = reason
                with self.assertRaises(write_serial.SerialWriteError):
                    write_serial.SerialWriter(port, 0.02).write(VALUE)
                self.assertEqual(port.programs, 0)
                self.assertEqual(sum(raw[1] == CMD_SERIAL for raw in port.writes), 1)

    def test_timeout_and_wrong_readback_are_failures(self):
        port = FakePort()
        port.respond = False
        with self.assertRaisesRegex(write_serial.SerialWriteError, "no valid response"):
            write_serial.SerialWriter(port, 0.005).write(VALUE)
        port = FakePort()
        port.wrong_readback = True
        with self.assertRaisesRegex(write_serial.SerialWriteError, "readback"):
            write_serial.SerialWriter(port, 0.005).write(VALUE)

    def test_main_uses_fixed_baud_and_closes_port(self):
        port = FakePort()
        stdout = io.StringIO()
        with patch("Tools.write_serial.serial.Serial", return_value=port) as factory, redirect_stdout(stdout):
            rc = write_serial.main(["--port", "COM5", "--serial", TEXT])
        self.assertEqual(rc, 0)
        factory.assert_called_once_with("COM5", 115200, timeout=0.05, write_timeout=0.5)
        self.assertTrue(port.closed)
        self.assertIn(TEXT, stdout.getvalue())

    def test_main_reports_failure_and_closes_port(self):
        port = FakePort(locks=0xef)
        with patch("Tools.write_serial.serial.Serial", return_value=port), redirect_stderr(io.StringIO()):
            rc = write_serial.main(["--port", "COM5", "--serial", TEXT])
        self.assertEqual(rc, 1)
        self.assertTrue(port.closed)


@unittest.skipUnless(shutil.which("avr-gcc") and shutil.which("qemu-system-avr"),
                     "AVR GCC and QEMU AVR are required")
class AvrSerialTests(unittest.TestCase):
    def test_real_serial_and_lb_handlers_preserve_pages_state_and_blb_bits(self):
        if not (ROOT / "Bootloader/Release/device_key.h").exists():
            self.skipTest("build the bootloader first")
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "serial.elf"
            result = subprocess.run([
                "avr-gcc", "-mmcu=atmega328p", "-DF_CPU=16000000UL", "-DCBC=0", "-DCTR=0", "-DECB=1",
                f"-I{ROOT / 'Common'}", f"-I{ROOT / 'Bootloader/tiny-AES-c'}",
                f"-I{ROOT / 'Bootloader/Release'}", "-Os", "-ffunction-sections", "-fdata-sections",
                str(ROOT / "tests/avr_serial_harness.c"), "-Wl,--gc-sections,--relax", "-o", str(elf)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            qemu = subprocess.Popen([
                "qemu-system-avr", "-machine", "uno", "-bios", str(elf), "-display", "none",
                "-serial", "stdio", "-monitor", "none", "-no-reboot"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            try:
                actual = bytearray()
                deadline = time.monotonic() + 3
                while len(actual) < 16 and time.monotonic() < deadline:
                    if select.select([qemu.stdout], [], [], 0.1)[0]:
                        actual.extend(os.read(qemu.stdout.fileno(), 16 - len(actual)))
                self.assertEqual(bytes(actual), b"\x01" * 16)
            finally:
                qemu.terminate()
                qemu.wait(timeout=2)
                qemu.stdout.close()
                qemu.stderr.close()
