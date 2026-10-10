from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import io
from itertools import product
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from Tools.Flasher import cli
from Tools.Flasher.policy import flash_block_reason
from Tools.Flasher.protocol import (CMD_ACK, CMD_BEGIN, CMD_FINISH, CMD_HEADER, CMD_INFO,
                                    CMD_LOCK, CMD_NACK, CMD_PAGE, CMD_RESET, CONTROL_SEQ,
                                    DeviceInfo, INFO_FORMAT, encode_serial, NACK_AUTH, NACK_PACKET,
                                    Parser, encode, lock_mode_mask)
from Tools.image_format import (HEADER_FORMAT, HEADER_OFFSET, HEADER_SIZE, IMAGE_MAGIC,
                                HW_ID, build_package, prepare_image)


class DevicePort:
    def __init__(self, header, locks=0xff, app=False):
        self.header = header
        self.locks = locks
        self.rx = bytearray()
        self.writes = []
        self.programmed = []
        self.lose_page_ack = False
        self.lose_finish_ack = False
        self.lose_lock_ack = False
        self.packet_nack = False
        self.auth_nack = False
        self.respond = True
        self.bad_lock_readback = False
        self.closed = False
        if not app:
            self.status()

    def info(self):
        return struct.pack(INFO_FORMAT, 1, 1, 0, 1, b"Oct  9 2026", b"12:34:56",
                           encode_serial("SN-001"), 0xff, 0xd8, 0xfd, self.locks)

    def status(self):
        self.rx.extend(encode(CMD_HEADER, self.header.to_bytes() if self.header else b"\0" * HEADER_SIZE))
        self.rx.extend(encode(CMD_INFO, self.info()))

    @property
    def in_waiting(self):
        return min(11, len(self.rx))

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
            self.status()
            return len(data)
        packet, = Parser().feed(data)
        cmd = packet.command
        if cmd == CMD_INFO:
            self.rx.extend(encode(CMD_INFO, self.info()))
            return len(data)
        if cmd == CMD_RESET:
            return len(data)
        if cmd == CMD_BEGIN:
            seq = 0xffff
        elif cmd == CMD_PAGE:
            seq = int.from_bytes(packet.payload[:2], "little")
            if self.auth_nack:
                self.rx.extend(encode(CMD_NACK, seq.to_bytes(2, "little") + bytes((NACK_AUTH,))))
                return len(data)
            if self.packet_nack:
                self.packet_nack = False
                self.rx.extend(encode(CMD_NACK, b"\xff\xff" + bytes((NACK_PACKET,))))
                return len(data)
            if seq not in self.programmed:
                self.programmed.append(seq)
            if self.lose_page_ack:
                self.lose_page_ack = False
                return len(data)
            # A stale previous ACK must not advance the ordered transfer.
            if seq:
                self.rx.extend(encode(CMD_ACK, (seq - 1).to_bytes(2, "little")))
        elif cmd == CMD_FINISH:
            seq = int.from_bytes(packet.payload, "little")
            if self.lose_finish_ack:
                self.lose_finish_ack = False
                return len(data)
        elif cmd == CMD_LOCK:
            seq = CONTROL_SEQ
            if not self.bad_lock_readback:
                self.locks &= ~packet.payload[0]
            if self.lose_lock_ack:
                self.lose_lock_ack = False
                return len(data)
        else:
            raise AssertionError(cmd)
        self.rx.extend(encode(CMD_ACK, seq.to_bytes(2, "little")))
        return len(data)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True


class LockModeTests(unittest.TestCase):
    def test_all_physical_lock_bit_combinations(self):
        for locks in range(256):
            with self.subTest(locks=locks):
                info = DeviceInfo(1, 1, 0, 1, b"", b"", bytes(16), 0xff, 0xd8, 0xfd, locks)
                bits_to_mode = {0b11: 1, 0b10: 2, 0b00: 3, 0b01: 4}
                self.assertEqual(info.blb0_mode, bits_to_mode[(locks >> 2) & 3])
                self.assertEqual(info.blb1_mode, bits_to_mode[(locks >> 4) & 3])
                self.assertEqual(info.lb_mode, {0b11: 1, 0b10: 2, 0b00: 3}.get(locks & 3))
                self.assertEqual(info.application_writable, bool(locks & 4))
                self.assertEqual(info.application_readable, bool(locks & 8))
                self.assertEqual(info.boot_writable, bool(locks & 16))
                self.assertEqual(info.boot_readable_from_app, bool(locks & 32))

    def test_lb_masks_and_impossible_mode_restoration(self):
        info = DeviceInfo(1, 1, 0, 1, b"", b"", bytes(16), 0xff, 0xd8, 0xfd, 0xff)
        self.assertEqual(lock_mode_mask(info), 0)
        self.assertEqual(lock_mode_mask(info, 1), 0)
        self.assertEqual(lock_mode_mask(info, 2), 1)
        self.assertEqual(lock_mode_mask(info, 3), 3)
        self.assertEqual(lock_mode_mask(replace(info, lock_bits=0xfe), 3), 2)
        self.assertEqual(lock_mode_mask(replace(info, lock_bits=0xfc), 3), 0)
        for locks, target in ((0xfe, 1), (0xfc, 1), (0xfc, 2), (0xfd, 2)):
            with self.subTest(locks=locks, target=target), self.assertRaisesRegex(ValueError, "chip erase"):
                lock_mode_mask(replace(info, lock_bits=locks), target)

    def test_every_lb_target_preserves_all_blb_bits(self):
        pairs = {1: 3, 2: 2, 3: 0}
        info = DeviceInfo(1, 1, 0, 1, b"", b"", bytes(16), 0xff, 0xd8, 0xfd, 0xff)
        for locks, mode in product(range(256), range(1, 4)):
            current = replace(info, lock_bits=locks)
            target = (locks & ~3) | pairs[mode]
            with self.subTest(locks=locks, mode=mode):
                if target & ~locks:
                    with self.assertRaises(ValueError):
                        lock_mode_mask(current, mode)
                else:
                    mask = lock_mode_mask(current, mode)
                    self.assertEqual(mask & ~3, 0)
                    self.assertEqual(current.lock_bits & ~mask, target)

    def test_invalid_targets_and_reserved_lb_repair(self):
        info = DeviceInfo(1, 1, 0, 1, b"", b"", bytes(16), 0xff, 0xd8, 0xfd, 0xfd)
        self.assertEqual(lock_mode_mask(info, lb_mode=3), 1)
        for target in (0, 4, 5):
            with self.assertRaisesRegex(ValueError, "invalid"):
                lock_mode_mask(info, target)

class FlasherCliTests(unittest.TestCase):
    def setUp(self):
        raw = bytearray(b"\xff" * 400)
        raw[HEADER_OFFSET:HEADER_OFFSET + HEADER_SIZE] = struct.pack(
            HEADER_FORMAT, IMAGE_MAGIC, HW_ID, 1, 2, 3, 5, b"Oct  9 2026", b"12:34:56",
            b"5.4.0", 0, bytes(12), bytes(16))
        self.root = bytes(range(16))
        self.image, self.header = prepare_image(bytes(raw), self.root, b"0123456789ab")
        self.signer = Ed25519PrivateKey.generate()
        self.package = build_package(self.image, self.header, self.root, self.signer)
        self.pages = [(b"x" * 128, b"t" * 16)] * (len(self.image) // 128)

    def client(self, **kwargs):
        port = DevicePort(None, **kwargs)
        client = cli.FlasherClient(port, 0.01)
        client.connect()
        return client, port

    def test_auto_bootloader_and_sequenced_flash_retry(self):
        client, port = self.client(app=True)
        port.lose_page_ack = True
        client.flash(self.header, self.pages)
        self.assertEqual(port.writes[0], b"BOOT\n")
        self.assertEqual(port.programmed, list(range(len(self.pages))))
        frames = [Parser().feed(raw)[0] for raw in port.writes if raw != b"BOOT\n"]
        self.assertEqual(frames[0].command, CMD_BEGIN)
        self.assertEqual(frames[1], frames[2])
        self.assertEqual(frames[-1].command, CMD_FINISH)
        self.assertEqual(client.device_header, self.header)

    def test_packet_nack_retries_auth_nack_stops(self):
        client, port = self.client()
        port.packet_nack = True
        client.flash(self.header, self.pages)
        self.assertEqual(len(port.programmed), len(self.pages))
        client, port = self.client()
        port.auth_nack = True
        with self.assertRaisesRegex(cli.FlasherError, "authentication"):
            client.flash(self.header, self.pages, force=True)
        self.assertFalse(any(raw[1] == CMD_FINISH for raw in port.writes))

    def test_force_only_overrides_version_and_isp_locks_do_not_block_spm(self):
        client, port = self.client()
        client.device_header = self.header
        with self.assertRaisesRegex(cli.FlasherError, "older"):
            client.flash(self.header, self.pages)
        self.assertEqual(port.writes, [])
        client.flash(self.header, self.pages, force=True)
        for locks in (0xfb, 0xf7):
            client, port = self.client(locks=locks)
            with self.assertRaises(cli.FlasherError):
                client.flash(self.header, self.pages, force=True)
            self.assertEqual(port.writes, [])
        client, port = self.client(locks=0xfc)
        client.flash(self.header, self.pages)
        self.assertEqual(port.programmed, list(range(len(self.pages))))
        wrong_hw = replace(self.header, hw_id=0x9999)
        self.assertIsNotNone(flash_block_reason(wrong_hw, self.header, client.device_info, True))

    def test_application_request_does_not_wait_for_output(self):
        client, port = self.client()
        client.application()
        self.assertEqual(port.writes[-1], encode(CMD_RESET))
        self.assertEqual(client.mode, "unknown")
        self.assertIsNone(client.device_info)
        self.assertIsNone(client.device_header)
        port = DevicePort(None, app=True)  # silent arbitrary application
        output = io.StringIO()
        with patch("Tools.Flasher.cli.serial.Serial", return_value=port), redirect_stdout(output):
            self.assertEqual(cli.main(["application", "--port", "COM5"]), 0)
        self.assertEqual(port.writes, [encode(CMD_RESET)])
        self.assertIn('"application_start": "requested"', output.getvalue())
        self.assertIn('"confirmed": false', output.getvalue())
        self.assertTrue(port.closed)

    def test_request_timeout_and_lock_readback_failure(self):
        client, port = self.client()
        port.respond = False
        with self.assertRaisesRegex(cli.FlasherError, "5 attempts"):
            client.request(CMD_INFO)
        client, port = self.client()
        port.bad_lock_readback = True
        with self.assertRaisesRegex(cli.FlasherError, "readback"):
            client.lock(lb_mode=2)

    def test_finish_retry_is_identical(self):
        client, port = self.client()
        port.lose_finish_ack = True
        count = len(self.pages)
        client.request(CMD_FINISH, count.to_bytes(2, "little"), count, timeout=0.005)
        self.assertEqual(len(port.writes), 2)
        self.assertEqual(port.writes[0], port.writes[1])

    def test_main_closes_port_on_transfer_error(self):
        with tempfile.TemporaryDirectory() as directory:
            package_path, key_path = self.files(directory)
            port = DevicePort(None)
            port.auth_nack = True
            with patch("Tools.Flasher.cli.serial.Serial", return_value=port), redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["flash", "--port", "COM5", "--file", str(package_path), "--key", str(key_path)]), 1)
            self.assertTrue(port.closed)

    def test_lb_programming_preserves_existing_blb_protection(self):
        client, port = self.client(locks=0xeb)
        info = client.lock(lb_mode=3)
        self.assertEqual(info.blb0_mode, 2)
        self.assertEqual(info.blb1_mode, 2)
        self.assertEqual(info.lb_mode, 3)
        self.assertIn(encode(CMD_LOCK, b"\x03"), port.writes)
        self.assertEqual(port.locks, 0xe8)

    def test_lb_readback_retry_and_impossible_unlock(self):
        client, port = self.client()
        port.lose_lock_ack = True
        info = client.lock(lb_mode=2)
        self.assertEqual((info.blb0_mode, info.blb1_mode, info.lb_mode), (1, 1, 2))
        self.assertEqual(port.writes.count(encode(CMD_LOCK, b"\x01")), 2)
        count = len(port.writes)
        self.assertEqual(client.lock(2), info)
        self.assertEqual(len(port.writes), count)
        with self.assertRaisesRegex(ValueError, "chip erase"):
            client.lock(lb_mode=1)
        self.assertEqual(len(port.writes), count)
        info = client.lock(lb_mode=3)
        self.assertEqual((info.blb0_mode, info.blb1_mode, info.lb_mode), (1, 1, 3))
        self.assertIn(encode(CMD_LOCK, b"\x02"), port.writes)

    def test_lock_readback_checks_preserved_bits_too(self):
        client, port = self.client()
        original_write = port.write
        def extra_lock(data):
            result = original_write(data)
            if Parser().feed(data)[0].command == CMD_LOCK:
                port.locks &= ~0x20  # unrequested App-to-boot read lock
            return result
        port.write = extra_lock
        with self.assertRaisesRegex(cli.FlasherError, "readback"):
            client.lock(lb_mode=2)
        self.assertIsNone(client.device_info)

    def test_cli_accepts_lb_and_rejects_blb_or_reserved_mode_before_open(self):
        port = DevicePort(None)
        with patch("Tools.Flasher.cli.serial.Serial", return_value=port), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["lock", "--port", "COM5", "--lb-mode", "3", "--yes"]), 0)
        self.assertEqual(port.locks, 0xfc)
        for options in (["--lb-mode", "4"], ["--lb-mode", "2", "--blb0-mode", "2"],
                        ["--lb-mode", "2", "--blb1-mode", "3"]):
            with self.subTest(options=options):
                with patch("Tools.Flasher.cli.serial.Serial") as factory, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    cli.main(["lock", "--port", "COM5", *options, "--yes"])
                factory.assert_not_called()

    def test_info_serial_is_a_string_without_padding_or_hex(self):
        client, port = self.client()
        summary = cli.device_summary(client)
        self.assertEqual(summary["serial"], "SN-001")
        self.assertTrue(summary["serial_valid"])
        self.assertTrue(summary["serial_provisioned"])
        client.device_info = replace(client.device_info, serial=b"a" * 16)
        summary = cli.device_summary(client)
        self.assertIsNone(summary["serial"])
        self.assertFalse(summary["serial_valid"])

    def files(self, directory):
        package_path, key_path = Path(directory) / "image.bin", Path(directory) / "trusted.pem"
        package_path.write_bytes(self.package)
        key_path.write_bytes(self.signer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        return package_path, key_path

    def test_main_verifies_before_opening_port_and_closes_on_success(self):
        with tempfile.TemporaryDirectory() as directory:
            package_path, key_path = self.files(directory)
            port = DevicePort(None)
            output = io.StringIO()
            with patch("Tools.Flasher.cli.serial.Serial", return_value=port), redirect_stdout(output), redirect_stderr(io.StringIO()):
                rc = cli.main(["flash", "--port", "COM5", "--file", str(package_path), "--key", str(key_path)])
            self.assertEqual(rc, 0)
            self.assertTrue(port.closed)
            self.assertIn('"firmware": "verified"', output.getvalue())
            package_path.write_bytes(self.package[:-1] + bytes((self.package[-1] ^ 1,)))
            with patch("Tools.Flasher.cli.serial.Serial") as factory, redirect_stderr(io.StringIO()):
                rc = cli.main(["flash", "--port", "COM5", "--file", str(package_path), "--key", str(key_path), "--force"])
            self.assertEqual(rc, 1)
            factory.assert_not_called()

    def test_offline_verify_and_lock_confirmation_do_not_open_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            package_path, key_path = self.files(directory)
            with patch("Tools.Flasher.cli.serial.Serial") as factory, redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["verify", "--file", str(package_path), "--key", str(key_path)]), 0)
                factory.assert_not_called()
        with patch("Tools.Flasher.cli.serial.Serial") as factory, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["lock", "--port", "COM5", "--lb-mode", "2"])
        factory.assert_not_called()

    def test_main_cli_does_not_import_qt(self):
        code = '''
import builtins, runpy, sys
original = builtins.__import__
def no_qt(name, *args, **kwargs):
    if name.startswith("PyQt5"):
        raise AssertionError("Qt imported by CLI")
    return original(name, *args, **kwargs)
builtins.__import__ = no_qt
sys.argv = ["main.py", "ports"]
runpy.run_module("Tools.Flasher.main", run_name="__main__")
'''
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
