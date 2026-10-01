"""Emit a C initializer into an untracked build directory."""

from pathlib import Path
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("key", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
key = bytes.fromhex(args.key.read_text().strip())
if len(key) != 16:
    raise SystemExit("device key must be exactly 16 bytes")
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text("#define DEVICE_KEY_BYTES " + ", ".join(f"0x{b:02x}" for b in key) + "\n")
