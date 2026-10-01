"""Test-only package verifier and plaintext extractor."""

import argparse
from pathlib import Path
from image_format import load_device_key, load_verifier, verify_and_decrypt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True, type=Path)
    parser.add_argument("--device-key", required=True, type=Path)
    parser.add_argument("--verify-key", required=True, type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    image = verify_and_decrypt(args.file.read_bytes(), load_verifier(args.verify_key),
                               load_device_key(args.device_key))
    output = args.output or args.file.with_suffix(".plain.bin")
    output.write_bytes(image)
    print(f"{output}: {len(image)} verified bytes")


if __name__ == "__main__":
    main()
