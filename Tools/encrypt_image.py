"""Package an application HEX as signed, page-authenticated AES-128 firmware."""

import argparse
from pathlib import Path
from intelhex import IntelHex
from image_format import BOOT_START, build_package, load_device_key, load_signer, prepare_image


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True, type=Path)
    parser.add_argument("--device-key", required=True, type=Path)
    parser.add_argument("--signing-key", required=True, type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    source = IntelHex(str(args.file))
    if source.minaddr() != 0 or source.maxaddr() >= BOOT_START:
        raise SystemExit("HEX image must start at zero and end before bootloader")
    source.padding = 0xff
    plain = bytes(source.tobinarray(start=0, end=source.maxaddr()))
    key = load_device_key(args.device_key)
    image, header = prepare_image(plain, key)
    package = build_package(image, header, key, load_signer(args.signing_key))
    output = args.output or args.file.with_name(args.file.stem + "_encrypted.bin")
    output.write_bytes(package)
    print(f"{output}: {header.version}, {header.image_size} bytes, {len(package)} byte package")


if __name__ == "__main__":
    main()
