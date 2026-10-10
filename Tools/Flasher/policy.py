"""Package validation and version/write policy shared by GUI and CLI."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    from ..image_format import load_verifier, parse_package
except ImportError:
    from image_format import load_verifier, parse_package


def version_tuple(header):
    return header.sw_major, header.sw_minor, header.sw_revision, header.build


def verified_package(path, trusted_key):
    verifier = load_verifier(trusted_key)
    if not isinstance(verifier, Ed25519PublicKey):
        raise ValueError("trusted key is not an Ed25519 public key")
    return parse_package(path.read_bytes(), verifier)


def flash_block_reason(header, device_header, info, force=False):
    if info is None:
        return "Current bootloader information is required"
    if device_header is not None and header.hw_id != device_header.hw_id:
        return "Hardware ID does not match the device"
    if not info.application_writable:
        return "BLB0 blocks application writes"
    if not info.application_readable:
        return "BLB0 blocks the full-image CMAC read"
    if device_header is not None and version_tuple(header) <= version_tuple(device_header) and not force:
        return "Same or older version is locked; select Force to override"
    return None
