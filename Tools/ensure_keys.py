"""Create local development keys. Production keys must be provisioned separately."""

from pathlib import Path
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def ensure_keys(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    device = directory / "device_key.hex"
    private = directory / "signing_private.pem"
    public = directory / "signing_public.pem"
    if not device.exists():
        device.write_text(os.urandom(16).hex() + "\n")
        device.chmod(0o600)
        print(f"Generated DEVELOPMENT device key: {device}")
    if not private.exists():
        key = Ed25519PrivateKey.generate()
        private.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        private.chmod(0o600)
        public.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        print(f"Generated DEVELOPMENT signing key: {private}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    ensure_keys(parser.parse_args().directory)
