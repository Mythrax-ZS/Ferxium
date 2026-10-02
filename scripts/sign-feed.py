"""Offline Ed25519 feed tool. Install cryptography on the isolated signer.

The service signs/verifies exact payload bytes. Never publish the private key.
"""
import argparse
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("keygen")
    generate.add_argument("--private", type=Path, required=True)
    sign = commands.add_parser("sign")
    sign.add_argument("--private", type=Path, required=True)
    sign.add_argument("--database", type=Path, required=True)
    sign.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "keygen":
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        descriptor = os.open(args.private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as file:
            file.write(pem)
            file.flush()
            os.fsync(file.fileno())
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        print("Trusted public key (hex):", public.hex())
        print("Private key created exclusively. On Windows, verify its directory ACL before use.")
    else:
        key = serialization.load_pem_private_key(args.private.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            parser.error("The key must be an Ed25519 private key")
        payload = args.database.read_bytes()
        if len(payload) > 4 * 1024 * 1024:
            parser.error("Database exceeds the service's 4 MiB limit")
        database = json.loads(payload)
        if not isinstance(database.get("version"), int) or database["version"] <= 0:
            parser.error("Positive database version required")
        envelope = {"payload": payload.decode("utf-8"), "signature": key.sign(payload).hex()}
        with args.output.open("x", encoding="utf-8", newline="\n") as file:
            json.dump(envelope, file, ensure_ascii=False, indent=2)
            file.write("\n")
        print("Signed envelope written:", args.output)


if __name__ == "__main__":
    main()
