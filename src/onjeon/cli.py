"""Local key creation. Only the public key is printed."""

import argparse
from pathlib import Path

from .crypto import create_private_key


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an Ed25519 institution signing key")
    parser.add_argument("institution_id")
    parser.add_argument("key_version")
    parser.add_argument("--key-directory", default=".secrets")
    args = parser.parse_args()
    from .api import ID_RE, KEY_RE
    import re
    if not re.fullmatch(ID_RE, args.institution_id) or not re.fullmatch(KEY_RE, args.key_version):
        parser.error("Invalid institution ID or key version")
    path = Path(args.key_directory) / args.institution_id / f"{args.key_version}.pem"
    public_key = create_private_key(path)
    print(f"Private key written to: {path}")
    print(f"Public key: {public_key}")


if __name__ == "__main__":
    main()
