"""Read-only issuer credential format inventory; never prints IDs or hashes."""
import argparse
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path


def inspect(path: Path) -> dict:
    counts = {"salt_32_bytes": 0, "legacy_salt_16_bytes": 0, "legacy_unsalted": 0, "invalid": 0}
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as database:
        for (value,) in database.execute("SELECT issuer_token_hash FROM institutions"):
            if re.fullmatch(r"sha256\$[0-9a-f]{64}\$[0-9a-f]{64}", value):
                label = "salt_32_bytes"
            elif re.fullmatch(r"sha256\$[0-9a-f]{32}\$[0-9a-f]{64}", value):
                label = "legacy_salt_16_bytes"
            elif re.fullmatch(r"[0-9a-f]{64}", value):
                label = "legacy_unsalted"
            else:
                label = "invalid"
            counts[label] += 1
    return {"read_only": True, "counts": counts,
            "production_compatible": not any(counts[key] for key in ("legacy_salt_16_bytes", "legacy_unsalted", "invalid"))}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    print(json.dumps(inspect(parser.parse_args().database), indent=2))
