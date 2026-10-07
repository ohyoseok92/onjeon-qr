"""Verify archive manifest and absence of runtime/personal files."""

import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "submission" / "OE-1_onjeon_source.zip"
FORBIDDEN = {".secrets", ".env", "data", "node_modules", ".venv", "demo-output"}


def main() -> None:
    with zipfile.ZipFile(ARCHIVE) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or "MANIFEST.sha256" not in names:
            raise SystemExit("Duplicate files or missing manifest")
        for name in names:
            path = Path(name)
            if name.startswith("/") or ".." in path.parts or FORBIDDEN.intersection(path.parts):
                raise SystemExit(f"Forbidden archive path: {name}")
            if path.suffix.lower() in {".pem", ".sqlite3", ".pdf", ".docx"}:
                raise SystemExit(f"Forbidden archive file: {name}")
        lines = archive.read("MANIFEST.sha256").decode("utf-8").splitlines()
        checked = set()
        for line in lines:
            expected, name = line.split("  ", 1)
            if name not in names or hashlib.sha256(archive.read(name)).hexdigest() != expected:
                raise SystemExit(f"Hash mismatch: {name}")
            checked.add(name)
        if checked != set(names) - {"MANIFEST.sha256"}:
            raise SystemExit("Manifest does not cover every file")
    print(f"Verified {len(checked)} files: {ARCHIVE}")


if __name__ == "__main__":
    main()
