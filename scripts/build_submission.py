"""Build a source ZIP from an explicit allowlist; never include runtime secrets."""

import hashlib
import io
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "submission" / "OE-1_onjeon_source.zip"
FILES = [
    ROOT / name for name in (
        ".gitignore", "README.md", "pyproject.toml", "requirements-dev.lock",
        ".github/workflows/ci.yml", "frontend/index.html", "frontend/package.json",
        "frontend/package-lock.json", "frontend/tsconfig.json", "frontend/vite.config.ts",
        "submission/README.md", "submission/SECURITY.md", "submission/TEST_REPORT.md",
        "submission/CLAUDE_REVIEW.md",
    )
]
for pattern in (
    "src/onjeon/*.py", "tests/*.py", "scripts/*.py", "frontend/src/*",
    "frontend/public/*", "frontend/dist/**/*",
):
    FILES.extend(ROOT.glob(pattern))


def main() -> None:
    files = sorted({path for path in FILES if path.is_file()})
    missing = [path for path in FILES if not path.exists()]
    if missing:
        raise SystemExit("Required submission file missing: " + ", ".join(str(path) for path in missing))
    hashes = []
    payload = io.BytesIO()
    def add(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
        info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        archive.writestr(info, data, compresslevel=9)

    with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = path.relative_to(ROOT).as_posix()
            data = path.read_bytes()
            add(archive, relative, data)
            hashes.append(f"{hashlib.sha256(data).hexdigest()}  {relative}")
        add(archive, "MANIFEST.sha256", ("\n".join(hashes) + "\n").encode("utf-8"))
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_bytes(payload.getvalue())
    print(f"ZIP: {OUTPUT}")
    print(f"Files: {len(files) + 1}")
    print(f"SHA-256: {hashlib.sha256(payload.getvalue()).hexdigest()}")


if __name__ == "__main__":
    main()
