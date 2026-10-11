"""Build a source ZIP from an explicit allowlist; never include runtime secrets."""

import hashlib
import io
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "submission" / "OE-1_onjeon_source.zip"
FILES = [
    ROOT / name for name in (
        ".gitignore", ".dockerignore", "Dockerfile", "compose.yaml", "compose.security.yaml", "compose.production.yaml",
        "README.md", "pyproject.toml", "requirements-dev.lock", "requirements-runtime.lock",
        ".github/workflows/ci.yml", "frontend/index.html", "frontend/package.json",
        "frontend/package-lock.json", "frontend/tsconfig.json", "frontend/vite.config.ts", "frontend/vitest.config.ts",
        "submission/README.md", "submission/SECURITY.md", "submission/TEST_REPORT.md",
        "submission/CLAUDE_REVIEW.md",
        "submission/SECURITY_CHECKLIST_49.md", "submission/GUIDE_SECURITY_REVIEW.md",
        "submission/GUIDE_SOURCES.json", "submission/SBOM.python.cdx.json",
        "submission/SBOM.frontend.cdx.json", "submission/PRODUCT_EVALUATION.json",
        "submission/PRODUCT_EVALUATION.md",
    )
]
for pattern in (
    "src/onjeon/*.py", "tests/*.py", "scripts/*.py", "scripts/*.yaml", "frontend/src/**/*",
    "deploy/*",
    "frontend/public/*", "frontend/dist/**/*",
    "submission/screenshots/*.jpg",
    "submission/screenshots/*.png", "submission/schemas/**/*",
    "submission/FULL_GUIDE_*.md", "submission/licenses/**/*",
    "submission/THIRD_PARTY_NOTICES.md", "submission/SUPPLY_CHAIN_VALIDATION.*",
    "submission/OPERATION_SECURITY.md", "submission/RECOVERY_CHECK.md",
    "submission/DAST_CHECK.md",
    "submission/EVALUATION_READINESS.md",
    "submission/SBOM.*.json",
    "submission/SECURITY_CONDITIONS_*.md", "submission/SECURITY_CONDITIONS_*.json",
    "submission/DOCKER_RUNTIME_CHECK.*", "submission/DOCKER_BACKUP_CHECK.json",
    "submission/RELEASE_VERIFICATION.md",
    "submission/DOCKER_IMAGE_SCAN.md", "submission/DOCKER_IMAGE_SCAN.json",
    "submission/CLAUDE_OPUS_SECURITY_REVIEW_*.md", "submission/CLAUDE_OPUS_SECURITY_REVIEW_*.json",
    "submission/CLAUDE_OPUS_REMEDIATION_*.md", "submission/CLAUDE_OPUS_REMEDIATION_*.json",
    "submission/BACKUP_CUSTODY.md", "submission/CRL_OPERATIONS.md", "submission/RELEASE_OPERATIONS.md",
    "submission/PUBLIC_*_CHECK.json", "submission/MYBOX_BACKUP_CHECK.json", "submission/OPERATIONS_COMPLETION_*.md",
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
