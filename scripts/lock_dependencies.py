"""Regenerate artifact hashes for already reviewed, exactly pinned PyPI versions.

Run deliberately when updating dependencies, never as part of a normal build.
The index JSON is fetched over verified HTTPS; normal installation uses hashes.
"""

from concurrent.futures import ThreadPoolExecutor
from importlib import metadata
from pathlib import Path
import re

import requests
from packaging.requirements import Requirement


ROOT = Path(__file__).resolve().parents[1]


def runtime_packages() -> set[str]:
    found: set[str] = set()
    pending = [Requirement(name) for name in ("fastapi", "uvicorn", "cryptography", "qrcode[pil]")]
    visited: set[tuple[str, tuple[str, ...]]] = set()
    while pending:
        requirement = pending.pop()
        name = re.sub(r"[-_.]+", "-", requirement.name).lower()
        entry = (name, tuple(sorted(requirement.extras)))
        if entry in visited:
            continue
        visited.add(entry)
        found.add(name)
        for value in metadata.requires(requirement.name) or []:
            dependency = Requirement(value)
            if dependency.marker is None or any(dependency.marker.evaluate({"extra": extra}) for extra in ("", *requirement.extras)):
                pending.append(dependency)
    return found


def main() -> None:
    lock = ROOT / "requirements-dev.lock"
    pins = re.findall(r"^([\w.-]+)==([\w.+-]+)", lock.read_text(encoding="utf-8"), re.MULTILINE)

    def hashes(pin: tuple[str, str]) -> tuple[str, str]:
        name, version = pin
        response = requests.get(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30)
        response.raise_for_status()
        values = sorted({item["digests"]["sha256"] for item in response.json()["urls"] if not item.get("yanked")})
        if not values:
            raise ValueError(f"No verified distribution hashes: {name}=={version}")
        lines = [f"{name}=={version} \\"]
        lines.extend(f"    --hash=sha256:{value}" + (" \\" if i < len(values) - 1 else "") for i, value in enumerate(values))
        return re.sub(r"[-_.]+", "-", name).lower(), "\n".join(lines)

    with ThreadPoolExecutor(max_workers=8) as pool:
        entries = list(pool.map(hashes, pins))
    header = "# Exact versions and PyPI distribution SHA-256 hashes.\n"
    lock.write_text(header + "\n".join(value for _, value in entries) + "\n", encoding="utf-8")
    runtime = runtime_packages()
    missing = runtime - {name for name, _ in entries}
    if missing:
        raise ValueError(f"Runtime dependencies missing from reviewed lock: {sorted(missing)}")
    (ROOT / "requirements-runtime.lock").write_text(
        header + "\n".join(value for name, value in entries if name in runtime) + "\n", encoding="utf-8",
    )
    print(f"Pinned {len(entries)} development packages; {len(runtime)} runtime packages")


if __name__ == "__main__":
    main()
