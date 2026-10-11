"""Inventory installed production dependencies and preserve their declared notices.

No registry requests: Python metadata, exact lock files and npm's installed tree
are the evidence. Lock wheel/sdist candidate hashes are NOT installed-file hashes.
"""
from __future__ import annotations

import hashlib
import importlib.metadata as metadata
import json
import re
import shutil
import subprocess
import tomllib
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from packaging.requirements import Requirement
from packaging.markers import default_environment
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "submission"
AUTHOR = {"name": "scripts/generate_supply_chain.py (automated inventory author)"}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def prop(name: str, value: object) -> dict:
    return {"name": f"onjeon:{name}", "value": str(value)}


def parse_lock() -> dict[str, tuple[str, list[str]]]:
    text = (ROOT / "requirements-runtime.lock").read_text(encoding="utf-8")
    blocks = re.split(r"(?=^[\w.-]+==)", text, flags=re.MULTILINE)[1:]
    result = {}
    for block in blocks:
        pin = re.match(r"([\w.-]+)==([\w.+-]+)", block)
        if not pin:
            raise ValueError("Invalid exact version entry in requirements-runtime.lock")
        name, version = pin.groups()
        result[canonicalize_name(name)] = (version, re.findall(r"--hash=sha256:([0-9a-f]{64})", block))
    return result


def is_notice(path: Path) -> bool:
    # Includes bundled third-party text shipped in licenses/ directories.
    return any(part.lower() in {"license", "licenses"} for part in path.parts) or bool(
        re.match(r"^(licen[cs]e|notice|copying|copyright)(?:[._-].*)?$", path.name, re.I)
    )


def copy_notice(source: Path, destination: Path) -> dict:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    return {"path": destination.relative_to(OUTPUT).as_posix(),
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(), "bytes": destination.stat().st_size}


def graph_errors(bom: dict) -> dict:
    refs = [bom["metadata"]["component"]["bom-ref"], *(c["bom-ref"] for c in bom["components"])]
    known = set(refs)
    dangling = sorted({ref for d in bom["dependencies"] for ref in [d["ref"], *d.get("dependsOn", [])] if ref not in known})
    nodes = {d["ref"] for d in bom["dependencies"]}
    reached, pending = set(), [refs[0]]
    graph = {d["ref"]: d.get("dependsOn", []) for d in bom["dependencies"]}
    while pending:
        ref = pending.pop()
        if ref not in reached:
            reached.add(ref)
            pending.extend(graph.get(ref, []))
    return {"dangling_refs": dangling, "missing_dependency_nodes": sorted(known - nodes),
            "unreachable_components": sorted(known - reached), "duplicate_refs": sorted({r for r in refs if refs.count(r) > 1}),
            "edge_count": sum(len(d.get("dependsOn", [])) for d in bom["dependencies"])}


def python_inventory(timestamp: str, *, marker_environment: dict[str, str] | None = None) -> tuple[dict, list[dict], dict]:
    pins = parse_lock()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    root_ref = f"pkg:pypi/{project['name']}@{project['version']}"
    refs = {name: f"pkg:pypi/{name}@{version}" for name, (version, _) in pins.items()}
    environment = {**default_environment(), **(marker_environment or {})}
    dists = {}
    mismatches = []
    edges = {root_ref: set()}
    queue = deque((root_ref, Requirement(value)) for value in project["dependencies"])
    seen = set()
    reached = set()
    while queue:
        parent, req = queue.popleft()
        name = canonicalize_name(req.name)
        if name not in pins:
            raise ValueError(f"Runtime dependency absent from lock: {req}")
        if name not in dists:
            dists[name] = metadata.distribution(name)
            if dists[name].version != pins[name][0]:
                raise ValueError(f"Python installed versions differ: {name}: lock={pins[name][0]}, installed={dists[name].version}")
        edges.setdefault(refs[name], set())
        if not req.specifier.contains(dists[name].version):
            raise ValueError(f"Installed dependency fails declared constraint: {req}")
        edges[parent].add(refs[name])
        reached.add(name)
        context = (name, tuple(sorted(req.extras)))
        if context in seen:
            continue
        seen.add(context)
        for raw in dists[name].requires or []:
            dependency = Requirement(raw)
            if dependency.marker is None or any(dependency.marker.evaluate({**environment, "extra": extra}) for extra in ("", *req.extras)):
                queue.append((refs[name], dependency))
    inactive = [{"name": name, "version": pins[name][0]} for name in sorted(set(pins) - reached)]
    components, notices = [], []
    for name in sorted(reached):
        dist = dists[name]
        declared_supplier = dist.metadata.get("Supplier")
        expression = dist.metadata.get("License-Expression")
        license_classifiers = [item for item in dist.metadata.get_all("Classifier", []) if item.startswith("License ::")]
        license_label = expression or dist.metadata.get("License") or "; ".join(license_classifiers) or "unknown (not declared)"
        files = []
        for relative in sorted(dist.files or [], key=str):
            if is_notice(Path(str(relative))):
                source = Path(dist.locate_file(relative))
                if source.is_file():
                    files.append(copy_notice(source, OUTPUT / "licenses" / "python" / f"{name}-{dist.version}" / str(relative)))
        component = {"type": "library", "bom-ref": refs[name], "name": name, "version": dist.version,
                     "purl": refs[name], "supplier": {"name": declared_supplier or "unknown (supplier not declared in installed metadata)"},
                     "licenses": [{"expression": expression}] if expression else [{"license": {"name": license_label}}],
                     "properties": [prop("metadata-source", "installed dist-info/METADATA"),
                                    prop("supplier-evidence", "Supplier field" if declared_supplier else "No Supplier field; Author/Maintainer are not treated as supplier"),
                                    prop("declared-author", dist.metadata.get("Author-email") or dist.metadata.get("Author") or "unknown"),
                                    prop("lock-distribution-sha256-candidates", json.dumps(pins[name][1])),
                                    prop("artifact-hash-status", "Installed wheel/sdist archive unavailable: exact installed archive hash omitted. No RECORD aggregate hash represented as a wheel hash.") ]}
        components.append(component)
        notices.append({"ecosystem": "python", "name": name, "version": dist.version,
                        "declared_license": license_label, "files": files})
    bom = {"$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json", "bomFormat": "CycloneDX", "specVersion": "1.5",
           "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
           "metadata": {"timestamp": timestamp, "authors": [AUTHOR],
                        "tools": [{"name": "generate_supply_chain.py", "version": "1"}],
                        "component": {"type": "application", "bom-ref": root_ref, "name": project["name"], "version": project["version"], "purl": root_ref}},
           "components": components, "dependencies": [{"ref": ref, "dependsOn": sorted(children)} for ref, children in sorted(edges.items())]}
    validation = {"component_count": len(components), "lock_count": len(pins), "installed_version_mismatches": mismatches,
                  "dependency_environment": environment,
                  "declared_extras": ["qrcode[pil]"],
                  "inactive_locked_packages": inactive,
                  "inactive_semantics": "Locked packages not reached from production roots after current-platform marker/extra evaluation; excluded from this platform's active SBOM, not missing active dependencies.",
                  **graph_errors(bom)}
    return bom, notices, validation


def frontend_inventory(timestamp: str) -> tuple[dict, list[dict], dict]:
    # npm's generator traverses the real installed production tree offline.
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    if not npm:
        raise ValueError("npm executable missing")
    completed = subprocess.run([npm, "sbom", "--sbom-format", "cyclonedx", "--omit", "dev"],
                               cwd=ROOT / "frontend", capture_output=True, text=True, encoding="utf-8", check=True)
    raw_production = json.loads(completed.stdout)
    write_json(OUTPUT / "SBOM.frontend.npm-production.raw.cdx.json", raw_production)
    # npm 11 can omit production React packages shared with development peers.
    # Preserve that output as evidence; select production components from its full
    # installed inventory and rebuild edges from the installed package declarations.
    full = subprocess.run([npm, "sbom", "--sbom-format", "cyclonedx"], cwd=ROOT / "frontend",
                          capture_output=True, text=True, encoding="utf-8", check=True)
    bom = json.loads(full.stdout)
    bom["metadata"]["authors"] = [AUTHOR]
    bom["metadata"]["timestamp"] = timestamp
    lock = json.loads((ROOT / "frontend/package-lock.json").read_text(encoding="utf-8"))["packages"]
    runtime = {path: entry for path, entry in lock.items() if path and not entry.get("dev")}
    installed, missing_optional, missing_required = {}, [], []
    for path, entry in runtime.items():
        package_file = ROOT / "frontend" / path / "package.json"
        if not package_file.exists():
            (missing_optional if entry.get("optional") else missing_required).append(path)
            continue
        package = json.loads(package_file.read_text(encoding="utf-8"))
        installed[(package["name"], package["version"])] = (path, package, entry)
    raw_keys = {(c["name"], c["version"]) for c in raw_production["components"]}
    raw_missing = sorted(f"{name}@{version}" for name, version in set(installed) - raw_keys)
    bom["components"] = [c for c in bom["components"] if (c["name"], c["version"]) in installed]
    refs = {(c["name"], c["version"]): c["bom-ref"] for c in bom["components"]}
    by_path = {path: (name, version) for (name, version), (path, _, _) in installed.items()}
    frontend_root = ROOT / "frontend"

    def resolve_dependency(package_root: Path, dependency: str) -> str | None:
        for directory in [package_root, *package_root.parents]:
            if not directory.is_relative_to(frontend_root):
                break
            candidate = directory / "node_modules" / dependency
            relative = candidate.relative_to(frontend_root).as_posix()
            if relative in by_path:
                return refs.get(by_path[relative])
        return None

    def declared_edges(package_root: Path, package: dict) -> list[str]:
        children = set()
        declared = {**package.get("dependencies", {}), **package.get("optionalDependencies", {}), **package.get("peerDependencies", {})}
        for name in declared:
            ref = resolve_dependency(package_root, name)
            if ref:
                children.add(ref)
            elif name in package.get("dependencies", {}) and name not in package.get("optionalDependencies", {}):
                raise ValueError(f"Missing required installed production dependency: {package['name']} -> {name}")
        return sorted(children)

    root_package = json.loads((frontend_root / "package.json").read_text(encoding="utf-8"))
    bom["dependencies"] = [{"ref": bom["metadata"]["component"]["bom-ref"], "dependsOn": declared_edges(frontend_root, root_package)}]
    for key, (path, package, _) in sorted(installed.items()):
        if key in refs:
            bom["dependencies"].append({"ref": refs[key], "dependsOn": declared_edges(frontend_root / path, package)})
    mismatches, notices = [], []
    component_keys = set()
    for component in bom["components"]:
        key = (component["name"], component["version"])
        component_keys.add(key)
        if key not in installed:
            mismatches.append(f"SBOM component absent from installed lock tree: {key}")
            continue
        path, package, entry = installed[key]
        if package["version"] != entry["version"]:
            mismatches.append(f"{path}: lock={entry['version']}, installed={package['version']}")
        declared_supplier = package.get("supplier")
        supplier_name = declared_supplier if isinstance(declared_supplier, str) else (declared_supplier or {}).get("name")
        component["supplier"] = {"name": supplier_name or "unknown (supplier not declared in installed package.json)"}
        component.setdefault("properties", []).extend([prop("supplier-evidence", "package.json supplier" if supplier_name else "No supplier declaration; author/repository are not treated as supplier"), prop("metadata-source", f"frontend/{path}/package.json")])
        files = []
        package_root = ROOT / "frontend" / path
        for source in sorted(package_root.rglob("*")):
            relative = source.relative_to(package_root)
            if "node_modules" not in relative.parts and source.is_file() and is_notice(relative):
                folder = f"{key[0].replace('@', '').replace('/', '__')}-{key[1]}"
                files.append(copy_notice(source, OUTPUT / "licenses" / "npm" / folder / relative))
        label = package.get("license", "unknown (not declared)")
        notices.append({"ecosystem": "npm", "name": key[0], "version": key[1], "declared_license": label, "files": files})
    missing_components = sorted(f"{name}@{version}" for name, version in set(installed) - component_keys)
    validation = {"component_count": len(bom["components"]), "production_lock_count": len(runtime),
                  "installed_runtime_count": len(installed), "installed_version_mismatches": mismatches,
                  "missing_required_installed_packages": missing_required, "missing_optional_platform_packages": missing_optional,
                  "npm_raw_omit_dev_missing_components": raw_missing,
                  "generation_method": "npm full installed SBOM filtered by production lock+installed package versions; dependencies reconstructed from installed dependencies/optionalDependencies/peerDependencies with Node ancestor resolution. Original npm --omit dev output retained as evidence.",
                  "missing_sbom_components": missing_components, **graph_errors(bom)}
    return bom, notices, validation


def main() -> None:
    OUTPUT.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    python_bom, python_notices, python_validation = python_inventory(timestamp)
    frontend_bom, frontend_notices, frontend_validation = frontend_inventory(timestamp)
    all_notices = python_notices + frontend_notices
    missing_notices = [f"{n['ecosystem']}:{n['name']}@{n['version']}" for n in all_notices if not n["files"]]
    validation = {"generated_at": timestamp, "python": python_validation, "frontend": frontend_validation,
                  "license_component_count": len(all_notices), "license_file_count": sum(len(n["files"]) for n in all_notices),
                  "missing_license_texts": missing_notices, "license_files": all_notices,
                  "hash_semantics": "Python lock SHA-256 values are approved wheel/sdist candidate hashes, not a claim about the installed archive. No RECORD aggregate hash is used. Copied license SHA-256 checks text fidelity. npm integrity refers to its locked distribution archive.",
                  "supplier_semantics": "Only explicit Supplier/supplier declarations count; unknown is stated. Authors and repository hosts are not inferred suppliers.",
                  "scope": "Production Python runtime and installed npm production runtime; development/build packages and native binary subcomponents are not expanded into separate components."}
    failure_fields = ["dangling_refs", "missing_dependency_nodes", "unreachable_components", "duplicate_refs", "installed_version_mismatches", "missing_required_installed_packages", "missing_sbom_components"]
    validation["passed"] = not missing_notices and not any(section.get(key) for section in [python_validation, frontend_validation] for key in failure_fields)
    write_json(OUTPUT / "SBOM.python.cdx.json", python_bom)
    write_json(OUTPUT / "SBOM.frontend.cdx.json", frontend_bom)
    write_json(OUTPUT / "SUPPLY_CHAIN_VALIDATION.json", validation)
    notice_lines = ["# Third-party notices", "", f"Generated: {timestamp}", "",
                    "The following license declarations and full texts come from the exact installed production packages. Texts are copied unchanged; SHA-256 and paths are recorded in `SUPPLY_CHAIN_VALIDATION.json`. A declaration is not a legal compatibility opinion. Supplier names are not inferred from authors or repository hosts.", "",
                    "Python wheel/sdist archives are not retained, so the SBOM does not claim an installed archive hash. Lock candidate hashes remain explicitly labelled. Bundled native libraries may carry additional notices inside the copied package license text; they are not separately inventoried here.", "",
                    "| Ecosystem | Package | Declared license | Complete text / notices |", "|---|---|---|---|"]
    for item in all_notices:
        label = str(item["declared_license"]).replace("\n", " ").replace("|", "\\|")
        links = ", ".join(f"[{Path(f['path']).name}](<{f['path']}>)" for f in item["files"]) or "MISSING"
        notice_lines.append(f"| {item['ecosystem']} | {item['name']} {item['version']} | {label} | {links} |")
    (OUTPUT / "THIRD_PARTY_NOTICES.md").write_text("\n".join(notice_lines) + "\n", encoding="utf-8")
    report = ["# 공급망 대조 결과", "", f"생성 시각: {timestamp}", "",
              f"판정: {'통과' if validation['passed'] else '미완료'}. Python 생산 구성요소 {len(python_bom['components'])}개, 프런트 생산 구성요소 {len(frontend_bom['components'])}개. 라이선스 원문 {validation['license_file_count']}개를 `submission/licenses/`에 복사했다.", "",
              "두 SBOM은 CycloneDX 1.5 형식으로 구성요소 이름·버전·purl·공급자 선언 여부·실제 의존관계·문서 생성자·타임스탬프를 기록한다. `requirements-runtime.lock`의 정확한 버전을 설치 metadata와 대조하고, pyproject의 생산 의존성과 `qrcode[pil]` extra부터 현재 플랫폼 marker를 평가해 실제 그래프를 구성한다. 프런트는 npm SBOM을 재생성한 뒤 package-lock과 설치 package.json을 대조했다.", "",
              f"npm `--omit dev` 원본에서는 생산 패키지 {frontend_validation['npm_raw_omit_dev_missing_components']}가 누락됐다. 원본은 `SBOM.frontend.npm-production.raw.cdx.json`에 남겼다. 전체 설치 SBOM 중 생산 lock과 정확히 일치하는 구성요소를 선택하고, 설치 package.json의 dependencies/optionalDependencies/peerDependencies와 Node 상위 디렉터리 해석으로 실제 의존관계를 다시 구성해 최종 SBOM의 누락을 해결했다.", "",
              "공급자 필드가 없으면 unknown을 명시했다. 작성자나 저장소 소유자를 공급자로 추정하지 않았다. Python lock의 wheel/sdist 후보 해시는 설치된 wheel 자체 해시가 아니며, RECORD 집계값도 wheel 해시로 싣지 않았다. 원문 복사 파일의 SHA-256은 복사 무결성을 확인하는 값이다.", "",
              "| 대조 | Python | 프런트 |", "|---|---:|---:|"]
    for key, label in [("component_count", "구성요소"), ("edge_count", "의존관계"), ("installed_version_mismatches", "버전 불일치"), ("dangling_refs", "존재하지 않는 참조"), ("missing_dependency_nodes", "누락된 그래프 노드"), ("unreachable_components", "루트에서 닿지 않는 구성요소"), ("duplicate_refs", "중복 참조")]:
        values = [section[key] if isinstance(section[key], int) else len(section[key]) for section in [python_validation, frontend_validation]]
        report.append(f"| {label} | {values[0]} | {values[1]} |")
    report.extend(["", f"현재 Python 플랫폼: {python_validation['dependency_environment']['sys_platform']}. 플랫폼/extra 평가 후 생산 루트에서 도달하지 않는 잠금 항목: {python_validation['inactive_locked_packages']}. 비활성 잠금 항목은 이 플랫폼의 활성 SBOM에서 제외하며, 활성 의존성의 lock 누락이나 설치 버전 불일치는 계속 실패 처리한다. Windows는 활성 20개, Linux는 Windows 전용 colorama를 제외한 활성 19개다.", "",
                   f"라이선스 원문 누락: {len(missing_notices)}개. 프런트 플랫폼 선택사항 미설치: {len(frontend_validation['missing_optional_platform_packages'])}개. 상세 원문 경로·해시·버전 증거는 `SUPPLY_CHAIN_VALIDATION.json`, 읽을 라이선스 전문은 `THIRD_PARTY_NOTICES.md`에서 확인한다.", "",
                   "이 검사는 오프라인 설치 목록과 잠금 파일의 대조다. SBOM JSON 스키마 검증이나 라이선스 의무의 법률 판정, 네이티브 바이너리에 포함된 모든 하위 라이브러리의 독립 SBOM을 보증하지 않는다. 기존 취약점 조회 결과는 별도 보안 점검 기록에 있다."])
    (OUTPUT / "SUPPLY_CHAIN_VALIDATION.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps({"passed": validation["passed"], "python": len(python_bom["components"]), "frontend": len(frontend_bom["components"]), "license_files": validation["license_file_count"], "missing_license_texts": missing_notices}, ensure_ascii=False))
    if not validation["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
