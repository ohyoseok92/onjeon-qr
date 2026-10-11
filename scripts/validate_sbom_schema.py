"""Validate saved SBOMs against the locally preserved official CycloneDX 1.5 schema.

Requires jsonschema 4.x in the validation tool environment, not service runtime.
Schemas are preserved in submission/schemas with source URL and SHA-256 evidence.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "submission"


def main() -> None:
    manifest = json.loads((OUTPUT / "schemas/SOURCES.json").read_text(encoding="utf-8"))
    registry = Registry()
    documents = {}
    for source in manifest["sources"]:
        data = (OUTPUT / "schemas" / source["filename"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != source["sha256"]:
            raise ValueError(f"Schema hash changed: {source['filename']}")
        document = json.loads(data)
        documents[source["filename"]] = document
        registry = registry.with_resource(f"http://cyclonedx.org/schema/{source['filename']}", Resource.from_contents(document))
    validator = Draft7Validator(documents["bom-1.5.schema.json"], registry=registry)
    results = {}
    for name in ["SBOM.python.cdx.json", "SBOM.frontend.cdx.json"]:
        errors = sorted(validator.iter_errors(json.loads((OUTPUT / name).read_text(encoding="utf-8"))), key=lambda error: str(error.path))
        results[name] = [{"path": list(error.absolute_path), "message": error.message} for error in errors]
    check = {"checked_at": datetime.now(timezone.utc).isoformat(), "validator": "jsonschema Draft7Validator",
             "validator_version": importlib.metadata.version("jsonschema"),
             "official_specification": "CycloneDX specification git tag 1.5", "results": results,
             "passed": not any(results.values())}
    validation_file = OUTPUT / "SUPPLY_CHAIN_VALIDATION.json"
    validation = json.loads(validation_file.read_text(encoding="utf-8"))
    validation["schema_validation"] = check
    validation["passed"] = validation["passed"] and check["passed"]
    validation_file.write_text(json.dumps(validation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report_path = OUTPUT / "SUPPLY_CHAIN_VALIDATION.md"
    report = report_path.read_text(encoding="utf-8")
    report = report.replace("SBOM JSON 스키마 검증이나 라이선스 의무의 법률 판정", "라이선스 의무의 법률 판정")
    report += "\n## 공식 스키마 검증\n\n"
    report += f"CycloneDX 공식 저장소의 1.5 태그에 있는 JSON 스키마와 두 참조 스키마를 내려받아 `submission/schemas/`에 보존했다. 출처와 SHA-256은 `schemas/SOURCES.json`에 있다. jsonschema Draft7 검증 결과: {'두 최종 SBOM 모두 통과' if check['passed'] else '실패, JSON 상세 확인 필요'}. 검증 도구는 별도 임시 환경에서 실행했으며 서비스 생산 의존성에 추가하지 않았다.\n"
    report_path.write_text(report, encoding="utf-8")
    print(json.dumps(check, ensure_ascii=False))
    if not check["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
