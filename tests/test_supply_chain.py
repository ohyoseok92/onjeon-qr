"""Check the real local production inventory, including shared React peers."""
import sys
import pytest

from scripts import generate_supply_chain as inventory


@pytest.mark.skipif(not (inventory.ROOT / "frontend/node_modules/react/package.json").is_file(),
                    reason="Cross-stack inventory requires installed npm production dependencies")
def test_production_inventory_matches_installed_metadata_and_preserves_licenses(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory, "OUTPUT", tmp_path)
    python, python_notices, py_check = inventory.python_inventory("2026-10-11T00:00:00Z")
    frontend, npm_notices, npm_check = inventory.frontend_inventory("2026-10-11T00:00:00Z")
    assert py_check["lock_count"] == 20
    expected_python_count = 20 if sys.platform == "win32" else 19
    assert py_check["component_count"] == expected_python_count
    assert py_check["component_count"] + len(py_check["inactive_locked_packages"]) == py_check["lock_count"]
    assert npm_check["component_count"] == npm_check["production_lock_count"] == 8
    for check in [py_check, npm_check]:
        for key in ["installed_version_mismatches", "dangling_refs", "missing_dependency_nodes", "unreachable_components", "duplicate_refs"]:
            assert not check[key], (key, check[key])
    npm_refs = {component["name"]: component["bom-ref"] for component in frontend["components"]}
    assert {"react", "react-dom", "scheduler", "jsqr"} <= npm_refs.keys()
    npm_graph = {node["ref"]: node["dependsOn"] for node in frontend["dependencies"]}
    assert npm_refs["react"] in npm_graph[frontend["metadata"]["component"]["bom-ref"]]
    assert npm_refs["scheduler"] in npm_graph[npm_refs["react-dom"]]
    py_refs = {component["name"]: component["bom-ref"] for component in python["components"]}
    py_graph = {node["ref"]: node["dependsOn"] for node in python["dependencies"]}
    assert py_refs["starlette"] in py_graph[py_refs["fastapi"]]
    assert py_refs["pillow"] in py_graph[py_refs["qrcode"]]
    for notice in python_notices + npm_notices:
        assert notice["files"], notice["name"]
        for file in notice["files"]:
            data = (tmp_path / file["path"]).read_bytes()
            assert data
            assert inventory.hashlib.sha256(data).hexdigest() == file["sha256"]
    # Supplier provenance must not be fabricated from the package's author.
    assert all(component["supplier"]["name"] for component in python["components"] + frontend["components"])


def test_lock_and_installed_version_disagreement_is_rejected(tmp_path, monkeypatch):
    lock = (inventory.ROOT / "requirements-runtime.lock").read_text(encoding="utf-8")
    (tmp_path / "requirements-runtime.lock").write_text(lock.replace("annotated-doc==0.0.5", "annotated-doc==999.0.0"), encoding="utf-8")
    (tmp_path / "pyproject.toml").write_bytes((inventory.ROOT / "pyproject.toml").read_bytes())
    monkeypatch.setattr(inventory, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="installed versions differ"):
        inventory.python_inventory("2026-10-11T00:00:00Z")


def test_linux_markers_exclude_windows_only_colorama_without_reading_its_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory, "OUTPUT", tmp_path)
    actual_distribution = inventory.metadata.distribution

    def read_active_distribution(name):
        assert name != "colorama", "Windows-only inactive package must not require installed metadata on Linux"
        return actual_distribution(name)

    monkeypatch.setattr(inventory.metadata, "distribution", read_active_distribution)
    bom, notices, check = inventory.python_inventory("2026-10-11T00:00:00Z", marker_environment={
        "sys_platform": "linux", "platform_system": "Linux", "os_name": "posix",
    })
    assert check["component_count"] == 19
    assert check["lock_count"] == 20
    assert check["inactive_locked_packages"] == [{"name": "colorama", "version": "0.4.6"}]
    assert "colorama" not in {component["name"] for component in bom["components"]}
    assert "colorama" not in {item["name"] for item in notices}
    assert not check["dangling_refs"]
    assert not check["unreachable_components"]
    assert not check["missing_dependency_nodes"]
