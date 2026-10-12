"""Keep the production origin, trusted peer, and Nginx header contract aligned."""

import importlib
import ipaddress
import re
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_production_proxy_configuration_uses_one_exact_gateway():
    compose = yaml.safe_load((ROOT / "compose.production.yaml").read_text(encoding="utf-8"))
    app = compose["services"]["app"]
    bridge = compose["networks"]["trusted-proxy-bridge"]["ipam"]["config"][0]
    assert app["networks"] == ["trusted-proxy-bridge"]
    assert app["ports"] == ["127.0.0.1:8002:8000"]
    gateway = app["environment"]["ONJEON_TRUSTED_PROXY_IP"]
    assert gateway == bridge["gateway"]
    subnet_default = re.fullmatch(r"\$\{ONJEON_BRIDGE_SUBNET:-([^}]+)\}", bridge["subnet"])[1]
    gateway_default = re.fullmatch(r"\$\{ONJEON_BRIDGE_GATEWAY:-([^}]+)\}", gateway)[1]
    assert ipaddress.ip_address(gateway_default) in ipaddress.ip_network(subnet_default)

    nginx = (ROOT / "deploy" / "nginx-onjeon.conf").read_text(encoding="utf-8")
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in nginx
    assert "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;" not in nginx
    assert "proxy_set_header X-Real-IP \"\";" in nginx


def test_production_server_rejects_wildcard_or_network_proxy_trust(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    entrypoint = importlib.import_module("run_production_server")
    monkeypatch.setattr(entrypoint, "load_configuration", lambda: None)
    captured = []
    monkeypatch.setattr(entrypoint.uvicorn, "run", lambda *args, **kwargs: captured.append(kwargs))
    monkeypatch.setenv("ONJEON_TRUSTED_PROXY_IP", "172.29.253.1")
    entrypoint.main()
    assert captured == [{"factory": True, "host": "0.0.0.0", "port": 8000,
                         "proxy_headers": True, "forwarded_allow_ips": "172.29.253.1", "access_log": False}]
    for unsafe in ("*", "172.29.253.0/29", ""):
        monkeypatch.setenv("ONJEON_TRUSTED_PROXY_IP", unsafe)
        with pytest.raises(RuntimeError, match="one Docker gateway IP"):
            entrypoint.main()
    assert len(captured) == 1
