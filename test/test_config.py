import importlib
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))


def _reload_config_module():
    sys.modules.pop("mcp_server_uyuni.config", None)
    return importlib.import_module("mcp_server_uyuni.config")


def test_config_accepts_schemeless_uyuni_server(monkeypatch):
    monkeypatch.setenv("UYUNI_SERVER", "mock-server.local")

    config_module = _reload_config_module()

    assert config_module.CONFIG["UYUNI_SERVER"] == "https://mock-server.local"


def test_config_accepts_and_normalizes_uris(monkeypatch):
    monkeypatch.setenv("UYUNI_SERVER", "https://mock-server.local/")
    monkeypatch.setenv("UYUNI_AUTH_SERVER", "auth.example.com/realms/uyuni-mcp/")

    config_module = _reload_config_module()

    assert config_module.CONFIG["UYUNI_SERVER"] == "https://mock-server.local"
    assert config_module.CONFIG["AUTH_SERVER"] == "https://auth.example.com/realms/uyuni-mcp"


def test_config_rejects_non_http_scheme(monkeypatch):
    monkeypatch.setenv("UYUNI_SERVER", "ftp://mock-server.local")

    with pytest.raises(ImportError, match="UYUNI_SERVER must use http or https"):
        _reload_config_module()


def test_config_keeps_auth_optional(monkeypatch):
    monkeypatch.setenv("UYUNI_SERVER", "https://mock-server.local")
    monkeypatch.delenv("UYUNI_AUTH_SERVER", raising=False)

    config_module = _reload_config_module()

    assert config_module.CONFIG["AUTH_SERVER"] is None


def test_auth_provider_uses_issuer_and_static_audience():
    from mcp_server_uyuni.auth import AuthProvider

    with patch("mcp_server_uyuni.auth.JWTVerifier") as verifier_mock, patch(
        "mcp_server_uyuni.auth.RemoteAuthProvider.__init__", return_value=None
    ):
        AuthProvider(
            auth_server="https://auth.example.com/realms/demo",
            base_url="http://mcp.example",
            write_enabled=True,
        )

    verifier_kwargs = verifier_mock.call_args.kwargs
    assert verifier_kwargs["issuer"] == "https://auth.example.com/realms/demo"
    assert verifier_kwargs["jwks_uri"] == "https://auth.example.com/realms/demo/protocol/openid-connect/certs"
    assert verifier_kwargs["audience"] == "mcp-server-uyuni"
    assert verifier_kwargs["required_scopes"] == ["mcp:read", "mcp:write"]
