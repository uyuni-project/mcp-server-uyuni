import os

import httpx
import pytest
from unittest.mock import patch

os.environ.setdefault("UYUNI_SERVER", "https://mock-server.local")

from mcp_server_uyuni.api import client
from mcp_server_uyuni.errors import APIError, AuthError, NetworkError


@pytest.mark.asyncio
async def test_username_password_login(monkeypatch):
    monkeypatch.setitem(client.CONFIG, "UYUNI_USER", "test-user")
    monkeypatch.setitem(client.CONFIG, "UYUNI_PASS", "test-pass")
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"success": True, "result": []})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        await client.login(http_client)

    assert requests[0].url.path == "/rhn/manager/api/login"
    assert requests[0].content == b'{"login":"test-user","password":"test-pass"}'


@pytest.mark.asyncio
async def test_oidc_login_and_session_reuse(monkeypatch):
    monkeypatch.setitem(client.CONFIG, "UYUNI_USER", "test-user")
    monkeypatch.setitem(client.CONFIG, "UYUNI_PASS", "test-pass")
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"success": True, "result": 42})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        await client.login(http_client, token="oidc-token")
        result = await client.call(
            http_client, "GET", "/rhn/manager/api/system/getDetails",
            "fetching details", perform_login=False,
        )

    assert result == 42
    assert [request.url.path for request in requests] == [
        "/rhn/manager/api/oidcLogin", "/rhn/manager/api/system/getDetails",
    ]
    assert requests[0].headers["Authorization"] == "Bearer oidc-token"


@pytest.mark.asyncio
async def test_login_auth_failure_preserves_error(monkeypatch):
    monkeypatch.setitem(client.CONFIG, "UYUNI_USER", "test-user")
    monkeypatch.setitem(client.CONFIG, "UYUNI_PASS", "test-pass")
    transport = httpx.MockTransport(lambda request: httpx.Response(401, text="denied"))
    async with httpx.AsyncClient(transport=transport) as http_client:
        with pytest.raises(AuthError) as captured:
            await client.login(http_client)
    assert captured.value.status_code == 401


@pytest.mark.asyncio
async def test_post_rejected_when_writes_disabled(monkeypatch):
    monkeypatch.setitem(client.CONFIG, "UYUNI_MCP_WRITE_TOOLS_ENABLED", False)
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        with pytest.raises(APIError, match="write tools are disabled"):
            await client.call(http_client, "POST", "/rhn/manager/api/system/deleteSystem", "deleting")
    assert requests == []


def test_client_uses_configured_ssl_and_timeout(monkeypatch):
    monkeypatch.setitem(client.CONFIG, "UYUNI_MCP_SSL_VERIFY", False)
    monkeypatch.setitem(client.CONFIG, "UYUNI_MCP_TIMEOUT", 17.0)
    with patch.object(client.httpx, "AsyncClient") as client_factory:
        client.make_client()
    assert client_factory.call_args.kwargs["verify"] is False
    assert client_factory.call_args.kwargs["timeout"].read == 17.0
    assert client_factory.call_args.kwargs["timeout"].connect == 10.0


@pytest.mark.asyncio
async def test_expected_and_unexpected_timeouts():
    def timeout(request):
        raise httpx.ReadTimeout("timed out", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(timeout)) as http_client:
        result = await client.call(
            http_client, "GET", "/rhn/manager/api/system/listSystems",
            "listing systems", perform_login=False, expect_timeout=True,
        )
        assert result is client.TIMEOUT_HAPPENED
        with pytest.raises(NetworkError) as captured:
            await client.call(
                http_client, "GET", "/rhn/manager/api/system/listSystems",
                "listing systems", perform_login=False,
            )
    assert captured.value.timed_out is True


@pytest.mark.asyncio
async def test_session_authenticates_once_for_multiple_requests(monkeypatch):
    monkeypatch.setitem(client.CONFIG, "UYUNI_USER", "test-user")
    monkeypatch.setitem(client.CONFIG, "UYUNI_PASS", "test-pass")
    paths = []

    def handler(request):
        paths.append(request.url.path)
        return httpx.Response(200, json={"success": True, "result": []})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(client, "make_client", lambda: httpx.AsyncClient(transport=transport))
    async with client.UyuniSession() as session:
        await session.get("/rhn/manager/api/system/listSystems", "listing systems")
        await session.get("/rhn/manager/api/system/listSuggestedReboot", "listing reboots")

    assert paths == [
        "/rhn/manager/api/login",
        "/rhn/manager/api/system/listSystems",
        "/rhn/manager/api/system/listSuggestedReboot",
    ]
    with pytest.raises(APIError, match="must be open"):
        await session.request("GET", "/rhn/manager/api/system/listSystems", "listing systems")


@pytest.mark.asyncio
async def test_session_closes_client_when_login_fails(monkeypatch):
    monkeypatch.setitem(client.CONFIG, "UYUNI_USER", "test-user")
    monkeypatch.setitem(client.CONFIG, "UYUNI_PASS", "test-pass")
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(401, text="denied"))
    )
    monkeypatch.setattr(client, "make_client", lambda: http_client)

    with pytest.raises(AuthError):
        async with client.UyuniSession():
            pytest.fail("An unauthenticated session must not be exposed")

    assert http_client.is_closed
