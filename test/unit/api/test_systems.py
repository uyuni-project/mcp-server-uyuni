import os

import pytest

os.environ.setdefault("UYUNI_SERVER", "https://mock-server.local")

from mcp_server_uyuni.api.client import UyuniSession
from mcp_server_uyuni.api.systems import SystemsApi
from mcp_server_uyuni.errors import UnexpectedResponse


@pytest.mark.asyncio
async def test_adapter_paths_params_and_response_validation():
    calls = []
    session = UyuniSession()

    async def fake_request(method, path, context, *, params=None, json_body=None):
        calls.append((method, path, params))
        if path.endswith("getDetails"):
            return {"id": 7, "profile_name": "host"}
        if path.endswith("listSuggestedReboot"):
            return ["invalid"]
        return []

    session.request = fake_request
    api = SystemsApi(session)
    await api.search("hostname", "host")
    await api.get_id("host")
    await api.list_group_systems("ops")
    await api.get_event_history(7, 10, 26, "2026-01-01T00:00:00Z")
    await api.get_details(7)
    assert calls == [
        ("GET", "/rhn/manager/api/system/search/hostname", {"searchTerm": "host"}),
        ("GET", "/rhn/manager/api/system/getId", {"name": "host"}),
        ("GET", "/rhn/manager/api/systemgroup/listSystemsMinimal", {"systemGroupName": "ops"}),
        ("GET", "/rhn/manager/api/system/getEventHistory", {"sid": 7, "offset": 10, "limit": 26, "earliestDate": "2026-01-01T00:00:00Z"}),
        ("GET", "/rhn/manager/api/system/getDetails", {"sid": 7}),
    ]
    with pytest.raises(UnexpectedResponse):
        await api.get_network(7)
    with pytest.raises(UnexpectedResponse, match="list of dict"):
        await api.list_suggested_reboot()
    with pytest.raises(ValueError):
        await api.search("unsupported", "x")
