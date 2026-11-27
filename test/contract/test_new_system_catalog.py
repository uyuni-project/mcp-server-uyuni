import os

import pytest
from fastmcp import Client

os.environ.setdefault("UYUNI_SERVER", "https://mock-server.local")

from mcp_server_uyuni.tools.systems import build_test_system_catalog


@pytest.mark.asyncio
async def test_new_system_catalog_contract():
    server = build_test_system_catalog()
    tools = {tool.name: tool.to_mcp_tool() for tool in await server.list_tools()}
    assert list(tools) == ["systems_search", "systems_get", "systems_events_list", "systems_events_get"]

    expected_inputs = {
        "systems_search": {
            "hostname", "ip", "uuid", "name", "group_name",
            "reboot_required", "limit", "offset",
        },
        "systems_get": {"system_id", "system_name"},
        "systems_events_list": {
            "system_id", "system_name", "limit", "offset", "earliest_date",
        },
        "systems_events_get": {"event_id", "system_id", "system_name"},
    }
    for name, properties in expected_inputs.items():
        assert set(tools[name].inputSchema["properties"]) == properties

    assert tools["systems_events_get"].inputSchema["required"] == ["event_id"]
    for name in ("systems_search", "systems_get", "systems_events_list"):
        assert not tools[name].inputSchema.get("required")

    for tool in tools.values():
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.openWorldHint is False
        assert tool.outputSchema is None


@pytest.mark.asyncio
async def test_tool_delegates_to_domain_with_flat_arguments():
    calls = []

    class FakeApi:
        def __init__(self, token):
            calls.append(("token", token))
            self.systems = self

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def list_group_systems(self, name):
            calls.append(("group", name))
            return [{"id": 4, "name": "host"}]

    server = build_test_system_catalog(FakeApi)
    async with Client(server) as client:
        result = await client.call_tool("systems_search", {"group_name": "ops", "limit": 1})
    assert result.structured_content["items"] == [{"system_id": 4, "system_name": "host"}]
    assert ("group", "ops") in calls
