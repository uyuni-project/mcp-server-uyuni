import os

import pytest
from fastmcp import Client, FastMCP

os.environ.setdefault("UYUNI_SERVER", "https://mock-server.local")

from mcp_server_uyuni.api.client import UyuniSession
from mcp_server_uyuni.tools.cve import register_cve_tools
from mcp_server_uyuni.tools.systems import register_system_tools


def build_test_system_catalog(session_factory=UyuniSession) -> FastMCP:
    server = FastMCP("uyuni-system-catalog-test")
    register_system_tools(server, session_factory)
    register_cve_tools(server)
    return server


@pytest.mark.asyncio
async def test_new_system_catalog_contract():
    server = build_test_system_catalog()
    tools = {tool.name: tool.to_mcp_tool() for tool in await server.list_tools()}
    assert list(tools) == [
        "systems_search", "systems_get", "systems_events_list", "systems_events_get",
        "systems_updates_get", "systems_updates_search", "cve_systems_search",
    ]

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
        "systems_updates_get": {
            "system_id", "system_name", "response_format", "advisory_types",
            "application_status", "limit", "offset",
        },
        "systems_updates_search": {
            "group_name", "response_format",
            "limit", "offset",
        },
        "cve_systems_search": {"cve_identifier", "patch_statuses", "limit", "offset"},
    }
    for name, properties in expected_inputs.items():
        assert set(tools[name].inputSchema["properties"]) == properties

    assert tools["systems_events_get"].inputSchema["required"] == ["event_id"]
    assert tools["cve_systems_search"].inputSchema["required"] == ["cve_identifier"]
    for name in ("systems_search", "systems_get", "systems_events_list",
                 "systems_updates_get", "systems_updates_search"):
        assert not tools[name].inputSchema.get("required")

    # Adjacent requests have distinct system scope and patch-status semantics.
    assert "system_id" in tools["systems_updates_get"].inputSchema["properties"]
    assert "group_name" in tools["systems_updates_search"].inputSchema["properties"]
    assert "patch_statuses" in tools["cve_systems_search"].inputSchema["properties"]
    get_formats = tools["systems_updates_get"].inputSchema["properties"]["response_format"]
    search_formats = tools["systems_updates_search"].inputSchema["properties"]["response_format"]
    assert get_formats["enum"] == ["counts", "summary", "standard", "detailed"]
    assert search_formats["enum"] == ["summary", "standard", "detailed"]

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
