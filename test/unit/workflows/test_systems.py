import os

import pytest

os.environ.setdefault("UYUNI_SERVER", "https://mock-server.local")

from mcp_server_uyuni.workflows.systems.discovery import (
    AmbiguousSystemError, SystemNotFoundError, get_system, resolve_id,
    search_systems,
)
from mcp_server_uyuni.workflows.systems.events import get_event, list_events


class FakeApi:
    """Controlled Uyuni responses for routing and result-shaping tests."""

    def __init__(self):
        self.calls = []
        self.systems = self

    async def search(self, field, term):
        self.calls.append((field, term))
        return [{"id": 1, "name": "host"}, {"id": 2, "name": "host"}] if term == "host" else []

    async def get_id(self, name):
        self.calls.append(("get_id", name))
        if name == "host":
            # Exact-name lookup can still return more than one system.
            return [{"id": 1, "name": name}, {"id": 2, "name": name}]
        if name == "other":
            return [{"id": 2, "name": name}]
        return []

    async def list_systems(self):
        self.calls.append("all")
        return [{"id": 1, "name": "host"}, {"id": 2, "name": "other"}]

    async def list_group_systems(self, name):
        self.calls.append(("group", name))
        return [{"id": 1, "name": "host"}]

    async def list_suggested_reboot(self):
        self.calls.append("reboot")
        return [{"id": 1, "name": "host"}]

    async def get_details(self, sid):
        self.calls.append(("details", sid))
        return {"id": sid, "profile_name": "host", "last_boot": "2026-01-01T00:00:00Z"}

    async def get_cpu(self, sid):
        return {"model": "x"}

    async def get_network(self, sid):
        return {"hostname": "host", "ip": "192.0.2.1"}

    async def get_uuid(self, sid):
        return "u"

    async def get_installed_products(self, sid):
        return [{"name": "SLES", "friendlyName": "SUSE Linux", "isBaseProduct": True}]

    async def get_event_history(self, sid, offset, limit, earliest_date):
        self.calls.append(("history", sid, offset, limit, earliest_date))
        # Fill the requested page, including the lookahead row used for has_more.
        return [{"id": i, "summary": "event"} for i in range(limit)]

    async def get_event_details(self, sid, eid):
        self.calls.append(("event", sid, eid))
        return {"id": eid, "status": "completed"}


@pytest.mark.asyncio
async def test_exact_one_and_ambiguity():
    api = FakeApi()
    for kwargs in ({}, {"system_id": 1, "system_name": "host"}, {"system_id": 0}):
        with pytest.raises(ValueError):
            await resolve_id(api, **kwargs)
    with pytest.raises(AmbiguousSystemError) as exc:
        await resolve_id(api, system_name="host")
    assert [candidate["system_id"] for candidate in exc.value.candidates] == [1, 2]
    assert await resolve_id(api, system_name="other") == 2
    with pytest.raises(SystemNotFoundError):
        await resolve_id(api, system_name="OTHER")
    # Invalid identifier combinations are rejected before any Uyuni lookup.
    assert api.calls == [
        ("get_id", "host"),
        ("get_id", "other"),
        ("get_id", "OTHER"),
    ]


@pytest.mark.asyncio
async def test_specialized_routing_and_canonical_shape():
    api = FakeApi()
    result = await search_systems(api, group_name="ops", reboot_required=True)
    assert result["items"] == [{"system_id": 1, "system_name": "host"}]
    assert result["page"]["mode"] == "response_only"
    assert api.calls == [("group", "ops"), "reboot"]
    system = await get_system(api, system_id=1)
    assert system["system_name"] == "host"
    assert system["cpu"]["model"] == "x"
    assert system["network"]["ip"] == "192.0.2.1"
    assert system["installed_products"][0]["friendly_name"] == "SUSE Linux"


@pytest.mark.asyncio
async def test_reboot_false_filters_existing_candidates_without_listing_all_systems():
    api = FakeApi()

    result = await search_systems(api, hostname="host", reboot_required=False)

    assert result["items"] == [{"system_id": 2, "system_name": "host"}]
    assert api.calls == ["reboot", ("hostname", "host")]


@pytest.mark.asyncio
async def test_reboot_false_without_other_filters_starts_from_all_systems():
    api = FakeApi()

    result = await search_systems(api, reboot_required=False)

    assert result["items"] == [{"system_id": 2, "system_name": "other"}]
    assert api.calls == ["reboot", "all"]


@pytest.mark.asyncio
async def test_events_use_native_page_and_owner():
    api = FakeApi()
    result = await list_events(api, system_id=1, limit=2, offset=3)
    assert result["page"] == {"returned": 2, "next_offset": 5, "has_more": True, "mode": "native"}
    assert api.calls[-1] == ("history", 1, 3, 3, None)
    event = await get_event(api, 9, system_id=1)
    assert event["system"] == {"system_id": 1, "system_name": "host"}
    assert api.calls[-1] == ("event", 1, 9)
    with pytest.raises(ValueError):
        await get_event(api, 9)
