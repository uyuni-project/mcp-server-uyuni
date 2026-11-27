import os

import pytest

os.environ.setdefault("UYUNI_SERVER", "https://mock-server.local")

from mcp_server_uyuni.workflows.systems.updates import get_updates, search_updates
from mcp_server_uyuni.workflows.cve import search_cve_systems
from mcp_server_uyuni.errors import UnexpectedResponse


def erratum(number, kind="Security Advisory"):
    return {
        "id": number, "advisory_name": f"ADV-{number}",
        "advisory_type": kind, "advisory_synopsis": f"Patch {number}",
        "reboot_suggested": False, "advisory_status": "final",
    }


class UpdateApi:
    def __init__(self, count=3):
        self.calls = []
        self.systems = self
        self.errata = self
        self.system_rows = [{"id": sid, "name": f"host-{sid}"} for sid in range(1, count + 1)]
        self.outdated = [{**row, "outdated_pkg_count": sid + 2}
                         for sid, row in enumerate(self.system_rows, 1)]
        self.errata_rows = {
            1: [erratum(1), erratum(2, "Bug Fix Advisory")],
            2: [erratum(3)],
        }

    async def list_systems(self):
        self.calls.append("list")
        return self.system_rows

    async def list_out_of_date_systems(self):
        self.calls.append("outdated")
        return self.outdated

    async def list_group_systems(self, name):
        self.calls.append(("group", name))
        return self.system_rows[:2]

    async def get_details(self, sid):
        return {"id": sid, "profile_name": f"host-{sid}"}

    async def get_relevant_errata(self, sid):
        self.calls.append(("single", sid))
        return self.errata_rows.get(sid, [])

    async def get_unscheduled_errata(self, sid):
        self.calls.append(("unscheduled", sid))
        return [erratum(1)] if sid == 1 else []

    async def get_relevant_errata_batch(self, sids):
        self.calls.append(("batch", sids))
        return [{"system_id": str(sid), "errata": self.errata_rows.get(sid, [])} for sid in sids]

    async def list_cves(self, advisory_name):
        return []


@pytest.mark.asyncio
async def test_one_system_formats_status_filters_and_cve_page(monkeypatch):
    api = UpdateApi()
    cve_calls = []

    async def fake_list_cves(self, advisory_name):
        cve_calls.append(advisory_name)
        return ["CVE-2026-1234"]

    monkeypatch.setattr(UpdateApi, "list_cves", fake_list_cves)
    summary = await get_updates(api, system_id=1)
    assert summary["summary"]["pending_update_count"] == 1
    assert summary["summary"]["queued_update_count"] == 1
    assert "advisory_synopsis" not in summary["items"][0]
    assert cve_calls == []

    counts = await get_updates(api, system_id=1, response_format="counts")
    assert counts["items"] == []
    assert counts["summary"] == summary["summary"]
    assert counts["page"] == {
        "returned": 0, "next_offset": None, "has_more": False,
        "mode": "response_only",
    }
    assert cve_calls == []

    filtered_counts = await get_updates(
        api, system_id=1, response_format="counts",
        advisory_types=["Bug Fix Advisory"], application_status="Queued",
    )
    assert filtered_counts["summary"]["update_count"] == 1
    assert filtered_counts["summary"]["pending_update_count"] == 0
    assert filtered_counts["summary"]["queued_update_count"] == 1
    with pytest.raises(ValueError, match="offset must be 0"):
        await get_updates(api, system_id=1, response_format="counts", offset=1)

    standard = await get_updates(api, system_id=1, response_format="standard",
                                 advisory_types=["Bug Fix Advisory"])
    assert [item["advisory_name"] for item in standard["items"]] == ["ADV-2"]
    assert standard["items"][0]["application_status"] == "Queued"
    assert "advisory_synopsis" in standard["items"][0]
    pending = await get_updates(api, system_id=1, application_status="Pending")
    assert [item["advisory_name"] for item in pending["items"]] == ["ADV-1"]

    detailed = await get_updates(api, system_id=1, response_format="detailed", limit=1)
    assert detailed["items"][0]["cves"] == ["CVE-2026-1234"]
    assert detailed["page"]["has_more"] is True
    assert detailed["page"]["mode"] == "response_only"
    assert cve_calls == ["ADV-1"]


@pytest.mark.asyncio
async def test_batch_search_pages_outdated_systems_and_never_calls_single():
    api = UpdateApi(count=205)
    result = await search_updates(api, limit=2, offset=1)
    assert [item["system_id"] for item in result["items"]] == [2, 3]
    assert result["items"][1]["outdated_package_count"] == 5
    assert result["items"][1]["relevant_advisory_count"] == 0
    assert result["page"]["next_offset"] == 3
    assert result["page"]["mode"] == "response_only"
    assert api.calls == ["outdated", ("batch", [2, 3])]

    api.calls.clear()
    full_page = await search_updates(api, limit=100)
    assert len(full_page["items"]) == 100
    batches = [call for call in api.calls if isinstance(call, tuple) and call[0] == "batch"]
    assert [len(call[1]) for call in batches] == [100]
    assert not any(isinstance(call, tuple) and call[0] == "single" for call in api.calls)

    api.calls.clear()
    group = await search_updates(api, group_name="ops")
    assert [item["system_id"] for item in group["items"]] == [1, 2]
    assert api.calls == ["outdated", ("group", "ops"), ("batch", [1, 2])]


@pytest.mark.asyncio
async def test_search_formats_empty_and_malformed(monkeypatch):
    api = UpdateApi()
    cve_calls = []

    async def fake_list_cves(self, advisory_name):
        cve_calls.append(advisory_name)
        return ["CVE-2026-1234"]

    monkeypatch.setattr(UpdateApi, "list_cves", fake_list_cves)
    with pytest.raises(ValueError, match="response_format must be one of"):
        await search_updates(api, response_format="counts")
    summary = await search_updates(api, group_name="ops", response_format="summary")
    assert "updates" not in summary["items"][0]
    standard = await search_updates(api, response_format="standard")
    assert standard["items"][0]["updates"][0]["advisory_synopsis"] == "Patch 1"
    assert cve_calls == []
    detailed = await search_updates(api, response_format="detailed")
    assert detailed["items"][0]["updates"][0]["advisory_status"] == "final"
    assert detailed["items"][0]["updates"][0]["cves"] == ["CVE-2026-1234"]
    assert sorted(cve_calls) == ["ADV-1", "ADV-2", "ADV-3"]
    assert (await search_updates(api, offset=2))["items"][0]["system_id"] == 3
    assert (await search_updates(api, offset=100))["items"] == []
    api.errata_rows[1] = [{"bad": 1}]
    with pytest.raises(ValueError, match="without an ID"):
        await search_updates(api)
    api.outdated.clear()
    assert (await search_updates(api))["items"] == []

    api.outdated = [{"id": 1, "name": "host-1", "outdated_pkg_count": True}]
    with pytest.raises(ValueError, match="invalid outdated package count"):
        await search_updates(api)

    api.outdated = [{"id": 1, "name": "host-1", "outdated_pkg_count": 3}] * 2
    with pytest.raises(ValueError, match="duplicate out-of-date system"):
        await search_updates(api)


@pytest.mark.asyncio
async def test_detailed_search_expands_only_visible_bounded_updates(monkeypatch):
    api = UpdateApi()
    api.errata_rows[1] = [erratum(number) for number in range(30)]
    requested = []

    async def fake_list_cves(self, advisory_name):
        requested.append(advisory_name)
        return []

    monkeypatch.setattr(UpdateApi, "list_cves", fake_list_cves)
    result = await search_updates(api, response_format="detailed", limit=1)
    assert len(result["items"][0]["updates"]) == 5
    assert result["items"][0]["updates_truncated"] is True
    assert requested == [f"ADV-{number}" for number in range(5)]
    assert result["page"]["has_more"] is True


class AuditApi:
    def __init__(self):
        self.calls = []
        self.audit = self
        self.errata = NeededErrataApi()
        self.rows = [
            {"system_id": sid, "patch_status": status,
             "channel_labels": ["base"], "errata_advisories": ["ADV-1"]}
            for sid, status in enumerate((
                "AFFECTED_PATCH_INAPPLICABLE", "AFFECTED_PATCH_APPLICABLE",
                "NOT_AFFECTED", "PATCHED"), 1)
        ]
        self.rows.append({
            "system_id": 5,
            "patch_status": "AFFECTED_PARTIAL_PATCH_APPLICABLE",
            "channel_labels": ["base"],
            "errata_advisories": ["ADV-2"],
        })

    async def list_systems_by_patch_status(self, cve, statuses=None):
        self.calls.append((cve, statuses))
        if statuses is None:
            return self.rows
        accepted = set(statuses)
        if "AFFECTED_PATCH_APPLICABLE" in accepted:
            accepted.add("AFFECTED_FULL_PATCH_APPLICABLE")
        return [row for row in self.rows if row["patch_status"] in accepted]


class NeededErrataApi:
    def __init__(self):
        self.calls = []
        self.advisories = [{"advisory_name": "ADV-1"}, {"advisory_name": "ADV-2"}]
        self.affected = {
            "ADV-1": [{"id": 2, "name": "host-b"}, {"id": 5, "name": "host-e"}],
            "ADV-2": [{"id": 5, "name": "host-e"}],
        }

    async def find_by_cve(self, cve):
        self.calls.append(("find", cve))
        return self.advisories

    async def list_affected_systems(self, advisory):
        self.calls.append(("affected", advisory))
        return self.affected[advisory]


@pytest.mark.asyncio
async def test_cve_native_statuses_and_metadata(monkeypatch):
    api = AuditApi()
    errata = NeededErrataApi()
    api.errata = errata
    default = await search_cve_systems(api, " cve-2026-1234 ")
    assert [row["system_id"] for row in default["items"]] == [2, 5]
    assert [row["system_name"] for row in default["items"]] == ["host-b", "host-e"]
    assert api.calls[-1] == ("CVE-2026-1234", None)
    assert errata.calls == [
        ("find", "CVE-2026-1234"), ("affected", "ADV-1"), ("affected", "ADV-2"),
    ]
    # Audit reports an inapplicable system, but needed-errata membership
    # determines the default result set.
    assert 1 not in [row["system_id"] for row in default["items"]]
    errata.calls.clear()
    for status in ("AFFECTED_PATCH_INAPPLICABLE", "AFFECTED_PATCH_APPLICABLE",
                   "NOT_AFFECTED", "PATCHED"):
        result = await search_cve_systems(api, "CVE-2026-1234", [status])
        assert result["items"][0]["patch_status"] == status
        assert result["items"][0]["channel_labels"] == ["base"]
        assert result["items"][0]["errata_advisories"] == ["ADV-1"]
        assert api.calls[-1][1] == [status]
    assert errata.calls == []
    page = await search_cve_systems(api, "CVE-2026-1234", [
        "AFFECTED_PATCH_INAPPLICABLE", "AFFECTED_PATCH_APPLICABLE",
        "NOT_AFFECTED", "PATCHED",
    ], limit=1)
    assert page["page"]["mode"] == "response_only"
    assert page["page"]["has_more"] is True
    assert (await search_cve_systems(api, "CVE-2026-1234", []))["items"] == []
    # The Java handler maps this documented filter to a newer source enum.
    api.rows[1]["patch_status"] = "AFFECTED_FULL_PATCH_APPLICABLE"
    api.rows[1]["channel_labels"] = ["security"]
    api.rows[1]["errata_advisories"] = ["ADV-2"]
    mapped = await search_cve_systems(api, "CVE-2026-1234", ["AFFECTED_PATCH_APPLICABLE"])
    assert mapped["items"][0]["patch_status"] == "AFFECTED_FULL_PATCH_APPLICABLE"
    assert mapped["items"][0]["errata_advisories"] == ["ADV-2"]
    assert [row["system_id"] for row in mapped["items"]] == [2]
    api.rows[0]["channel_labels"] = "bad"
    with pytest.raises(ValueError, match="invalid CVE audit"):
        await search_cve_systems(api, "CVE-2026-1234", ["AFFECTED_PATCH_INAPPLICABLE"])


@pytest.mark.asyncio
async def test_cve_default_empty_and_missing_audit_data(monkeypatch):
    api = AuditApi()
    errata = NeededErrataApi()
    api.errata = errata
    errata.advisories = []
    empty = await search_cve_systems(api, "CVE-2026-1234")
    assert empty["items"] == []
    assert empty["page"]["mode"] == "response_only"
    assert api.calls == []

    errata.advisories = [{"advisory_name": "ADV-3"}]
    errata.affected["ADV-3"] = [{"id": 99, "name": "host-z"}]
    result = await search_cve_systems(api, "CVE-2026-1234")
    assert result["items"] == [{
        "system_id": 99, "system_name": "host-z", "patch_status": None,
        "channel_labels": [], "errata_advisories": [],
    }]
    assert result["warnings"] == ["Audit data unavailable for 1 matching systems"]


@pytest.mark.asyncio
async def test_cve_default_propagates_audit_enrichment_failure(monkeypatch):
    api = AuditApi()
    errata = NeededErrataApi()
    api.errata = errata

    async def failed_audit(cve, statuses=None):
        raise UnexpectedResponse("audit/listSystemsByPatchStatus", "CVE cache unavailable")

    api.list_systems_by_patch_status = failed_audit
    with pytest.raises(UnexpectedResponse, match="CVE cache unavailable"):
        await search_cve_systems(api, "CVE-2026-1234")
    with pytest.raises(UnexpectedResponse):
        await search_cve_systems(api, "CVE-2026-1234", ["PATCHED"])
