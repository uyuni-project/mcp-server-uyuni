import os

import pytest

os.environ.setdefault("UYUNI_SERVER", "https://mock-server.local")

from mcp_server_uyuni.api.audit import AuditApi
from mcp_server_uyuni.api.client import UyuniSession
from mcp_server_uyuni.api.errata import ErrataApi
from mcp_server_uyuni.api.systems import SystemsApi
from mcp_server_uyuni.errors import UnexpectedResponse


@pytest.mark.asyncio
async def test_update_and_cve_adapter_routes():
    calls = []
    session = UyuniSession()

    async def fake_request(method, path, context, *, params=None, json_body=None):
        calls.append((method, path, params))
        return []

    session.request = fake_request
    systems = SystemsApi(session)
    errata = ErrataApi(session)
    audit = AuditApi(session)
    await systems.list_out_of_date_systems()
    await systems.get_relevant_errata(7)
    await systems.get_relevant_errata_batch([7, 8])
    await systems.get_unscheduled_errata(7)
    await errata.list_cves("ADV-1")
    await errata.find_by_cve("CVE-2026-1234")
    await errata.list_affected_systems("ADV-1")
    await audit.list_systems_by_patch_status("CVE-2026-1234", ["PATCHED"])
    await audit.list_systems_by_patch_status("CVE-2026-1234")
    assert calls == [
        ("GET", "/rhn/manager/api/system/listOutOfDateSystems", None),
        ("GET", "/rhn/manager/api/system/getRelevantErrata", {"sid": 7}),
        ("GET", "/rhn/manager/api/system/getRelevantErrata", {"sids": [7, 8]}),
        ("GET", "/rhn/manager/api/system/getUnscheduledErrata", {"sid": 7}),
        ("GET", "/rhn/manager/api/errata/listCves", {"advisoryName": "ADV-1"}),
        ("GET", "/rhn/manager/api/errata/findByCve", {"cveName": "CVE-2026-1234"}),
        ("GET", "/rhn/manager/api/errata/listAffectedSystems", {"advisoryName": "ADV-1"}),
        ("GET", "/rhn/manager/api/audit/listSystemsByPatchStatus",
         {"cveIdentifier": "CVE-2026-1234", "patchStatusLabels": ["PATCHED"]}),
        ("GET", "/rhn/manager/api/audit/listSystemsByPatchStatus",
         {"cveIdentifier": "CVE-2026-1234"}),
    ]


@pytest.mark.asyncio
async def test_adapters_reject_malformed_response():
    session = UyuniSession()

    async def bad_request(*args, **kwargs):
        return {"unexpected": True}

    session.request = bad_request
    with pytest.raises(UnexpectedResponse):
        await SystemsApi(session).list_out_of_date_systems()
    with pytest.raises(UnexpectedResponse):
        await SystemsApi(session).get_relevant_errata_batch([1])
    with pytest.raises(UnexpectedResponse):
        await ErrataApi(session).list_cves("ADV-1")
    with pytest.raises(UnexpectedResponse):
        await ErrataApi(session).find_by_cve("CVE-2026-1234")
    with pytest.raises(UnexpectedResponse):
        await ErrataApi(session).list_affected_systems("ADV-1")
    with pytest.raises(UnexpectedResponse):
        await AuditApi(session).list_systems_by_patch_status("CVE-2026-1234")
