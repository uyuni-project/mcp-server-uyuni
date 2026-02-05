import pytest
import respx
import httpx
from httpx import Response
import os
import sys
import json
from unittest.mock import MagicMock, AsyncMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

os.environ.setdefault("UYUNI_SERVER", "mock-server.local")
os.environ.setdefault("UYUNI_USER", "mock-user")
os.environ.setdefault("UYUNI_PASS", "mock-pass")
os.environ.setdefault("UYUNI_MCP_WRITE_TOOLS_ENABLED", "true")
os.environ.setdefault("UYUNI_MCP_SSL_VERIFY", "false")

from mcp_server_uyuni import server
from mcp_server_uyuni.errors import HTTPError, AuthError, NotFoundError, UnexpectedResponse

@pytest.fixture
def mock_ctx():
    """Fixture for the MCP context."""
    ctx = MagicMock()
    ctx.info = AsyncMock()
    ctx.error = AsyncMock()
    ctx.warning = AsyncMock()
    ctx.report_progress = AsyncMock()
    ctx.get_state.return_value = "mock_token"
    ctx.session.check_client_capability.return_value = False
    return ctx

@pytest.fixture
def mock_uyuni(respx_mock):
    """Fixture to mock Uyuni API calls using respx."""
    base_url = server.CONFIG["UYUNI_SERVER"]

    respx_mock.post(f"{base_url}/rhn/manager/api/oidcLogin").mock(
        return_value=Response(200, json={"success": True, "message": "Logged in"})
    )

    return respx_mock

@pytest.mark.asyncio
async def test_list_systems(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    mock_data = [
        {"id": 1001, "name": "system1.example.com", "last_boot": "2023-01-01"},
        {"id": 1002, "name": "system2.example.com", "last_boot": "2023-01-02"},
    ]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._list_systems("mock_token")

    assert len(result) == 2
    assert result[0]['system_name'] == "system1.example.com"
    assert result[0]['system_id'] == 1001
    assert route.called

@pytest.mark.asyncio
async def test_get_system_details(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001

    mock_details = {
        "id": 1001,
        "profile_name": "system1.example.com",
        "last_boot": "2023-10-27 10:00:00",
    }
    mock_uuid = "550e8400-e29b-41d4-a716-446655440000"
    mock_cpu = {
        "id": 1001,
        "family": "6",
        "model": "Intel Xeon",
        "vendor": "GenuineIntel",
        "mhz": "2500.000",
        "arch": "x86_64"
    }
    mock_network = {
        "id": 1001,
        "hostname": "system1.example.com",
        "ip": "192.168.1.10",
        "ip6": "fe80::1"
    }
    mock_products = [
        {"friendlyName": "SLES 15 SP4", "isBaseProduct": True}
    ]

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getDetails").mock(return_value=Response(200, json={"success": True, "result": mock_details}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUuid").mock(return_value=Response(200, json={"success": True, "result": mock_uuid}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getCpu").mock(return_value=Response(200, json={"success": True, "result": mock_cpu}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getNetwork").mock(return_value=Response(200, json={"success": True, "result": mock_network}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getInstalledProducts").mock(return_value=Response(200, json={"success": True, "result": mock_products}))

    result = await server._get_system_details(system_id, "mock_token")

    assert result['system_name'] == "system1.example.com"
    assert result['cpu']['model'] == "Intel Xeon"
    assert result['network']['ip'] == "192.168.1.10"
    assert result['installed_products'] == ["SLES 15 SP4"]

@pytest.mark.asyncio
async def test_add_system(mock_uyuni, mock_ctx, monkeypatch):
    base_url = server.CONFIG["UYUNI_SERVER"]
    monkeypatch.setenv("UYUNI_SSH_PRIV_KEY", "secret_key")
    monkeypatch.setenv("UYUNI_SSH_PRIV_KEY_PASS", "passphrase")

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": []})
    )

    result = await server._add_system(
        host="new-system",
        activation_key="1-KEY",
        ctx=mock_ctx,
        confirm=False
    )
    assert "CONFIRMATION REQUIRED" in result

    route_bootstrap = mock_uyuni.post(f"{base_url}/rhn/manager/api/system/bootstrapWithPrivateSshKey").mock(
        return_value=Response(200, json={"success": True, "result": 1})
    )

    result = await server._add_system(
        host="new-system",
        activation_key="1-KEY",
        ctx=mock_ctx,
        confirm=True
    )
    assert "successfully scheduled" in result
    assert route_bootstrap.called

    payload = json.loads(route_bootstrap.calls.last.request.content)
    assert payload['host'] == "new-system"
    assert payload['activationKey'] == "1-KEY"
    assert payload['sshPrivKey'] == "secret_key"
    assert payload['sshPrivKeyPass'] == "passphrase"

@pytest.mark.asyncio
async def test_get_system_updates(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001

    mock_relevant = [
        {"id": 501, "advisory_name": "SUSE-RU-2023:1234", "advisory_type": "Security Advisory", "advisory_synopsis": "Fixes stuff"}
    ]
    mock_unscheduled = []
    mock_cves = ["CVE-2023-0001"]

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getRelevantErrata").mock(return_value=Response(200, json={"success": True, "result": mock_relevant}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUnscheduledErrata").mock(return_value=Response(200, json={"success": True, "result": mock_unscheduled}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/errata/listCves").mock(return_value=Response(200, json={"success": True, "result": mock_cves}))

    result = await server._get_system_updates(system_id, mock_ctx)

    assert result['has_pending_updates'] is True
    assert result['update_count'] == 1
    assert result['updates'][0]['advisory_name'] == "SUSE-RU-2023:1234"
    assert result['updates'][0]['cves'] == ["CVE-2023-0001"]

@pytest.mark.asyncio
async def test_get_system_event_history(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001
    limit = 10
    offset = 0

    mock_data = [
        {"summary":"Hardware List Refresh scheduled by (system)","details":"","completed":"2026-01-10T04:00:07Z"}
    ]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getEventHistory").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._get_system_event_history(system_id, limit, offset, None, "mock_token")

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]['summary'] == "Hardware List Refresh scheduled by (system)"

    assert route.called
    assert route.calls.last.request.url.params['sid'] == str(system_id)

@pytest.mark.asyncio
async def test_schedule_specific_update(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001
    errata_id = 501

    route = mock_uyuni.post(f"{base_url}/rhn/manager/api/system/scheduleApplyErrata").mock(
        return_value=Response(200, json={"success": True, "result": [12345]})
    )

    result = await server._schedule_specific_update(system_id, errata_id, mock_ctx, confirm=False)
    assert "CONFIRMATION REQUIRED" in result

    result = await server._schedule_specific_update(system_id, errata_id, mock_ctx, confirm=True)
    assert "successfully scheduled" in result
    assert route.called

@pytest.mark.asyncio
async def test_schedule_pending_updates_to_system(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001

    mock_relevant = [
        {"id": 501, "advisory_name": "SUSE-RU-2023:1234", "advisory_type": "Security Advisory", "advisory_synopsis": "Fixes stuff"}
    ]
    mock_unscheduled = []
    mock_cves = ["CVE-2023-0001"]

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getRelevantErrata").mock(return_value=Response(200, json={"success": True, "result": mock_relevant}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUnscheduledErrata").mock(return_value=Response(200, json={"success": True, "result": mock_unscheduled}))
    mock_uyuni.get(f"{base_url}/rhn/manager/api/errata/listCves").mock(return_value=Response(200, json={"success": True, "result": mock_cves}))

    route_schedule = mock_uyuni.post(f"{base_url}/rhn/manager/api/system/scheduleApplyErrata").mock(
        return_value=Response(200, json={"success": True, "result": [12345]})
    )

    result = await server._schedule_pending_updates_to_system(system_id, mock_ctx, confirm=False)
    assert "CONFIRMATION REQUIRED" in result

    result = await server._schedule_pending_updates_to_system(system_id, mock_ctx, confirm=True)
    assert "successfully scheduled" in result
    assert route_schedule.called

    payload = json.loads(route_schedule.calls.last.request.content)
    assert payload['sid'] == system_id
    assert payload['errataIds'] == [501]

@pytest.mark.asyncio
async def test_remove_system(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": [{"id": 1001, "name": "sys1"}]})
    )

    route_delete = mock_uyuni.post(f"{base_url}/rhn/manager/api/system/deleteSystem").mock(
        return_value=Response(200, json={"success": True, "result": 1})
    )

    result = await server._remove_system(system_id, mock_ctx, confirm=False)
    assert "CONFIRMATION REQUIRED" in result

    result = await server._remove_system(system_id, mock_ctx, confirm=True)
    assert "successfully removed" in result
    assert route_delete.called

@pytest.mark.asyncio
async def test_schedule_system_reboot(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001

    route_reboot = mock_uyuni.post(f"{base_url}/rhn/manager/api/system/scheduleReboot").mock(
        return_value=Response(200, json={"success": True, "result": 12346})
    )

    result = await server._schedule_system_reboot(system_id, mock_ctx, confirm=False)
    assert "CONFIRMATION REQUIRED" in result

    result = await server._schedule_system_reboot(system_id, mock_ctx, confirm=True)
    assert "successfully scheduled" in result
    assert route_reboot.called

@pytest.mark.asyncio
async def test_cancel_action(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    action_id = 12345

    route = mock_uyuni.post(f"{base_url}/rhn/manager/api/schedule/cancelActions").mock(
        return_value=Response(200, json={"success": True, "result": 1})
    )

    result = await server._cancel_action(action_id, mock_ctx, confirm=False)
    assert "CONFIRMATION REQUIRED" in result

    result = await server._cancel_action(action_id, mock_ctx, confirm=True)
    assert "Successfully canceled action" in result
    assert route.called

@pytest.mark.asyncio
async def test_create_system_group(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    group_name = "new-group"
    description = "description"

    route_create = mock_uyuni.post(f"{base_url}/rhn/manager/api/systemgroup/create").mock(
        return_value=Response(200, json={"success": True, "result": {"id": 101, "name": group_name}})
    )

    result = await server._create_system_group(group_name, mock_ctx, description=description, confirm=False)
    assert "CONFIRMATION REQUIRED" in result

    result = await server._create_system_group(group_name, mock_ctx, description=description, confirm=True)
    assert "Successfully created system group" in result
    assert route_create.called

@pytest.mark.asyncio
async def test_list_group_systems(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    group_name = "my-group"

    mock_data = [
        {"id": 1001, "name": "system1.example.com"},
        {"id": 1002, "name": "system2.example.com"}
    ]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/systemgroup/listSystemsMinimal").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._list_group_systems(group_name, "mock_token")

    assert len(result) == 2
    assert result[0]['system_name'] == "system1.example.com"
    assert route.called
    assert route.calls.last.request.url.params['systemGroupName'] == group_name

@pytest.mark.asyncio
async def test_add_systems_to_group(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    group_name = "my-group"
    system_ids = [1001, 1002]

    route_add = mock_uyuni.post(f"{base_url}/rhn/manager/api/systemgroup/addOrRemoveSystems").mock(
        return_value=Response(200, json={"success": True, "result": 1})
    )

    result = await server._manage_group_systems(group_name, system_ids, True, mock_ctx, confirm=False)
    assert "CONFIRMATION REQUIRED" in result

    result = await server._manage_group_systems(group_name, system_ids, True, mock_ctx, confirm=True)
    assert "Successfully added" in result
    assert route_add.called

    payload = json.loads(route_add.calls.last.request.content)
    assert payload['add'] is True
    assert payload['serverIds'] == system_ids

@pytest.mark.asyncio
async def test_remove_systems_from_group(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    group_name = "my-group"
    system_ids = [1001]

    route_remove = mock_uyuni.post(f"{base_url}/rhn/manager/api/systemgroup/addOrRemoveSystems").mock(
        return_value=Response(200, json={"success": True, "result": 1})
    )

    result = await server._manage_group_systems(group_name, system_ids, False, mock_ctx, confirm=False)
    assert "CONFIRMATION REQUIRED" in result

    result = await server._manage_group_systems(group_name, system_ids, False, mock_ctx, confirm=True)
    assert "Successfully removed" in result
    assert route_remove.called

    payload = json.loads(route_remove.calls.last.request.content)
    assert payload['add'] is False
    assert payload['serverIds'] == system_ids

@pytest.mark.asyncio
async def test_get_system_event_details(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001
    event_id = 123

    mock_details = {
        "id": 123,
        "history_type": "System reboot",
        "status": "Completed",
        "summary": "System reboot scheduled by admin",
        "completed": "2025-11-27T15:37:28Z"
    }

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getEventDetails").mock(
        return_value=Response(200, json={"success": True, "result": mock_details})
    )

    result = await server._get_system_event_details(system_id, event_id, "mock_token")

    assert result['id'] == 123
    assert result['history_type'] == "System reboot"
    assert route.called
    assert route.calls.last.request.url.params['sid'] == str(system_id)
    assert route.calls.last.request.url.params['eid'] == str(event_id)

@pytest.mark.asyncio
async def test_find_systems_by_name(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    name = "system1"

    mock_data = [
        {"id": 1001, "name": "system1.example.com"},
    ]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/search/hostname").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._find_systems_by_name(name, mock_ctx)

    assert len(result) == 1
    assert result[0]['system_name'] == "system1.example.com"
    assert route.called
    assert route.calls.last.request.url.params['searchTerm'] == name

@pytest.mark.asyncio
async def test_find_systems_by_ip(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    ip = "192.168.1.10"

    mock_data = [
        {"id": 1001, "name": "system1.example.com", "ip": "192.168.1.10"},
    ]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/search/ip").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._find_systems_by_ip(ip, mock_ctx)

    assert len(result) == 1
    assert result[0]['system_name'] == "system1.example.com"
    assert result[0]['ip'] == "192.168.1.10"
    assert route.called
    assert route.calls.last.request.url.params['searchTerm'] == ip

@pytest.mark.asyncio
async def test_check_all_systems_for_updates(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]

    # Mock list systems
    mock_systems = [{"id": 1001, "name": "system1"}]
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": mock_systems})
    )

    # Mock updates for system 1001
    mock_relevant = [{"id": 501, "advisory_name": "ADV-1"}]
    mock_unscheduled = []
    mock_cves = ["CVE-1"]

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getRelevantErrata").mock(
        return_value=Response(200, json={"success": True, "result": mock_relevant})
    )
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUnscheduledErrata").mock(
        return_value=Response(200, json={"success": True, "result": mock_unscheduled})
    )
    mock_uyuni.get(f"{base_url}/rhn/manager/api/errata/listCves").mock(
        return_value=Response(200, json={"success": True, "result": mock_cves})
    )

    result = await server._check_all_systems_for_updates(mock_ctx)

    assert len(result) == 1
    assert result[0]['system_id'] == 1001
    assert result[0]['update_count'] == 1
    assert result[0]['updates'][0]['cves'] == ["CVE-1"]

@pytest.mark.asyncio
async def test_list_systems_needing_update_for_cve(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    cve = "CVE-2023-1234"

    mock_errata = [{"advisory_name": "ADV-1"}]
    mock_affected = [{"id": 1001, "name": "system1"}]

    mock_uyuni.get(f"{base_url}/rhn/manager/api/errata/findByCve").mock(
        return_value=Response(200, json={"success": True, "result": mock_errata})
    )
    mock_uyuni.get(f"{base_url}/rhn/manager/api/errata/listAffectedSystems").mock(
        return_value=Response(200, json={"success": True, "result": mock_affected})
    )

    result = await server._list_systems_needing_update_for_cve(cve, mock_ctx)

    assert len(result) == 1
    assert result[0]['system_id'] == 1001
    assert result[0]['cve_identifier'] == cve

@pytest.mark.asyncio
async def test_list_systems_needing_reboot(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]

    mock_data = [{"id": 1001, "name": "system1"}]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSuggestedReboot").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._list_systems_needing_reboot(mock_ctx)

    assert len(result) == 1
    assert result[0]['system_id'] == 1001
    assert result[0]['reboot_status'] == 'reboot_required'
    assert route.called

@pytest.mark.asyncio
async def test_list_all_scheduled_actions(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]

    mock_data = [{"id": 123, "name": "Reboot"}]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/schedule/listAllActions").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._list_all_scheduled_actions(mock_ctx)

    assert len(result) == 1
    assert result[0]['action_id'] == 123
    assert route.called

@pytest.mark.asyncio
async def test_list_activation_keys(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]

    mock_data = [{"key": "1-KEY", "description": "My Key"}]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/activationkey/listActivationKeys").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._list_activation_keys(mock_ctx)

    assert len(result) == 1
    assert result[0]['key'] == "1-KEY"
    assert route.called

@pytest.mark.asyncio
async def test_get_unscheduled_errata(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 1001

    mock_data = [{"advisory_name": "ADV-1"}]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getUnscheduledErrata").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._get_unscheduled_errata(system_id, mock_ctx)

    assert len(result) == 1
    assert result[0]['advisory_name'] == "ADV-1"
    assert result[0]['system_id'] == system_id
    assert route.called
    assert route.calls.last.request.url.params['sid'] == str(system_id)

@pytest.mark.asyncio
async def test_list_system_groups(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]

    mock_data = [{"id": 10, "name": "group1", "description": "desc", "system_count": 5}]

    route = mock_uyuni.get(f"{base_url}/rhn/manager/api/systemgroup/listAllGroups").mock(
        return_value=Response(200, json={"success": True, "result": mock_data})
    )

    result = await server._list_system_groups(mock_ctx)

    assert len(result) == 1
    assert result[0]['id'] == "10"
    assert result[0]['name'] == "group1"
    assert route.called

@pytest.mark.asyncio
async def test_api_error_500(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(500, text="Internal Server Error")
    )
    with pytest.raises(HTTPError) as excinfo:
        await server._list_systems("mock_token")
    assert excinfo.value.status_code == 500

@pytest.mark.asyncio
async def test_auth_failure_401(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]
    # Override the default login mock
    mock_uyuni.post(f"{base_url}/rhn/manager/api/oidcLogin").mock(
        return_value=Response(401, text="Unauthorized")
    )
    with pytest.raises(AuthError) as excinfo:
        await server._list_systems("mock_token")
    assert excinfo.value.status_code == 401

@pytest.mark.asyncio
async def test_add_system_already_exists(mock_uyuni, mock_ctx, monkeypatch):
    base_url = server.CONFIG["UYUNI_SERVER"]
    monkeypatch.setenv("UYUNI_SSH_PRIV_KEY", "secret")

    # Mock listSystems to return existing system
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": [{"id": 1001, "name": "existing-system"}]})
    )

    result = await server._add_system("existing-system", mock_ctx, activation_key="key")
    assert "already exists" in result

@pytest.mark.asyncio
async def test_add_system_missing_ssh_key(mock_uyuni, mock_ctx, monkeypatch):
    base_url = server.CONFIG["UYUNI_SERVER"]
    monkeypatch.delenv("UYUNI_SSH_PRIV_KEY", raising=False)

    # Mock listSystems (empty)
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": []})
    )

    result = await server._add_system("new-system", mock_ctx, activation_key="key", confirm=True)
    assert "UYUNI_SSH_PRIV_KEY environment variable is not set" in result

@pytest.mark.asyncio
async def test_add_system_timeout(mock_uyuni, mock_ctx, monkeypatch):
    base_url = server.CONFIG["UYUNI_SERVER"]
    monkeypatch.setenv("UYUNI_SSH_PRIV_KEY", "secret")

    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": []})
    )

    # Mock bootstrap to raise TimeoutException
    mock_uyuni.post(f"{base_url}/rhn/manager/api/system/bootstrapWithPrivateSshKey").mock(
        side_effect=httpx.TimeoutException("Timeout")
    )

    result = await server._add_system("new-system", mock_ctx, activation_key="key", confirm=True)
    assert "process started" in result
    assert "may take some time" in result

@pytest.mark.asyncio
async def test_remove_system_not_found(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    system_id = 9999

    # Mock listSystems (does not contain 9999)
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": [{"id": 1001, "name": "sys1"}]})
    )

    result = await server._remove_system(system_id, mock_ctx)
    assert f"System with ID {system_id} not found" in result

@pytest.mark.asyncio
async def test_resolve_system_id_by_name_not_found(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    name = "non-existent"

    # Mock getId returning empty list
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getId").mock(
        return_value=Response(200, json={"success": True, "result": []})
    )

    with pytest.raises(NotFoundError):
        await server._get_system_details(name, "mock_token")

@pytest.mark.asyncio
async def test_resolve_system_id_by_name_multiple_found(mock_uyuni, mock_ctx):
    base_url = server.CONFIG["UYUNI_SERVER"]
    name = "ambiguous"

    # Mock getId returning multiple
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/getId").mock(
        return_value=Response(200, json={"success": True, "result": [{"id": 1}, {"id": 2}]})
    )

    with pytest.raises(UnexpectedResponse) as excinfo:
        await server._get_system_details(name, "mock_token")
    assert "Multiple systems found" in str(excinfo.value)

@pytest.mark.asyncio
async def test_malformed_api_response(mock_uyuni):
    base_url = server.CONFIG["UYUNI_SERVER"]

    # Mock listSystems returning something that is not a list
    mock_uyuni.get(f"{base_url}/rhn/manager/api/system/listSystems").mock(
        return_value=Response(200, json={"success": True, "result": "not-a-list"})
    )

    result = await server._list_systems("mock_token")
    assert result == []

def test_write_tool_disabled(monkeypatch):
    monkeypatch.setitem(server.CONFIG, "UYUNI_MCP_WRITE_TOOLS_ENABLED", False)

    def dummy_func():
        pass

    # When disabled, decorator returns original function
    decorated = server.write_tool()(dummy_func)
    assert decorated is dummy_func

def test_write_tool_enabled(monkeypatch):
    monkeypatch.setitem(server.CONFIG, "UYUNI_MCP_WRITE_TOOLS_ENABLED", True)

    # Mock mcp.tool to verify it wraps the function
    mock_tool_decorator = MagicMock(side_effect=lambda f: f)
    mock_tool_factory = MagicMock(return_value=mock_tool_decorator)

    with patch.object(server.mcp, 'tool', mock_tool_factory):
        def dummy_func():
            pass

        server.write_tool()(dummy_func)
        assert mock_tool_factory.called

@pytest.mark.asyncio
async def test_auth_middleware_extracts_token():
    middleware = server.AuthTokenMiddleware()

    mock_ctx = MagicMock()
    # Mock the nested structure: ctx.fastmcp_context.request_context.request.headers
    mock_ctx.fastmcp_context.request_context.request.headers = {'authorization': 'Bearer my-token'}
    mock_ctx.fastmcp_context.set_state = MagicMock()

    async def call_next(ctx):
        return "ok"

    await middleware.on_call_tool(mock_ctx, call_next)

    mock_ctx.fastmcp_context.set_state.assert_called_with('token', 'my-token')

@pytest.mark.asyncio
async def test_auth_middleware_missing_header():
    middleware = server.AuthTokenMiddleware()

    mock_ctx = MagicMock()
    mock_ctx.fastmcp_context.request_context.request.headers = {}
    mock_ctx.fastmcp_context.set_state = MagicMock()

    async def call_next(ctx):
        return "ok"

    await middleware.on_call_tool(mock_ctx, call_next)

    mock_ctx.fastmcp_context.set_state.assert_called_with('token', None)

@pytest.mark.asyncio
async def test_auth_middleware_malformed_header():
    middleware = server.AuthTokenMiddleware()

    mock_ctx = MagicMock()
    mock_ctx.fastmcp_context.request_context.request.headers = {'authorization': 'Basic user:pass'}
    mock_ctx.fastmcp_context.set_state = MagicMock()

    async def call_next(ctx):
        return "ok"

    await middleware.on_call_tool(mock_ctx, call_next)

    mock_ctx.fastmcp_context.set_state.assert_called_with('token', None)

def test_main_cli_stdio(monkeypatch):
    monkeypatch.setitem(server.CONFIG, "UYUNI_MCP_TRANSPORT", "stdio")

    with patch.object(server.mcp, 'run') as mock_run:
        server.main_cli()
        mock_run.assert_called_with(transport="stdio")

def test_main_cli_http(monkeypatch):
    monkeypatch.setitem(server.CONFIG, "UYUNI_MCP_TRANSPORT", "http")
    monkeypatch.setitem(server.CONFIG, "UYUNI_MCP_HOST", "localhost")
    monkeypatch.setitem(server.CONFIG, "UYUNI_MCP_PORT", 8000)
    monkeypatch.setitem(server.CONFIG, "AUTH_SERVER", None)

    with patch.object(server.mcp, 'run') as mock_run:
        server.main_cli()
        mock_run.assert_called_with(transport="streamable-http", host="localhost", port=8000)