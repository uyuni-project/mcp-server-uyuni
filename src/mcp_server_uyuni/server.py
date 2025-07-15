# Copyright (c) 2025 SUSE LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Any, List, Dict
import httpx
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP
import os
import sys

# Initialize FastMCP server
mcp = FastMCP("mcp-server-uyuni")

# Global variables for Uyuni connection - to be initialized in __main__
url = ""
username = ""
password = ""

async def _call_uyuni_api(
    client: httpx.AsyncClient,
    method: str,
    api_path: str,
    error_context: str,
    params: Dict[str, Any] = None,
    json_body: Dict[str, Any] = None,
    perform_login: bool = True,
    default_on_error: Any = None,
    expected_result_key: str = 'result'
) -> Any:
    """
    Helper function to make authenticated API calls to Uyuni.
    Handles login, request execution, error handling, and basic response parsing.
    """
    global url, username, password # Access global connection details

    if perform_login:
        login_data = {"login": username, "password": password}
        try:
            login_response = await client.post(url + '/rhn/manager/api/login', json=login_data)
            login_response.raise_for_status()
        except httpx.HTTPStatusError as e:
            print(f"HTTP error during login for {error_context}: {e.request.url} - {e.response.status_code} - {e.response.text}")
            return default_on_error
        except httpx.RequestError as e:
            print(f"Request error during login for {error_context}: {e.request.url} - {e}")
            return default_on_error
        except Exception as e:
            print(f"An unexpected error occurred during login for {error_context}: {e}")
            return default_on_error

    full_api_url = url + api_path
    try:
        if method.upper() == 'GET':
            response = await client.get(full_api_url, params=params)
        elif method.upper() == 'POST':
            response = await client.post(full_api_url, json=json_body, params=params)
        else:
            print(f"Unsupported HTTP method '{method}' for {error_context}.")
            return default_on_error
        
        response.raise_for_status()
        response_data = response.json()

        if response_data.get('success'):
            if expected_result_key in response_data:
                return response_data[expected_result_key]
            # If 'success' is true, but the expected_result_key is not there (e.g. 'result' is missing)
            print(f"API call for {error_context} succeeded but '{expected_result_key}' not found in response. Response: {response_data}")
            return default_on_error
        else:
            print(f"API call for {error_context} reported failure. Response: {response_data}")
            return default_on_error

    except httpx.HTTPStatusError as e:
        print(f"HTTP error occurred while {error_context}: {e.request.url} - {e.response.status_code} - {e.response.text}")
        return default_on_error
    except httpx.RequestError as e:
        print(f"Request error occurred while {error_context}: {e.request.url} - {e}")
        return default_on_error
    except Exception as e: # Catch other potential errors like JSONDecodeError
        print(f"An unexpected error occurred while {error_context}: {e}")
        return default_on_error

@mcp.tool()
async def get_list_of_active_systems() -> List[Dict[str, Any]]:
    """
    Fetches a list of active systems from the Uyuni server, returning their names and IDs.

    The returned list contains dictionaries, each with a 'system_name' (str) and
    a 'system_id' (int) for an active system.

    Returns:
        List[Dict[str, Any]]: A list of system dictionaries (system_name and system_id).
                              Returns an empty list if the API call fails,
                              the response format is unexpected, or no systems are found.
    """
    async with httpx.AsyncClient(verify=False) as client:
        systems_data_result = await _call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/listSystems",
            error_context="fetching active systems",
            default_on_error=[]
        )

    filtered_systems = []
    if isinstance(systems_data_result, list):
        for system in systems_data_result:
            if isinstance(system, dict):
                filtered_systems.append({'system_name': system.get('name'), 'system_id': system.get('id')})
            else:
                print(f"Warning: Unexpected item format in system list: {system}")
    elif systems_data_result: # Log if not the default empty list but still not a list
        print(f"Warning: Expected a list of systems, but received: {type(systems_data_result)}")

    return filtered_systems

@mcp.tool()
async def get_cpu_of_a_system(system_id: int) -> Dict[str, Any]:
    """Retrieves detailed CPU information for a specific system in the Uyuni server.

    Fetches CPU attributes such as model, core count, architecture, etc.

    Args:
        system_id: The unique identifier of the system.

    Returns:
        Dict[str, Any]: A dictionary containing the CPU attributes.
                        Returns an empty dictionary if the API call fails,
                        the response format is unexpected, or CPU data is not available.
    """
    async with httpx.AsyncClient(verify=False) as client:
        cpu_data_result = await _call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getCpu",
            params={'sid': str(system_id)},
            error_context=f"fetching CPU data for system ID {system_id}",
            default_on_error={}
        )

    if isinstance(cpu_data_result, dict):
        return cpu_data_result
    # If not a dict but not the default empty dict, log it
    elif cpu_data_result:
         print(f"Warning: Expected a dict for CPU data, but received: {type(cpu_data_result)}")
    return {}

@mcp.tool()
async def get_all_systems_cpu_info() -> List[Dict[str, Any]]:
    """
    Retrieves CPU information for all active systems in the Uyuni server.

    For each active system, this tool fetches its name, ID, and detailed CPU attributes.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries. Each dictionary contains:
                              - 'system_name' (str): The name of the system.
                              - 'system_id' (int): The unique ID of the system.
                              - 'cpu_info' (Dict[str, Any]): CPU attributes for the system.
                              Returns an empty list if no systems are found or if
                              fetching system list fails. Individual system CPU fetch
                              failures will result in empty 'cpu_info' for that system.
    """
    all_systems_cpu_data = []
    active_systems = await get_list_of_active_systems() # Calls your existing tool

    if not active_systems:
        print("Warning: No active systems found or failed to retrieve system list.")
        return []

    for system_summary in active_systems:
        system_id = system_summary.get('system_id')
        system_name = system_summary.get('system_name')

        if system_id is None:
            print(f"Warning: Skipping system due to missing ID: {system_summary}")
            continue

        print(f"Fetching CPU info for system: {system_name} (ID: {system_id})")
        cpu_info = await get_cpu_of_a_system(system_id) # Calls your other existing tool

        all_systems_cpu_data.append({
            'system_name': system_name,
            'system_id': system_id,
            'cpu_info': cpu_info
        })

    return all_systems_cpu_data

async def _fetch_cves_for_erratum(client: httpx.AsyncClient, advisory_name: str, system_id: int, list_cves_path: str) -> List[str]:
    """
    Internal helper to fetch CVEs for a given erratum advisory name.

    Args:
        client: The httpx.AsyncClient instance (must have active login session).
        advisory_name: The advisory name of the erratum to fetch CVEs for.
        system_id: The ID of the system (for logging purposes).
        list_cves_path: The API path for listing CVEs.

    Returns:
        List[str]: A list of CVE identifier strings. Returns an empty list on failure or if no CVEs are found.
    """
    if not advisory_name:
        print(f"Warning: advisory_name is missing for system ID {system_id}, cannot fetch CVEs.")
        return []

    print(f"Fetching CVEs for advisory: {advisory_name} (system ID: {system_id})")
    cve_list_from_api = await _call_uyuni_api(
        client=client,
        method="GET",
        api_path=list_cves_path,
        error_context=f"fetching CVEs for advisory {advisory_name} (system ID: {system_id})",
        params={'advisoryName': advisory_name},
        perform_login=False, # Login is handled by the calling function
        default_on_error=None # Distinguish API error (None) from empty list []
    )

    processed_cves = []
    if isinstance(cve_list_from_api, list):
        processed_cves = [str(cve) for cve in cve_list_from_api if cve]
    elif cve_list_from_api is None:
        # This means the API call might have failed OR API returned "result": null successfully.
        # _call_uyuni_api would return default_on_error (None) on failure.
        # If API returns "result": null, helper returns None. In both cases, processed_cves remains [].
        pass

    return processed_cves

@mcp.tool()
async def check_system_updates(system_id: int) -> Dict[str, Any]:
    """
    Checks if a specific system in the Uyuni server has pending updates (relevant errata),
    including associated CVEs for each update.

    Args:
        system_id: The unique identifier of the system.

    Returns:
        Dict[str, Any]: A dictionary containing:
                        - 'system_id' (int): The ID of the system checked.
                        - 'has_pending_updates' (bool): True if there are pending updates, False otherwise.
                        - 'update_count' (int): The number of pending updates.
                        - 'updates' (List[Dict[str, Any]]): A list of pending update details.
                          Each update dictionary will also include a 'cves' key
                          containing a list of CVE identifiers associated with that update.
                        Returns a dictionary with 'has_pending_updates': False and empty 'updates'
                        if the API call fails or the format is unexpected.
    """
    default_error_response = {
        'system_id': system_id,
        'has_pending_updates': False,
        'update_count': 0,
        'updates': []
    }
    list_cves_api_path = '/rhn/manager/api/errata/listCves'

    async with httpx.AsyncClient(verify=False) as client:
        updates_list_from_api = await _call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getRelevantErrata",
            params={'sid': str(system_id)},
            error_context=f"checking updates for system ID {system_id}",
            default_on_error=None # Distinguish API error from empty list
        )

        if updates_list_from_api is None: # API call failed or unexpected success format
            return default_error_response
        
        if not isinstance(updates_list_from_api, list):
            print(f"Warning: Expected a list of updates for system ID {system_id}, but received: {type(updates_list_from_api)}")
            return default_error_response

        enriched_updates_list = []

        for erratum_api_data in updates_list_from_api:
            # Create a new dictionary for the update, renaming 'id' to 'update_id'
            update_details = dict(erratum_api_data) # Start with a copy

            # Rename 'id' to 'update_id'
            if 'id' in update_details:
                update_details['update_id'] = update_details.pop('id')
            else:
                # This case is unlikely for errata from the API but good for robustness
                update_details['update_id'] = None

            advisory_name = update_details.get('advisory_name')
            
            # Initialize and fetch CVEs
            update_details['cves'] = []
            if advisory_name:
                # Call the helper function to fetch CVEs
                update_details['cves'] = await _fetch_cves_for_erratum(client, advisory_name, system_id, list_cves_api_path)
            
            enriched_updates_list.append(update_details)
        
        return {
            'system_id': system_id,
            'has_pending_updates': len(enriched_updates_list) > 0,
            'update_count': len(enriched_updates_list),
            'updates': enriched_updates_list
        }

@mcp.tool()
async def check_all_systems_for_updates() -> List[Dict[str, Any]]:
    """
    Checks all active systems in the Uyuni server for pending updates.

    Returns a list containing information only for those systems that have
    one or more pending updates. Each update detail will include associated CVEs.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries. Each dictionary represents
                              a system with pending updates and includes:
                              - 'system_name' (str): The name of the system.
                              - 'system_id' (int): The unique ID of the system.
                              - 'update_count' (int): The number of pending updates.
                              - 'updates' (List[Dict[str, Any]]): A list of pending update details.
                                Each update dictionary in this list will also contain a 'cves' key
                                with a list of associated CVE identifiers.
                              Returns an empty list if no systems are found,
                              fetching the system list fails, or no systems have updates.
    """
    systems_with_updates = []
    active_systems = await get_list_of_active_systems() # Get the list of all systems

    if not active_systems:
        print("Warning: No active systems found or failed to retrieve system list.")
        return []

    print(f"Checking {len(active_systems)} systems for updates...")

    for system_summary in active_systems:
        system_id = system_summary.get('system_id')
        system_name = system_summary.get('system_name')

        if system_id is None:
            print(f"Warning: Skipping system due to missing ID: {system_summary}")
            continue

        print(f"Checking updates for system: {system_name} (ID: {system_id})")
        # Use the existing check_system_updates tool
        update_check_result = await check_system_updates(system_id)

        if update_check_result.get('has_pending_updates', False):
            # If the system has updates, add its info and update details to the result list
            systems_with_updates.append({
                'system_name': system_name,
                'system_id': system_id,
                'update_count': update_check_result.get('update_count', 0),
                'updates': update_check_result.get('updates', [])
            })
        # else: System has no updates, do nothing for this system

    print(f"Finished checking systems. Found {len(systems_with_updates)} systems with updates.")
    return systems_with_updates

@mcp.tool()
async def schedule_apply_pending_updates_to_system(system_id: int, confirm: bool = False) -> str:
    """
    Checks for pending updates on a system, schedules all of them to be applied,
    and returns the action ID of the scheduled task.

    This tool first calls 'check_system_updates' to determine relevant errata.
    If updates are found, it then calls the 'system/scheduleApplyErrata' API
    endpoint to apply all found errata.

    Args:
        system_id: The unique identifier of the system.
        confirm: False by default. Only set confirm to True if the user has explicetely confirmed. Ask the user for confirmation.

    Returns:
        str: The action url if updates were successfully scheduled.
             Otherwise, returns an empty string.
    """
    print(f"Attempting to apply pending updates for system ID: {system_id}")

    if not confirm:
        return f"CONFIRMATION REQUIRED: This will apply pending updates to the system {system_id}.  Do you confirm?"

    # 1. Use check_system_updates to get relevant errata
    update_info = await check_system_updates(system_id)

    if not update_info or not update_info.get('has_pending_updates'):
        print(f"No pending updates found for system ID {system_id}, or an error occurred while fetching update information.")
        return ""

    errata_list = update_info.get('updates', [])
    if not errata_list:
        # This case should ideally be covered by 'has_pending_updates' being false,
        # but good to have a safeguard.
        print(f"Update check for system ID {system_id} indicated updates, but the updates list is empty.")
        return ""

    errata_ids = [erratum.get('update_id') for erratum in errata_list if erratum.get('update_id') is not None]

    if not errata_ids:
        print(f"Could not extract any valid errata IDs for system ID {system_id} from the update information: {errata_list}")
        return ""

    print(f"Found {len(errata_ids)} errata to apply for system ID {system_id}. IDs: {errata_ids}")

    # 2. Schedule apply errata using the API endpoint
    async with httpx.AsyncClient(verify=False) as client:
        payload = {"sid": system_id, "errataIds": errata_ids}
        api_result = await _call_uyuni_api(
            client=client,
            method="POST",
            api_path="/rhn/manager/api/system/scheduleApplyErrata",
            json_body=payload,
            error_context=f"scheduling errata application for system ID {system_id}",
            default_on_error=None # Helper will return None on error
        )

        if isinstance(api_result, list) and api_result and isinstance(api_result[0], int):
            action_id = api_result[0]
            print(f"Successfully scheduled action {action_id} to apply {len(errata_ids)} errata to system ID {system_id}.")
            return "Update successfully scheduled at " +url + "/rhn/schedule/ActionDetails.do?aid=" + str(action_id)
        else:
            # Error message already printed by _call_uyuni_api if it returned None
            if api_result is not None: # Log if result is not None but also not the expected format
                 print(f"Failed to schedule errata for system ID {system_id} or unexpected API response format. Result: {api_result}")
            return ""

@mcp.tool()
async def schedule_apply_specific_update(system_id: int, errata_id: int, confirm: bool = False) -> str:
    """
    Schedules a specific update (erratum) to be applied to a system.

    Args:
        system_id: The unique identifier of the system.
        errata_id: The unique identifier of the erratum (also referred to as update ID) to be applied.
        confirm: False by default. Only set confirm to True if the user has explicetely confirmed. Ask the user for confirmation.

    Returns:
        str: The action URL if the update was successfully scheduled.
             Otherwise, returns an empty string.
    """
    print(f"Attempting to apply specific update (errata ID: {errata_id}) to system ID: {system_id}")

    if not confirm:
        return f"CONFIRMATION REQUIRED: This will apply specific update (errata ID: {errata_id}) to the system {system_id}. Do you confirm?"

    async with httpx.AsyncClient(verify=False) as client:
        # The API expects a list of errata IDs, even if it's just one.
        payload = {"sid": system_id, "errataIds": [errata_id]}
        api_result = await _call_uyuni_api(
            client=client,
            method="POST",
            api_path="/rhn/manager/api/system/scheduleApplyErrata",
            json_body=payload,
            error_context=f"scheduling specific update (errata ID: {errata_id}) for system ID {system_id}",
            default_on_error=None # Helper returns None on error
        )

        if isinstance(api_result, list) and api_result and isinstance(api_result[0], int):
            action_id = api_result[0]
            success_message = f"Update (errata ID: {errata_id}) successfully scheduled for system ID {system_id}. Action URL: {url}/rhn/schedule/ActionDetails.do?aid={action_id}"
            print(success_message)
            return success_message
        # Some schedule APIs might return int directly in result (though scheduleApplyErrata usually returns a list)
        elif isinstance(api_result, int): # Defensive check
            action_id = api_result
            success_message = f"Update (errata ID: {errata_id}) successfully scheduled. Action URL: {url}/rhn/schedule/ActionDetails.do?aid={action_id}"
            print(success_message)
            return success_message
        else:
            if api_result is not None: # Log if not None but also not expected format
                print(f"Failed to schedule specific update (errata ID: {errata_id}) for system ID {system_id} or unexpected API result format. Result: {api_result}")
            return ""

@mcp.tool()
async def get_systems_needing_security_update_for_cve(cve_identifier: str) -> List[Dict[str, Any]]:
    """
    Finds systems requiring a security update due to a specific CVE identifier.

    This tool identifies systems that are vulnerable to a given Common
    Vulnerabilities and Exposures (CVE) identifier. It first looks up the
    security errata (patches/updates) associated with the CVE. Then, for each
    relevant erratum, it retrieves the list of systems that are affected by
    that erratum's advisory and thus require the security update.

    Args:
        cve_identifier: The CVE identifier string (e.g., "CVE-2008-3270").

    Returns:
        List[Dict[str, Any]]: A list of unique systems affected by the specified CVE.
                              Each dictionary contains 'system_id' (int) and
                              'system_name' (str), and 'cve_identifier' (str)
                              (the CVE for which the system needs an update). Returns an empty list if
                              the CVE is not found, no systems are affected,
                              or an API error occurs.
    """
    affected_systems_map = {}  # Use a dict to store unique systems by ID {system_id: {details}}

    find_by_cve_path = '/rhn/manager/api/errata/findByCve'
    list_affected_systems_path = '/rhn/manager/api/errata/listAffectedSystems'

    async with httpx.AsyncClient(verify=False) as client:
        # 1. Call findByCve (login will be handled by the helper)
        print(f"Searching for errata related to CVE: {cve_identifier}")
        errata_list = await _call_uyuni_api(
            client=client,
            method="GET",
            api_path=find_by_cve_path,
            params={'cveName': cve_identifier},
            error_context=f"finding errata for CVE {cve_identifier}",
            default_on_error=None # Distinguish API error from empty list
        )

        if errata_list is None: # API call failed
            return []
        if not isinstance(errata_list, list):
            print(f"Warning: Expected a list of errata for CVE {cve_identifier}, but received: {type(errata_list)}")
            return []
        if not errata_list:
            print(f"No errata found for CVE {cve_identifier}.")
            return []

        # 2. For each erratum, call listAffectedSystems
        for erratum in errata_list:
            advisory_name = erratum.get('advisory_name')
            if not advisory_name:
                print(f"Skipping erratum due to missing 'advisory_name': {erratum}")
                continue

            print(f"Fetching systems affected by advisory: {advisory_name} (related to CVE: {cve_identifier})")
            systems_data_result = await _call_uyuni_api(
                client=client,
                method="GET",
                api_path=list_affected_systems_path,
                params={'advisoryName': advisory_name},
                error_context=f"listing affected systems for advisory {advisory_name}",
                perform_login=False, # Login already performed for this client session
                default_on_error=None # Distinguish API error from empty list
            )

            if systems_data_result is None: # API call failed for this advisory
                continue # Move to the next advisory
            if not isinstance(systems_data_result, list):
                print(f"Warning: Expected list of affected systems for {advisory_name}, got {type(systems_data_result)}")
                continue

            for system_info in systems_data_result:
                if isinstance(system_info, dict):
                    system_id = system_info.get('id')
                    system_name = system_info.get('name')
                    if system_id is not None and system_name is not None:
                        if system_id not in affected_systems_map: # Add if new
                            affected_systems_map[system_id] = {
                                'system_id': system_id,
                                'system_name': system_name,
                                'cve_identifier': cve_identifier
                            }
                    else:
                        print(f"Warning: Received system data with missing ID or name for advisory {advisory_name}: {system_info}")
                else:
                    print(f"Warning: Unexpected item format in affected systems list for advisory {advisory_name}: {system_info}")

    if not affected_systems_map:
        print(f"No systems found affected by CVE {cve_identifier} after checking all related errata.")
    else:
        print(f"Found {len(affected_systems_map)} unique system(s) affected by CVE {cve_identifier}.")

    return list(affected_systems_map.values())

@mcp.tool()
async def get_systems_needing_reboot() -> List[Dict[str, Any]]:
    """
    Fetches a list of systems from the Uyuni server that require a reboot.

    The returned list contains dictionaries, each with 'system_id' (int),
    'system_name' (str), and 'reboot_status' (str, typically 'reboot_required')
    for a system that has been identified by Uyuni as needing a reboot.

    Returns:
        List[Dict[str, Any]]: A list of system dictionaries (system_id, system_name, reboot_status)
                              for systems requiring a reboot. Returns an empty list
                              if the API call fails, the response format is unexpected,
                              or no systems require a reboot.
    """
    systems_needing_reboot_list = []
    list_reboot_path = '/rhn/manager/api/system/listSuggestedReboot'

    async with httpx.AsyncClient(verify=False) as client:
        reboot_data_result = await _call_uyuni_api(
            client=client,
            method="GET",
            api_path=list_reboot_path,
            error_context="fetching systems needing reboot",
            default_on_error=[] # Return empty list on error
        )

        if isinstance(reboot_data_result, list):
            for system_info in reboot_data_result:
                if isinstance(system_info, dict):
                    system_id = system_info.get('id')
                    system_name = system_info.get('name')
                    if system_id is not None and system_name is not None:
                        systems_needing_reboot_list.append({
                            'system_id': system_id,
                            'system_name': system_name,
                            'reboot_status': 'reboot_required'
                        })
                else:
                    print(f"Warning: Unexpected item format in reboot list: {system_info}")
        elif reboot_data_result: # Log if not default empty list but also not a list
            print(f"Warning: Expected a list for systems needing reboot, but received: {type(reboot_data_result)}")

    return systems_needing_reboot_list

@mcp.tool()
async def schedule_system_reboot(system_id: int, confirm: bool = False) -> str:
    """
    Schedules an immediate reboot for a specific system on the Uyuni server.

    Args:
        system_id: The unique identifier (sid) of the system to be rebooted.
        confirm: False by default. Only set confirm to True if the user has explicetely confirmed. Ask the user for confirmation.

    The reboot is scheduled to occur as soon as possible (effectively "now").
    Returns:
        str: A message indicating the action ID if the reboot was successfully scheduled,
             e.g., "System reboot successfully scheduled. Action ID: 12345".
             Returns an empty string if scheduling fails or an error occurs.
    """
    schedule_reboot_path = '/rhn/manager/api/system/scheduleReboot'

    # Generate current time in ISO 8601 format (UTC)
    now_iso = datetime.now(timezone.utc).isoformat()

    if not confirm:
        return f"CONFIRMATION REQUIRED: This will reboot system {system_id}. Do you confirm?"

    async with httpx.AsyncClient(verify=False) as client:
        payload = {"sid": system_id, "earliestOccurrence": now_iso}
        api_result = await _call_uyuni_api(
            client=client,
            method="POST",
            api_path=schedule_reboot_path,
            json_body=payload,
            error_context=f"scheduling reboot for system ID {system_id}",
            default_on_error=None # Helper returns None on error
        )

        # Uyuni's scheduleReboot API returns an integer action ID directly in 'result'
        if isinstance(api_result, int):
            action_id = api_result
            action_detail_url = f"{url}/rhn/schedule/ActionDetails.do?aid={action_id}"
            success_message = f"System reboot successfully scheduled. Action URL: {action_detail_url}"
            print(success_message)
            return success_message
        else:
            # Error message already printed by _call_uyuni_api if it returned None
            if api_result is not None: # Log if result is not None but also not an int
                print(f"Failed to schedule reboot for system ID {system_id} or unexpected API result format. Result: {api_result}")
            return ""

@mcp.tool()
async def list_all_scheduled_actions() -> List[Dict[str, Any]]:
    """
    Fetches a list of all scheduled actions from the Uyuni server.

    This includes completed, in-progress, failed, and archived actions.
    Each action in the list is a dictionary containing details such as
    action_id, name, type, scheduler, earliest execution time,
    prerequisite action ID (if any), and counts of systems in
    completed, failed, or in-progress states.

    Returns:
        List[Dict[str, Any]]: A list of action dictionaries.
                              Returns an empty list if the API call fails,
                              the response format is unexpected, or no actions are found.
    """
    list_actions_path = '/rhn/manager/api/schedule/listAllActions'
    processed_actions_list = []

    async with httpx.AsyncClient(verify=False) as client:
        api_result = await _call_uyuni_api(
            client=client,
            method="GET",
            api_path=list_actions_path,
            error_context="listing all scheduled actions",
            default_on_error=[] # Return empty list on error
        )

        if isinstance(api_result, list):
            for action_dict in api_result:
                if isinstance(action_dict, dict):
                    # Create a new dict to avoid modifying the original if it's shared
                    modified_action = dict(action_dict)
                    if 'id' in modified_action:
                        modified_action['action_id'] = modified_action.pop('id')
                    processed_actions_list.append(modified_action)
                else:
                    print(f"Warning: Unexpected item format in actions list: {action_dict}")
        elif api_result: # Log if not default empty list but also not a list
            print(f"Warning: Expected a list for all scheduled actions, but received: {type(api_result)}")
    return processed_actions_list

@mcp.tool()
async def cancel_action(action_id: int, confirm: bool = False) -> str:
    """
    Cancels a specified action on the Uyuni server.

    If the action ID is invalid or the action cannot be canceled,
    the operation will fail.

    Args:
        action_id: The integer ID of the action to be canceled.
        confirm: False by default. Only set confirm to True if the user has explicetely confirmed. Ask the user for confirmation.

    Returns:
        str: A success message if the action was canceled,
             e.g., "Successfully canceled action: 123".
             Returns an error message if the cancellation failed for any reason,
             e.g., "Failed to cancel action 123. Please check the action ID and server logs."
    """
    cancel_actions_path = '/rhn/manager/api/schedule/cancelActions'
 
    if not isinstance(action_id, int): # Basic type check, though FastMCP might handle this
        return "Invalid action ID provided. Must be an integer."

    if not confirm:
        return f"CONFIRMATION REQUIRED: This will schedule action {action_id} to be canceled. Do you confirm?"

    async with httpx.AsyncClient(verify=False) as client:
        payload = {"actionIds": [action_id]} # API expects a list
        api_result = await _call_uyuni_api(
            client=client,
            method="POST",
            api_path=cancel_actions_path,
            json_body=payload,
            error_context=f"canceling action {action_id}",
            default_on_error=0 # API returns 1 on success, so 0 can signify an error or unexpected response from helper
        )
        if api_result == 1:
            return f"Successfully canceled action: {action_id}"
        else:
            # The _call_uyuni_api helper already prints detailed errors.
            return f"Failed to cancel action: {action_id}. The API did not return success (expected 1, got {api_result}). Check server logs for details."

@mcp.tool()
async def list_activation_keys() -> List[Dict[str, str]]:
    """
    Fetches a list of activation keys from the Uyuni server.

    This tool retrieves all activation keys visible to the user and returns
    a list containing only the key identifier and its description.

    Returns:
        List[Dict[str, str]]: A list of dictionaries, where each dictionary
                              represents an activation key with 'key' and
                              'description' fields. Returns an empty list
                              if the API call fails, the response is not in
                              the expected format, or no keys are found.
    """
    list_keys_path = '/rhn/manager/api/activationkey/listActivationKeys'

    async with httpx.AsyncClient(verify=False) as client:
        api_result = await _call_uyuni_api(
            client=client,
            method="GET",
            api_path=list_keys_path,
            error_context="listing activation keys",
            default_on_error=[]
        )

    filtered_keys = []
    if isinstance(api_result, list):
        for key_data in api_result:
            if isinstance(key_data, dict):
                filtered_keys.append({'key': key_data.get('key'), 'description': key_data.get('description')})
            else:
                print(f"Warning: Unexpected item format in activation key list: {key_data}")
    return filtered_keys

def main_cli():
    global url, username, password # Declare intent to modify globals

    # Initialize global Uyuni connection details from environment variables
    # This needs to be done before any mcp.tool function is called by the mcp server.
    url_env = os.environ.get('UYUNI_SERVER')
    if not url_env:
        print("Error: UYUNI_SERVER environment variable not set.", file=sys.stderr)
        sys.exit(1)
    url = 'https://' + url_env

    try:
        username = os.environ['UYUNI_USER']
        password = os.environ['UYUNI_PASS']
    except KeyError as e:
        print(f"Error: Environment variable {e} not set.", file=sys.stderr)
        sys.exit(1)

    # Initialize and run the server
    mcp.run(transport='stdio')
