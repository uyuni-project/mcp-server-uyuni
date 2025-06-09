from typing import Any, List, Dict
import httpx
from mcp.server.fastmcp import FastMCP
import os

# Initialize FastMCP server
mcp = FastMCP("mcp-server-uyuni")

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
        login_data = {"login": username, "password": password}
        try:
            login_response = await client.post(url + '/rhn/manager/api/login', json=login_data)
            login_response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

            systems_response = await client.get(url + '/rhn/manager/api/system/listSystems')
            systems_response.raise_for_status()
            systems_data = systems_response.json()

        except httpx.HTTPStatusError as e:
            print(f"HTTP error occurred while fetching active systems: {e.request.url} - {e.response.status_code} - {e.response.text}")
            return []
        except httpx.RequestError as e:
            print(f"Request error occurred while fetching active systems: {e.request.url} - {e}")
            return []
        except Exception as e: # Catch other potential errors like JSONDecodeError
            print(f"An unexpected error occurred while fetching active systems: {e}")
            return []
  
    filtered_systems = []
    if systems_data.get('success') and 'result' in systems_data:
        for system in systems_data['result']:
            # Use more specific key names
            filtered_systems.append({'system_name': system.get('name'), 'system_id': system.get('id')})
    else:
        print(f"Warning: Failed to get system list. Response: {systems_data}")
        return [] # Return empty list on failure/unexpected format

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
        login_data = {"login": username, "password": password}
        try:
            login_response = await client.post(url + '/rhn/manager/api/login', json=login_data)
            login_response.raise_for_status()
            cpu_response = await client.get(url + '/rhn/manager/api/system/getCpu?sid=' + str(system_id))
            cpu_response.raise_for_status()
            cpu_data = cpu_response.json()

        except httpx.HTTPStatusError as e:
            print(f"HTTP error occurred while fetching CPU data for system ID {system_id}: {e.request.url} - {e.response.status_code} - {e.response.text}")
            return {}
        except httpx.RequestError as e:
            print(f"Request error occurred while fetching CPU data for system ID {system_id}: {e.request.url} - {e}")
            return {}
        except Exception as e: # Catch other potential errors like JSONDecodeError
            print(f"An unexpected error occurred while fetching CPU data for system ID {system_id}: {e}")
            return {}
    if cpu_data.get('success') and isinstance(cpu_data.get('result'), dict):
        return cpu_data['result']
    else:
        print(f"Warning: Failed to get CPU data for system ID {system_id} or unexpected format. Response: {cpu_data}")
        return {} # Return empty dict on failure/unexpected format

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

async def _fetch_cves_for_erratum(client: httpx.AsyncClient, base_url: str, advisory_name: str, system_id: int, list_cves_path: str) -> List[str]:
    """
    Internal helper to fetch CVEs for a given erratum advisory name.

    Args:
        client: The httpx.AsyncClient instance (must have active login session).
        base_url: The base URL of the Uyuni server.
        advisory_name: The advisory name of the erratum to fetch CVEs for.
        system_id: The ID of the system (for logging purposes).
        list_cves_path: The API path for listing CVEs.

    Returns:
        List[str]: A list of CVE identifier strings. Returns an empty list on failure or if no CVEs are found.
    """
    if not advisory_name:
        print(f"Warning: advisory_name is missing for system ID {system_id}, cannot fetch CVEs.")
        return []

    cves_list = []
    try:
        print(f"Fetching CVEs for advisory: {advisory_name} (system ID: {system_id})")
        cves_response = await client.get(
            base_url + list_cves_path,
            params={'advisoryName': advisory_name} # Changed parameter to advisoryName
        )
        cves_response.raise_for_status()
        cves_data = cves_response.json()
        print(f"CVEs response for advisory {advisory_name}: {cves_data}")

        cve_list_from_api = cves_data.get('result')
        if cves_data.get('success'):
            if isinstance(cve_list_from_api, list):
                cves_list = [str(cve) for cve in cve_list_from_api if cve] # Ensure CVEs are strings and not None/empty
            elif cve_list_from_api is None: # Treat null as empty list
                pass # cves_list is already []
            else: # Unexpected format for CVE list
                print(f"Warning: Unexpected format for CVEs list for advisory {advisory_name} (system {system_id}). Expected list or None, got {type(cve_list_from_api)}. Response: {cves_data}")
        else: # API call for CVEs reported failure
            print(f"Warning: Failed to get CVEs (API call unsuccessful) for advisory {advisory_name} (system {system_id}). Response: {cves_data}")
    except httpx.HTTPStatusError as e_cve:
        print(f"HTTP error fetching CVEs for advisory {advisory_name} (system {system_id}): {e_cve.request.url} - {e_cve.response.status_code} - {e_cve.response.text}")
    except Exception as e_cve: # Catch other errors during CVE fetch, including httpx.RequestError
        print(f"Unexpected error fetching CVEs for advisory {advisory_name} (system {system_id}): {e_cve}")
    return cves_list

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
    list_cves_path = '/rhn/manager/api/errata/listCves' # Path for listing CVEs for an erratum

    async with httpx.AsyncClient(verify=False) as client:
        login_data = {"login": username, "password": password}
        try:
            login_response = await client.post(url + '/rhn/manager/api/login', json=login_data)
            login_response.raise_for_status()

            errata_response = await client.get(url + '/rhn/manager/api/system/getRelevantErrata?sid=' + str(system_id))
            errata_response.raise_for_status()
            errata_data = errata_response.json()

        except httpx.HTTPStatusError as e:
            print(f"HTTP error occurred while checking updates for system ID {system_id}: {e.request.url} - {e.response.status_code} - {e.response.text}")
            return default_error_response
        except httpx.RequestError as e:
            print(f"Request error occurred while checking updates for system ID {system_id}: {e.request.url} - {e}")
            return default_error_response
        except Exception as e: # Catch other potential errors like JSONDecodeError
            print(f"An unexpected error occurred while checking updates for system ID {system_id}: {e}")
            return default_error_response

        # Process errata and fetch CVEs within the same client session
        if not errata_data.get('success') or not isinstance(errata_data.get('result'), list):
            print(f"Warning: Failed to get updates for system ID {system_id} or unexpected format. Response: {errata_data}")
            return default_error_response

        updates_list_from_api = errata_data['result']
        enriched_updates_list = []

        for erratum in updates_list_from_api:
            erratum_id = erratum.get('id')
            advisory_name = erratum.get('advisory_name') # Get advisory_name from erratum
            # Initialize with the original erratum data and an empty list for CVEs
            erratum_with_cves = {**erratum, 'cves': []}

            if advisory_name: # Check if advisory_name is present
                # Call the helper function to fetch CVEs
                erratum_with_cves['cves'] = await _fetch_cves_for_erratum(client, url, advisory_name, system_id, list_cves_path)
            
            enriched_updates_list.append(erratum_with_cves)
        
        return { # This return is now correctly inside the async with client block
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
async def schedule_apply_pending_updates_to_system(system_id: int) -> str:
    """
    Checks for pending updates on a system, schedules all of them to be applied,
    and returns the action ID of the scheduled task.

    This tool first calls 'check_system_updates' to determine relevant errata.
    If updates are found, it then calls the 'system/scheduleApplyErrata' API
    endpoint to apply all found errata.

    Args:
        system_id: The unique identifier of the system.

    Returns:
        str: The action url if updates were successfully scheduled.
             Otherwise, returns an empty string.
    """
    print(f"Attempting to apply pending updates for system ID: {system_id}")

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

    errata_ids = [erratum.get('id') for erratum in errata_list if erratum.get('id') is not None]

    if not errata_ids:
        print(f"Could not extract any valid errata IDs for system ID {system_id} from the update information: {errata_list}")
        return ""

    print(f"Found {len(errata_ids)} errata to apply for system ID {system_id}. IDs: {errata_ids}")

    # 2. Schedule apply errata using the API endpoint
    async with httpx.AsyncClient(verify=False) as client:
        login_data = {"login": username, "password": password}
        payload = {"sid": system_id, "errataIds": errata_ids}

        try:
            login_response = await client.post(url + '/rhn/manager/api/login', json=login_data)
            login_response.raise_for_status()

            errata_response = await client.post(url + '/rhn/manager/api/system/scheduleApplyErrata', json=payload)
            errata_response.raise_for_status()
            errata_data = errata_response.json()


        except httpx.HTTPStatusError as e:
            print(f"HTTP error scheduling errata application for system ID {system_id}: {e.request.url} - {e.response.status_code} - {e.response.text}")
            return ""
        except httpx.RequestError as e:
            print(f"Request error scheduling errata application for system ID {system_id}: {e.request.url} - {e}")
            return ""
        except Exception as e: # Catch other potential errors like JSONDecodeError
            print(f"An unexpected error occurred while scheduling errata for system ID {system_id}: {e}")
            return ""

        if errata_data.get('success') and isinstance(errata_data.get('result'), list) and errata_data['result'] and isinstance(errata_data['result'][0], int):
            action_id = errata_data['result'][0]
            print(f"Successfully scheduled action {action_id} to apply {len(errata_ids)} errata to system ID {system_id}.")
            return "Update successfully scheduled at " +url + "/rhn/schedule/ActionDetails.do?aid=" + str(action_id)
        else:
            print(f"Failed to schedule errata for system ID {system_id} or unexpected API response format. Response: {errata_data}")
            return "" # Match return type hint str

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
        login_data = {"login": username, "password": password}
        try:
            # 1. Login
            login_response = await client.post(url + '/rhn/manager/api/login', json=login_data)
            login_response.raise_for_status()

            # 2. Call findByCve
            print(f"Searching for errata related to CVE: {cve_identifier}")
            cve_response = await client.get(
                url + find_by_cve_path,
                params={'cveName': cve_identifier}
            )
            cve_response.raise_for_status()
            errata_data = cve_response.json()

            if not errata_data.get('success') or not isinstance(errata_data.get('result'), list):
                print(f"Failed to find errata for CVE {cve_identifier} or unexpected API response format. Response: {errata_data}")
                return []

            errata_list = errata_data['result']
            if not errata_list:
                print(f"No errata found for CVE {cve_identifier}.")
                return []

            # 3. For each erratum, call listAffectedSystems
            for erratum in errata_list:
                advisory_name = erratum.get('advisory_name')
                if not advisory_name:
                    print(f"Skipping erratum due to missing 'advisory_name': {erratum}")
                    continue

                print(f"Fetching systems affected by advisory: {advisory_name} (related to CVE: {cve_identifier})")
                systems_response = await client.get(
                    url + list_affected_systems_path,
                    params={'advisoryName': advisory_name}
                )
                systems_response.raise_for_status()
                systems_data = systems_response.json()

                if systems_data.get('success') and isinstance(systems_data.get('result'), list):
                    for system_info in systems_data['result']:
                        system_id = system_info.get('id')
                        system_name = system_info.get('name')
                        if system_id is not None and system_name is not None:
                            if system_id not in affected_systems_map: # Add if new
                                affected_systems_map[system_id] = {
                                    'system_id': system_id,
                                    'system_name': system_name,
                                    'cve_identifier': cve_identifier # Add the CVE to the output
                                }
                        else:
                            print(f"Warning: Received system data with missing ID or name for advisory {advisory_name}: {system_info}")
                else:
                    print(f"Warning: Failed to list affected systems for advisory {advisory_name} or unexpected API response format. Response: {systems_data}")

        except httpx.HTTPStatusError as e:
            print(f"HTTP error occurred while processing CVE {cve_identifier}: {e.request.url} - {e.response.status_code} - {e.response.text}")
            return []
        except httpx.RequestError as e:
            print(f"Request error occurred while processing CVE {cve_identifier}: {e.request.url} - {e}")
            return []
        except Exception as e:  # Catch other potential errors like JSONDecodeError
            print(f"An unexpected error occurred while processing CVE {cve_identifier}: {e}")
            return []

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
        login_data = {"login": username, "password": password}
        try:
            login_response = await client.post(url + '/rhn/manager/api/login', json=login_data)
            login_response.raise_for_status()

            reboot_response = await client.get(url + list_reboot_path)
            reboot_response.raise_for_status()
            reboot_data = reboot_response.json()

            if reboot_data.get('success') and isinstance(reboot_data.get('result'), list):
                for system_info in reboot_data['result']:
                    system_id = system_info.get('id')
                    system_name = system_info.get('name')
                    if system_id is not None and system_name is not None:
                        systems_needing_reboot_list.append({
                            'system_id': system_id,
                            'system_name': system_name,
                            'reboot_status': 'reboot_required' # Explicitly state reboot is needed
                        })
            else:
                print(f"Failed to get list of systems needing reboot or unexpected API response format. Response: {reboot_data}")
                return []

        except httpx.HTTPStatusError as e:
            print(f"HTTP error occurred while fetching systems needing reboot: {e.request.url} - {e.response.status_code} - {e.response.text}")
            return []
        except Exception as e: # Catch other errors like RequestError, JSONDecodeError
            print(f"An unexpected error occurred while fetching systems needing reboot: {e}")
            return []

    return systems_needing_reboot_list

if __name__ == "__main__":
    # Initialize and run the server
    url = 'https://' + os.environ['UYUNI_SERVER']
    username = os.environ['UYUNI_USER']
    password = os.environ['UYUNI_PASS']
    mcp.run(transport='stdio')
