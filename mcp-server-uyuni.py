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

@mcp.tool()
async def check_system_updates(system_id: int) -> Dict[str, Any]:
    """
    Checks if a specific system in the Uyuni server has pending updates (relevant errata).

    Args:
        system_id: The unique identifier of the system.

    Returns:
        Dict[str, Any]: A dictionary containing:
                        - 'system_id' (int): The ID of the system checked.
                        - 'has_pending_updates' (bool): True if there are pending updates, False otherwise.
                        - 'update_count' (int): The number of pending updates.
                        - 'updates' (List[Dict[str, Any]]): A list of pending update details.
                        Returns a dictionary with 'has_pending_updates': False and empty 'updates'
                        if the API call fails or the format is unexpected.
    """
    default_error_response = {
        'system_id': system_id,
        'has_pending_updates': False,
        'update_count': 0,
        'updates': []
    }

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
        except Exception as e: 
            print(f"An unexpected error occurred while checking updates for system ID {system_id}: {e}")
            return default_error_response

    if errata_data.get('success') and isinstance(errata_data.get('result'), list):
        updates_list = errata_data['result']
        return {
            'system_id': system_id,
            'has_pending_updates': len(updates_list) > 0,
            'update_count': len(updates_list),
            'updates': updates_list
        }
    else:
        print(f"Warning: Failed to get updates for system ID {system_id} or unexpected format. Response: {errata_data}")
        return default_error_response

@mcp.tool()
async def check_all_systems_for_updates() -> List[Dict[str, Any]]:
    """
    Checks all active systems in the Uyuni server for pending updates.

    Returns a list containing information only for those systems that have
    one or more pending updates.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries. Each dictionary represents
                              a system with pending updates and includes:
                              - 'system_name' (str): The name of the system.
                              - 'system_id' (int): The unique ID of the system.
                              - 'update_count' (int): The number of pending updates.
                              - 'updates' (List[Dict[str, Any]]): A list of pending update details.
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

if __name__ == "__main__":
    # Initialize and run the server
    url = 'https://' + os.environ['UYUNI_SERVER']
    username = os.environ['UYUNI_USER']
    password = os.environ['UYUNI_PASS']
    mcp.run(transport='stdio')
