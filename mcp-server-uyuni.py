from typing import Any, List, Dict
import httpx # Used by get_list_of_active_systems and now get_cpu_of_a_system
from mcp.server.fastmcp import FastMCP
import requests # Still used by get_all_systems_cpu_info (indirectly)
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

if __name__ == "__main__":
    # Initialize and run the server
    url = 'https://' + os.environ['UYUNI_SERVER']
    username = os.environ['UYUNI_USER']
    password = os.environ['UYUNI_PASS']
    mcp.run(transport='stdio')
