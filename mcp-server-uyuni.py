from typing import Any, List, Dict
import httpx
from mcp.server.fastmcp import FastMCP
import requests
import os
import pprint

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

  data = {"login": username, "password": password}
  response = requests.post(url + '/rhn/manager/api/login', json=data, verify=False)
  cookies = response.cookies
  res2 = requests.get(url + '/rhn/manager/api/system/listSystems', cookies=cookies, verify=False)
  systems_data = res2.json()
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
async def get_cpu_of_a_system(system_id: int) -> Dict[str, Any]: # Changed return type hint
  """Retrieves detailed CPU information for a specific system.

  Fetches CPU attributes such as model, core count, architecture, etc.

  Args:
    system_id: The unique identifier of the system.

  Returns:
    Dict[str, Any]: A dictionary containing the CPU attributes.
                    Returns an empty dictionary if the API call fails,
                    the response format is unexpected, or CPU data is not available.
  """
  data = {"login": username, "password": password}
  response = requests.post(url + '/rhn/manager/api/login', json=data, verify=False)
  cookies = response.cookies
  res2 = requests.get(url + '/rhn/manager/api/system/getCpu?sid=' + str(system_id), cookies=cookies, verify=False)

  cpu_data = res2.json()
  if cpu_data.get('success') and isinstance(cpu_data.get('result'), dict):
      return cpu_data['result']
  else:
      print(f"Warning: Failed to get CPU data for system ID {system_id}. Response: {cpu_data}") # Basic warning
      return {} # Return empty dict on failure/unexpected format

if __name__ == "__main__":
  # Initialize and run the server
  url = 'https://' + os.environ['UYUNI_SERVER']
  username = os.environ['UYUNI_USER']
  password = os.environ['UYUNI_PASS']
  mcp.run(transport='stdio')
