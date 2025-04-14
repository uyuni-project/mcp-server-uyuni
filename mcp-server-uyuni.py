from typing import Any
import httpx
from mcp.server.fastmcp import FastMCP
import requests
import os
import pprint

# Initialize FastMCP server
mcp = FastMCP("mcp-server-uyuni")

@mcp.tool()
async def get_list_of_active_systems() -> str:
  """Get list of Active Systems installed in the uyuni server accessible at the url with username and password credentials.
  """
  data = {"login": username, "password": password}
  response = requests.post(url + '/rhn/manager/api/login', json=data, verify=False)
  cookies = response.cookies
  res2 = requests.get(url + '/rhn/manager/api/system/listSystems', cookies=cookies, verify=False)
  return res2.json()

@mcp.tool()
async def get_cpu_of_a_system(system_id: int) -> str:
  """Get relevant errata of a system, like advisories of Security or Bug Fixes or other data of a system.

  Args:
    system_id: id of the system we want the errata

  """
  data = {"login": username, "password": password}
  response = requests.post(url + '/rhn/manager/api/login', json=data, verify=False)
  cookies = response.cookies
  res2 = requests.get(url + '/rhn/manager/api/system/getCpu?sid=' + str(system_id), cookies=cookies, verify=False)
  return res2.json()

if __name__ == "__main__":
  # Initialize and run the server
  url = 'https://' + os.environ['UYUNI_SERVER']
  username = os.environ['UYUNI_USER']
  password = os.environ['UYUNI_PASS']
  mcp.run(transport='stdio')

