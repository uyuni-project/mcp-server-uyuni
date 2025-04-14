from typing import Any
import httpx
from mcp.server.fastmcp import FastMCP
import requests
import pprint

# Initialize FastMCP server
mcp = FastMCP("mlm")

@mcp.tool()
async def get_list_of_active_systems(url: str, username: str, password: str) -> str:
  """Get list of Active Systems installed in the mlm server accessible at the url with username and password credentials.
  
  Args:
    url: URL of the mlm server
    username: username for login to the mlm server
    password: password for login to the mlm server

  """
  data = {"login": username, "password": password}
  response = requests.post(url + '/rhn/manager/api/login', json=data, verify=False)
  cookies = response.cookies
  res2 = requests.get(url + '/rhn/manager/api/system/listSystems', cookies=cookies, verify=False)
  return res2.json()

@mcp.tool()
async def get_cpu_of_a_system(url: str, username: str, password: str, system_id: int) -> str:
  """Get relevant errata of a system, like advisories of Security or Bug Fixes or other data of a system.

  Args:
    url: URL of the mlm server
    username: username for login to the mlm server
    password: password for login to the mlm server
    system_id: id of the system we want the errata

  """
  data = {"login": username, "password": password}
  response = requests.post(url + '/rhn/manager/api/login', json=data, verify=False)
  cookies = response.cookies
  res2 = requests.get(url + '/rhn/manager/api/system/getCpu?sid=' + str(system_id), cookies=cookies, verify=False)
  return res2.json()

if __name__ == "__main__":
  # TODO: Get username, password and url from command line, so they are not sent to the LLM
  # Initialize and run the server
  mcp.run(transport='stdio')

