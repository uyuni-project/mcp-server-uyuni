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

import os
import sys
import asyncio
from typing import Any, List, Dict, Optional, Union, Coroutine
import httpx
from datetime import datetime, timezone
from pydantic import BaseModel

from fastmcp import FastMCP, Context
from mcp import LoggingLevel, ServerSession, types
from mcp_server_uyuni.logging_config import get_logger, Transport

from .auth import AuthProvider

class ActivationKeySchema(BaseModel):
    activation_key: str

REQUIRED_VARS = [
    "UYUNI_SERVER",
    "UYUNI_USER",
    "UYUNI_PASS",
]

missing_vars = [key for key in REQUIRED_VARS if key not in os.environ]

if missing_vars:
    raise ImportError(
        f"Failed to import config: Missing required environment variables: {', '.join(missing_vars)}"
    )

UYUNI_SERVER = 'https://' + os.environ.get('UYUNI_SERVER')
UYUNI_USER = os.environ.get('UYUNI_USER')
UYUNI_PASS = os.environ.get('UYUNI_PASS')
# UYUNI_MCP_SSL_VERIFY is optional and defaults to True. Set to 'false', '0', or 'no' to disable.
UYUNI_MCP_SSL_VERIFY = os.environ.get('UYUNI_MCP_SSL_VERIFY', 'true').lower() not in ('false', '0', 'no')
UYUNI_MCP_WRITE_TOOLS_ENABLED = os.environ.get('UYUNI_MCP_WRITE_TOOLS_ENABLED', 'false').lower() in ('true', '1', 'yes')
UYUNI_MCP_TRANSPORT = os.environ.get('UYUNI_MCP_TRANSPORT', 'stdio')
UYUNI_MCP_LOG_FILE_PATH = os.environ.get('UYUNI_MCP_LOG_FILE_PATH') # Defaults to None if not set

AUTH_SERVER = os.environ.get("UYUNI_AUTH_SERVER")

auth_provider = AuthProvider(AUTH_SERVER, UYUNI_MCP_WRITE_TOOLS_ENABLED) if AUTH_SERVER else None
mcp = FastMCP("mcp-server-uyuni", auth=auth_provider)

logger = get_logger(log_file=UYUNI_MCP_LOG_FILE_PATH, transport=UYUNI_MCP_TRANSPORT)

# Sentinel object to indicate an expected timeout for long-running actions
TIMEOUT_HAPPENED = object()

def write_tool(*decorator_args, **decorator_kwargs):
    """
    A decorator that registers a function as an MCP tool only if write
    tools are enabled via the UYUNI_MCP_WRITE_TOOLS_ENABLED environment variable.
    """
    # 2. This is the actual decorator that gets applied to the tool function.
    def decorator(func):
        if UYUNI_MCP_WRITE_TOOLS_ENABLED:
            # 3a. If enabled, it applies the @mcp.tool() decorator, registering the function.
            return mcp.tool(*decorator_args, **decorator_kwargs)(func)
        
        # 3b. If disabled, it does nothing and just returns the original,
        #     un-decorated function. It is never registered.
        return func
    
    # 1. The factory returns the decorator.
    return decorator

async def _call_uyuni_api(
    client: httpx.AsyncClient,
    method: str,
    api_path: str,
    error_context: str,
    params: Dict[str, Any] = None,
    json_body: Dict[str, Any] = None,
    perform_login: bool = True,
    default_on_error: Any = None,
    expected_result_key: str = 'result',
    expect_timeout: bool = False
) -> Any:
    """
    Helper function to make authenticated API calls to Uyuni.
    Handles login, request execution, error handling, and basic response parsing.
    """

    # Safety check: Do not allow POST requests if write tools are disabled.
    # This acts as a secondary guard after the @write_tool decorator.
    if method.upper() == 'POST' and not UYUNI_MCP_WRITE_TOOLS_ENABLED:
        error_msg = (f"Attempted to call a write API ({api_path}) while write tools are disabled. "
                     "Please set UYUNI_MCP_WRITE_TOOLS_ENABLED to 'true' to enable them.")
        logger.error(error_msg)
        return error_msg

    if perform_login:
        login_data = {"login": UYUNI_USER, "password": UYUNI_PASS}
        try:
            login_response = await client.post(UYUNI_SERVER + '/rhn/manager/api/login', json=login_data)
            login_response.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error during login for {error_context}: {e.request.url} - {e.response.status_code} - {e.response.text}")
            return default_on_error
        except httpx.RequestError as e:
            logger.exception(f"Request error during login for {error_context}: {e.request.url} - {e}")
            return default_on_error
        except Exception as e:
            logger.exception(f"An unexpected error occurred during login for {error_context}: {e}")
            return default_on_error

    full_api_url = UYUNI_SERVER + api_path

    try:
        if method.upper() == 'GET':
            response = await client.get(full_api_url, params=params)
        elif method.upper() == 'POST':
            logger.info(f"POSTing to {full_api_url}")
            response = await client.post(full_api_url, json=json_body, params=params)
            logger.info(f"POST response: {response.text}")
        else:
            logger.info(f"Unsupported HTTP method '{method}' for {error_context}.")
            return default_on_error
        response.raise_for_status()
        response_data = response.json()

        if response_data.get('success'):
            if expected_result_key in response_data:
                return response_data[expected_result_key]
            # If 'success' is true, but the expected_result_key is not there (e.g. 'result' is missing)
            logger.info(f"API call for {error_context} succeeded but '{expected_result_key}' not found in response. Response: {response_data}")
            return default_on_error
        else:
            print(f"API call for {error_context} reported failure. Response: {response_data}")
            return default_on_error

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error occurred while {error_context}: {e.request.url} - {e.response.status_code} - {e.response.text}")
        return default_on_error
    except httpx.TimeoutException as e:
        logger.info(f"timeout! timeout expected? {expect_timeout}")
        if expect_timeout:
            logger.info(f"A timeout occurred while {error_context} (expected for a long-running action): {e.request.url} - {e}")
            return TIMEOUT_HAPPENED
        logger.warning(f"A timeout occurred while {error_context}: {e.request.url} - {e}")
        return default_on_error
    except httpx.RequestError as e:
        logger.exception(f"Request error occurred while {error_context}: {e.request.url} - {e}")
        return default_on_error
    except Exception as e: # Catch other potential errors like JSONDecodeError
        logger.exception(f"An unexpected error occurred while {error_context}: {e}")
        return default_on_error

@mcp.tool()
async def get_list_of_active_systems(ctx: Context) -> List[Dict[str, Any]]:
    """
    Fetches a list of active systems from the Uyuni server, returning their names and IDs.

    The returned list contains dictionaries, each with a 'system_name' (str) and
    a 'system_id' (int) for an active system.

    Returns:
        List[Dict[str, Any]]: A list of system dictionaries (system_name and system_id).
                              Returns an empty list if the API call fails,
                              the response format is unexpected, or no systems are found.
    """
    log_string = "Getting list of active systems"
    logger.info(log_string)
    await ctx.info(log_string)

    return await _get_list_of_active_systems()

async def _get_list_of_active_systems() -> List[Dict[str, Union[str, int]]]:

    async with httpx.AsyncClient(verify=UYUNI_MCP_SSL_VERIFY) as client:
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

async def _resolve_system_id(system_identifier: Union[str, int]) -> Optional[str]:
    """
    Resolves a system identifier, which can be a name or an ID, to a numeric system ID string.
 
    If the identifier is numeric (or a string of digits), it's returned as a string.
    If it's a non-numeric string, it's treated as a name and the ID is looked up via the system.getId API endpoint.
 
    Args:
        system_identifier: The system name (e.g., "buildhost") or system ID (e.g., 1000010000).
    Returns:
        Optional[str]: The numeric system ID as a string if found, otherwise None.
    """
    id_str = str(system_identifier)
    if id_str.isdigit():
        return id_str
 
    # If it's not a digit string, it must be a name.
    system_name = id_str
    logger.info(f"System identifier '{system_name}' is not numeric, treating as a name and looking up ID.")

    async with httpx.AsyncClient(verify=UYUNI_MCP_SSL_VERIFY) as client:
        # The result from system.getId is an array of system structs
        systems_list = await _call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getId",
            params={'name': system_name},
            error_context=f"resolving system ID for name '{system_name}'",
            default_on_error=[]  # Return an empty list on failure
        )
 
    if not isinstance(systems_list, list):
        logger.error(f"Expected a list of systems for name '{system_name}', but received: {type(systems_list)}")
        return None
 
    if not systems_list:
        logger.warning(f"System with name '{system_name}' not found.")
        return None
 
    if len(systems_list) > 1:
        logger.error(f"Multiple systems found with name '{system_name}'.")
        return None
 
    first_system = systems_list[0]
    if isinstance(first_system, dict) and 'id' in first_system:
        resolved_id = str(first_system['id'])
        logger.info(f"Found ID {resolved_id} for system name '{system_name}'.")
        return resolved_id
    else:
        logger.error(f"System data for '{system_name}' is malformed. Expected a dict with 'id'. Got: {first_system}")
        return None

@mcp.tool()
async def get_cpu_of_a_system(system_identifier: Union[str, int], ctx: Context) -> Dict[str, Any]:

    """Retrieves detailed CPU information for a specific system in the Uyuni server.

    Fetches CPU attributes such as model, core count, architecture, etc.

    Args:
        system_identifier: The unique identifier of the system. It can be the system name (e.g. "buildhost") or the system ID (e.g. 1000010000).

    Returns:
        Dict[str, Any]: A dictionary containing the CPU attributes and the original system_identifier.
                        Returns an empty dictionary if the API call fails,
                        the response format is unexpected, or CPU data is not available.
    """
    log_string = f"Getting CPU information of system with id {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)
    return await _get_cpu_of_a_system(system_identifier)

async def _get_cpu_of_a_system(system_identifier: Union[str, int]) -> Dict[str, Any]:
    system_id = await _resolve_system_id(system_identifier)
    if not system_id:
        return {} # Helper function already logged the reason for failure.

    async with httpx.AsyncClient(verify=UYUNI_MCP_SSL_VERIFY) as client:
        cpu_data_result = await _call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getCpu",
            params={'sid': system_id},
            error_context=f"fetching CPU data for system {system_identifier}",
            default_on_error={}
        )

    if isinstance(cpu_data_result, dict):
        # Only add the identifier if the API returned actual data
        if cpu_data_result:
            cpu_data_result['system_identifier'] = system_identifier
        return cpu_data_result
    # If not a dict but not the default empty dict, log it
    elif cpu_data_result:
         print(f"Warning: Expected a dict for CPU data, but received: {type(cpu_data_result)}")
    return {}

@mcp.tool()
async def get_all_systems_cpu_info(ctx: Context) -> List[Dict[str, Any]]:
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

    log_string = "Get CPU info for all systems"
    logger.info(log_string)
    await ctx.info(log_string)

    all_systems_cpu_data = []
    active_systems = await _get_list_of_active_systems() # Calls your existing tool

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
        cpu_info = await _get_cpu_of_a_system(str(system_id)) # Calls your other existing tool

        all_systems_cpu_data.append({
            'system_name': system_name,
            'system_id': system_id,
            'cpu_info': cpu_info
        })

    return all_systems_cpu_data

async def _fetch_cves_for_erratum(client: httpx.AsyncClient, advisory_name: str, system_id: int, 
                                  list_cves_path: str, ctx: Context) -> List[str]:
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

    log_string = f"Fetching CVEs for advisory {advisory_name}"
    logger.info(log_string)
    await ctx.info(log_string)

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
async def check_system_updates(system_identifier: Union[str, int], ctx: Context) -> Dict[str, Any]:

    """
    Checks if a specific system in the Uyuni server has pending updates (relevant errata),
    including associated CVEs for each update.

    Args:
        system_identifier: The unique identifier of the system. It can be the system name (e.g. "buildhost") or the system ID (e.g. 1000010000).

    Returns:
        Dict[str, Any]: A dictionary containing:
                        - 'system_identifier' (Union[str, int]): The original system identifier used in the request.
                        - 'has_pending_updates' (bool): True if there are pending updates, False otherwise.
                        - 'update_count' (int): The number of pending updates.
                        - 'updates' (List[Dict[str, Any]]): A list of pending update details.
                          Each update dictionary will also include a 'cves' key
                          containing a list of CVE identifiers associated with that update.
                        Returns a dictionary with 'has_pending_updates': False and empty 'updates'
                        if the API call fails or the format is unexpected.
    """
    log_string = f"Checking pending updates for system {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)
    system_id = await _resolve_system_id(system_identifier)
    default_error_response = {
        'system_identifier': system_identifier,
        'has_pending_updates': False,
        'update_count': 0,
        'updates': []
    }
    if not system_id:
        # Return a structure consistent with the success response, but indicating failure.
        return default_error_response

    list_cves_api_path = '/rhn/manager/api/errata/listCves'

    async with httpx.AsyncClient(verify=UYUNI_MCP_SSL_VERIFY) as client:
        relevant_errata_call: Coroutine = _call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getRelevantErrata",
            params={'sid': system_id},
            error_context=f"checking updates for system {system_identifier}",
            default_on_error=None # Distinguish API error from empty list
        )

        unscheduled_errata_call: Coroutine = _call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getUnscheduledErrata",
            params={'sid': str(system_id)},
            error_context=f"checking unscheduled errata for system ID {system_id}",
            default_on_error=[] # Return empty list on failure
        )

        results = await asyncio.gather(
            relevant_errata_call,
            unscheduled_errata_call
        )
        relevant_updates_list, unscheduled_updates_list = results
        
        if not isinstance(relevant_updates_list, list) or not isinstance(unscheduled_updates_list, list):
            logger.error(
                f"API calls for system {system_id} did not return lists as expected. "
                f"Type of relevant_updates: {type(relevant_updates_list).__name__}, "
                f"Type of unscheduled_updates: {type(unscheduled_updates_list).__name__}"
            )
            return default_error_response

        unscheduled_advisory_names = {erratum.get('advisory_name') for erratum in unscheduled_updates_list}

        enriched_updates_list = []
        cve_fetch_tasks = []

        for erratum_api_data in relevant_updates_list:
            update_details = dict(erratum_api_data)

            # Rename 'id' to 'update_id'
            if 'id' in update_details:
                update_details['update_id'] = update_details.pop('id')
            else:
                # This case is unlikely for errata from the API but good for robustness
                update_details['update_id'] = None
            advisory_name = update_details.get('advisory_name')

            if advisory_name in unscheduled_advisory_names:
                update_details['application_status'] = 'Pending'
            else:
                update_details['application_status'] = 'Queued'
            
            # Initialize and fetch CVEs
            update_details['cves'] = []
            if advisory_name:
                # Call the helper function to fetch CVEs
                task = _fetch_cves_for_erratum(client, advisory_name, system_id, list_cves_api_path, ctx)
                cve_fetch_tasks.append(task)

            enriched_updates_list.append(update_details)

        all_cve_results = await asyncio.gather(*cve_fetch_tasks)

        if cve_fetch_tasks:
            cve_iterator = iter(all_cve_results)
            for update in enriched_updates_list:
                # If the update had an advisory name, it has a corresponding CVE result.
                if update.get("advisory_name"):
                    update['cves'] = next(cve_iterator)
                else:
                    update['cves'] = [] # Ensure the 'cves' key always exists

        return {
            'system_identifier': system_identifier,
            'has_pending_updates': len(enriched_updates_list) > 0,
            'update_count': len(enriched_updates_list),
            'updates': enriched_updates_list
        }

@mcp.tool()
async def check_all_systems_for_updates(ctx: Context) -> List[Dict[str, Any]]:
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

    log_string = "Checking all system for updates"
    logger.info(log_string)
    await ctx.info(log_string)

    systems_with_updates = []
    active_systems = await _get_list_of_active_systems() # Get the list of all systems

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
        update_check_result = await check_system_updates(system_id, ctx)

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

@write_tool()
async def schedule_apply_pending_updates_to_system(system_identifier: Union[str, int], ctx: Context, confirm: bool = False) -> str:

    """
    Checks for pending updates on a system, schedules all of them to be applied,
    and returns the action ID of the scheduled task.

    This tool first calls 'check_system_updates' to determine relevant errata.
    If updates are found, it then calls the 'system/scheduleApplyErrata' API
    endpoint to apply all found errata.

    Args:
        system_identifier: The unique identifier of the system. It can be the system name (e.g. "buildhost") or the system ID (e.g. 1000010000).
        confirm: False by default. Only set confirm to True if the user has explicetely confirmed. Ask the user for confirmation.

    Returns:
        str: The action url if updates were successfully scheduled.
             Otherwise, returns an empty string.
    """
    log_string = f"Attempting to apply pending updates for system ID: {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)

    if not confirm:
        return f"CONFIRMATION REQUIRED: This will apply pending updates to the system {system_identifier}.  Do you confirm?"

    # 1. Use check_system_updates to get relevant errata
    update_info = await check_system_updates(system_identifier, ctx)

    if not update_info or not update_info.get('has_pending_updates'):
        print(f"No pending updates found for system {system_identifier}, or an error occurred while fetching update information.")
        return ""

    errata_list = update_info.get('updates', [])
    if not errata_list:
        # This case should ideally be covered by 'has_pending_updates' being false,
        # but good to have a safeguard.
        print(f"Update check for system {system_identifier} indicated updates, but the updates list is empty.")
        return ""

    errata_ids = [erratum.get('update_id') for erratum in errata_list if erratum.get('update_id') is not None]

    if not errata_ids:
        print(f"Could not extract any valid errata IDs for system {system_identifier} from the update information: {errata_list}")
        return ""

    system_id = await _resolve_system_id(system_identifier)
    if not system_id:
        return "" # Helper function already logged the reason for failure.

    print(f"Found {len(errata_ids)} errata to apply for system {system_identifier} (ID: {system_id}). IDs: {errata_ids}")

    # 2. Schedule apply errata using the API endpoint
    async with httpx.AsyncClient(verify=UYUNI_MCP_SSL_VERIFY) as client:
        payload = {"sid": int(system_id), "errataIds": errata_ids}
        api_result = await _call_uyuni_api(
            client=client,
            method="POST",
            api_path="/rhn/manager/api/system/scheduleApplyErrata",
            json_body=payload,
            error_context=f"scheduling errata application for system {system_identifier}",
            default_on_error=None # Helper will return None on error
        )

        if isinstance(api_result, list) and api_result and isinstance(api_result[0], int):
            action_id = api_result[0]
            print(f"Successfully scheduled action {action_id} to apply {len(errata_ids)} errata to system {system_identifier}.")
            return "Update successfully scheduled at " + UYUNI_SERVER + "/rhn/schedule/ActionDetails.do?aid=" + str(action_id)
        else:
            # Error message already printed by _call_uyuni_api if it returned None
            if api_result is not None: # Log if result is not None but also not the expected format
                 print(f"Failed to schedule errata for system {system_identifier} or unexpected API response format. Result: {api_result}")
            return ""

@write_tool()
async def schedule_apply_specific_update(system_identifier: Union[str, int], errata_id: int, ctx: Context, confirm: bool = False) -> str:

    """
    Schedules a specific update (erratum) to be applied to a system.

    Args:
        system_identifier: The unique identifier of the system. It can be the system name (e.g. "buildhost") or the system ID (e.g. 1000010000).
        errata_id: The unique identifier of the erratum (also referred to as update ID) to be applied.
        confirm: False by default. Only set confirm to True if the user has explicetely confirmed. Ask the user for confirmation.

    Returns:
        str: The action URL if the update was successfully scheduled.
             Otherwise, returns an empty string.
    """
    log_string = f"Attempting to apply specific update (errata ID: {errata_id}) to system ID: {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)
    system_id = await _resolve_system_id(system_identifier)
    if not system_id:
        return "" # Helper function already logged the reason for failure.

    print(f"Attempting to apply specific update (errata ID: {errata_id}) to system: {system_identifier}")

    if not confirm:
        return f"CONFIRMATION REQUIRED: This will apply specific update (errata ID: {errata_id}) to the system {system_identifier}. Do you confirm?"

    async with httpx.AsyncClient(verify=UYUNI_MCP_SSL_VERIFY) as client:
        # The API expects a list of errata IDs, even if it's just one.
        payload = {"sid": int(system_id), "errataIds": [errata_id]}
        api_result = await _call_uyuni_api(
            client=client,
            method="POST",
            api_path="/rhn/manager/api/system/scheduleApplyErrata",
            json_body=payload,
            error_context=f"scheduling specific update (errata ID: {errata_id}) for system {system_identifier}",
            default_on_error=None # Helper returns None on error
        )

        if isinstance(api_result, list) and api_result and isinstance(api_result[0], int):
            action_id = api_result[0]
            success_message = f"Update (errata ID: {errata_id}) successfully scheduled for system {system_identifier}. Action URL: {UYUNI_SERVER}/rhn/schedule/ActionDetails.do?aid={action_id}"
            print(success_message)
            return success_message
        # Some schedule APIs might return int directly in result (though scheduleApplyErrata usually returns a list)
        elif isinstance(api_result, int): # Defensive check
            action_id = api_result
            success_message = f"Update (errata ID: {errata_id}) successfully scheduled. Action URL: {UYUNI_SERVER}/rhn/schedule/ActionDetails.do?aid={action_id}"
            print(success_message)
            return success_message
        else:
            if api_result is not None: # Log if not None but also not expected format
                print(f"Failed to schedule specific update (errata ID: {errata_id}) for system {system_identifier} or unexpected API result format. Result: {api_result}")
            return ""

@write_tool()
async def add_system(
    host: str,
    ctx: Context,
    activation_key: str = "",
    ssh_port: int = 22,
    ssh_user: str = "root",
    proxy_id: int = None,
    salt_ssh: bool = False,
    confirm: bool = False,
) -> str:
    """
    Adds a new system to be managed by Uyuni.

    This tool remotely connects to the specified host using SSH to register it.
    It requires an SSH private key to be configured in the UYUNI_SSH_PRIV_KEY
    environment variable for authentication.

    Args:
        host: Hostname or IP address of the target system to add.
        activation_key: The activation key for registering the system.
        ssh_port: The SSH port on the target machine (default: 22).
        ssh_user: The user to connect with via SSH (default: 'root').
        proxy_id: The system ID of a Uyuni proxy to use (optional).
        salt_ssh: Manage the system with Salt SSH (default: False).
        confirm: User confirmation is required to execute this action. Set to False
                 by default. If False, the tool returns a confirmation message. The
                 model must present this message to the user and, if they agree, call
                 the tool again with this parameter set to True.

    Returns:
        A confirmation message if 'confirm' is False.
        An error message if the UYUNI_SSH_PRIV_KEY environment variable is not set.
        A success message if the system is scheduled for addition successfully.
        An error message if the operation fails.
    """
    log_string = f"Attempting to add system ID: {host}"
    logger.info(log_string)
    await ctx.info(log_string)
    if ctx.session.check_client_capability(types.ClientCapabilities(elicitation=types.ElicitationCapability())):
        # Check for activation key
        if not activation_key:
            logger.info("Activation key not provided, prompting user for input.")
            result = await ctx.elicit(
                "An activation key is required to add a new system.",
                ActivationKeySchema,
            )
            if result.action == "accept":
                activation_key = result.data.activation_key
            elif result.action == "decline":
                return "System addition declined because no activation key was provided."
            else:  # 'cancel' or any other unhandled action
                return "System addition cancelled."
    elif not activation_key:  # Fallback if elicitation is not supported
        return "You need to provide an activation key."

    # Check if the system already exists
    active_systems = await _get_list_of_active_systems()
    for system in active_systems:
        if system.get('system_name') == host:
            message = f"System '{host}' already exists in Uyuni. No action taken."
            logger.info(message)
            await ctx.info(message)
            return message

    if not confirm:
        return f"CONFIRMATION REQUIRED: This will add system {host} with activation key {activation_key} to Uyuni. Do you confirm?"

    ssh_priv_key_raw = os.environ.get('UYUNI_SSH_PRIV_KEY')
    if not ssh_priv_key_raw:
        return "Error: UYUNI_SSH_PRIV_KEY environment variable is not set. Please set it to your SSH private key."

    # Unescape the raw string from the environment variable to convert literal '\n' to actual newlines for the JSON payload.
    ssh_priv_key = ssh_priv_key_raw.replace('\\n', '\n')

    print(f"Attempting to add system: {host}")

    ssh_priv_key_pass = os.environ.get('UYUNI_SSH_PRIV_KEY_PASS')
    if not ssh_priv_key_pass:
        ssh_priv_key_pass = ""

    payload = {
        "host": host,
        "sshPort": ssh_port,
        "sshUser": ssh_user,
        "sshPrivKey": ssh_priv_key,
        "sshPrivKeyPass": ssh_priv_key_pass,
        "activationKey": activation_key,
        "saltSSH": salt_ssh,
    }
    if proxy_id is not None:
        payload["proxyId"] = proxy_id
    logger.info(f"adding system {host}")

    async with httpx.AsyncClient(verify=False) as client:
        api_result = await _call_uyuni_api(
            client=client, method="POST",
            api_path="/rhn/manager/api/system/bootstrapWithPrivateSshKey",
            json_body=payload,
            error_context=f"adding system {host}",
            default_on_error=None,
            expect_timeout=True,
        )

    if api_result is TIMEOUT_HAPPENED:
        # The action was long-running and timed out, which is expected.
        # The task is likely running in the background on Uyuni.
        success_message = f"System {host} addition process started. It may take some time. Check the system list later for its status."
        logger.info(success_message)
        return success_message
    elif api_result == 1:  # The API returns 1 on success
        logger.info("api_result was 1")
        success_message = f"System {host} successfully scheduled to be added."
        print(success_message)
        return success_message
    else:
        logger.info(f"api result was NOT 1 {api_result}")
        return f"System {host} was NOT successfully scheduled to be added. Check server logs."


@write_tool()
async def remove_system(system_identifier: Union[str, int], ctx: Context, cleanup: bool = True, confirm: bool = False) -> str:
    """
    Removes/deletes a system from being managed by Uyuni.

    This is a destructive action and requires confirmation.

    Args:
        system_identifier: The unique identifier of the system to remove. It can be the system name (e.g. "buildhost") or the system ID (e.g. 1000010000).
        cleanup: If True (default), Uyuni will attempt to run cleanup scripts on the client before deletion.
                 If False, the system is deleted from Uyuni without attempting client-side cleanup.
        confirm: User confirmation is required. If False, the tool returns a confirmation prompt. The
                 model must ask the user and call the tool again with confirm=True if they agree.

    Returns:
        A confirmation message if 'confirm' is False.
        A success or error message string detailing the outcome.
    """
    log_string = f"Attempting to remove system with id {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)
    system_id = await _resolve_system_id(system_identifier)
    if not system_id:
        return "" # Helper function already logged the reason for failure.

    # Check if the system exists before proceeding
    active_systems = await _get_list_of_active_systems()
    if not any(s.get('system_id') == int(system_id) for s in active_systems):
        message = f"System with ID {system_id} not found."
        logger.warning(message)
        return message

    if not confirm:
        return (f"CONFIRMATION REQUIRED: This will permanently remove system {system_id} from Uyuni. "
                f"Client-side cleanup is currently {'ENABLED' if cleanup else 'DISABLED'}. Do you confirm?")

    cleanup_type = "FORCE_DELETE" if cleanup else "NO_CLEANUP"

    async with httpx.AsyncClient(verify=False) as client:
        api_result = await _call_uyuni_api(
            client=client,
            method="POST",
            api_path="/rhn/manager/api/system/deleteSystem",
            json_body={"sid": system_id, "cleanupType": cleanup_type},
            error_context=f"removing system ID {system_id}",
            default_on_error=None
        )

    if api_result == 1:
        success_message = f"System {system_identifier} was successfully removed."
        logger.info(success_message)
        return success_message
    else:
        error_message = f"Failed to remove system {system_identifier}. The API did not return success. Result: {api_result}"
        logger.error(error_message)
        return error_message

@mcp.tool()
async def get_systems_needing_security_update_for_cve(cve_identifier: str, ctx: Context) -> List[Dict[str, Any]]:
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

    log_string = f"Getting systems that need to apply CVE {cve_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)

    affected_systems_map = {}  # Use a dict to store unique systems by ID {system_id: {details}}

    find_by_cve_path = '/rhn/manager/api/errata/findByCve'
    list_affected_systems_path = '/rhn/manager/api/errata/listAffectedSystems'

    async with httpx.AsyncClient(verify=UYUNI_MCP_SSL_VERIFY) as client:
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
async def get_systems_needing_reboot(ctx: Context) -> List[Dict[str, Any]]:
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

    log_string = "Fetch list of system that require a reboot."
    logger.info(log_string)
    await ctx.info(log_string)

    systems_needing_reboot_list = []
    list_reboot_path = '/rhn/manager/api/system/listSuggestedReboot'

    async with httpx.AsyncClient(verify=UYUNI_MCP_SSL_VERIFY) as client:
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

@write_tool()
async def schedule_system_reboot(system_identifier: Union[str, int], ctx:Context, confirm: bool = False) -> str:

    """
    Schedules an immediate reboot for a specific system on the Uyuni server.

    Args:
        system_identifier: The unique identifier of the system. It can be the system name (e.g. "buildhost") or the system ID (e.g. 1000010000).
        confirm: False by default. Only set confirm to True if the user has explicetely confirmed. Ask the user for confirmation.

    The reboot is scheduled to occur as soon as possible (effectively "now").
    Returns:
        str: A message indicating the action ID if the reboot was successfully scheduled,
             e.g., "System reboot successfully scheduled. Action URL: ...".
             Returns an empty string if scheduling fails or an error occurs.
    """
    log_string = f"Schedule system reboot for system {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)
    system_id = await _resolve_system_id(system_identifier)
    if not system_id:
        return "" # Helper function already logged the reason for failure.

    if not confirm:
        return f"CONFIRMATION REQUIRED: This will reboot system {system_identifier}. Do you confirm?"

    schedule_reboot_path = '/rhn/manager/api/system/scheduleReboot'

    # Generate current time in ISO 8601 format (UTC)
    now_iso = datetime.now(timezone.utc).isoformat()

    async with httpx.AsyncClient(verify=UYUNI_MCP_SSL_VERIFY) as client:
        payload = {"sid": int(system_id), "earliestOccurrence": now_iso}
        api_result = await _call_uyuni_api(
            client=client,
            method="POST",
            api_path=schedule_reboot_path,
            json_body=payload,
            error_context=f"scheduling reboot for system {system_identifier}",
            default_on_error=None # Helper returns None on error
        )

        # Uyuni's scheduleReboot API returns an integer action ID directly in 'result'
        if isinstance(api_result, int):
            action_id = api_result
            action_detail_url = f"{UYUNI_SERVER}/rhn/schedule/ActionDetails.do?aid={action_id}"
            success_message = f"System reboot successfully scheduled. Action URL: {action_detail_url}"
            print(success_message)
            return success_message
        else:
            # Error message already printed by _call_uyuni_api if it returned None
            if api_result is not None: # Log if result is not None but also not an int
                print(f"Failed to schedule reboot for system {system_identifier} or unexpected API result format. Result: {api_result}")
            return ""

@mcp.tool()
async def list_all_scheduled_actions(ctx: Context) -> List[Dict[str, Any]]:
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

    log_string = "Listing all scheduled actions"
    logger.info(log_string)
    await ctx.info(log_string)

    list_actions_path = '/rhn/manager/api/schedule/listAllActions'
    processed_actions_list = []

    async with httpx.AsyncClient(verify=UYUNI_MCP_SSL_VERIFY) as client:
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

@write_tool()
async def cancel_action(action_id: int, ctx: Context, confirm: bool = False) -> str:
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

    log_string = f"Cancel action {action_id}"
    logger.info(log_string)
    await ctx.info(log_string)

    cancel_actions_path = '/rhn/manager/api/schedule/cancelActions'
 
    if not isinstance(action_id, int): # Basic type check, though FastMCP might handle this
        return "Invalid action ID provided. Must be an integer."

    if not confirm:
        return f"CONFIRMATION REQUIRED: This will schedule action {action_id} to be canceled. Do you confirm?"

    async with httpx.AsyncClient(verify=UYUNI_MCP_SSL_VERIFY) as client:
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

async def get_unscheduled_errata(system_id: int, ctx: Context) -> List[Dict[str, Any]]:
    """
    Provides a list of errata that are applicable to the system with the system_id
    passed as parameter and have not ben scheduled yet. All elements in the result are patches that are applicable
    for the system.

    If the system ID is invalid then the operation will fail.

    Args:
        sid: The integer ID of the system for which we want to know the list of applicable errata.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries with each dictionary defining a errata applicable
                            to the system given as a parameter.
                            Retruns an empty dictionary if no applicable errata for the system are found.
    """
    log_string = f"Getting list of unscheduled errata for system {system_id}"
    logger.info(log_string)
    await ctx.info(log_string)

    async with httpx.AsyncClient(verify=False) as client:
        get_unscheduled_errata = "/rhn/manager/api/system/getUnscheduledErrata"
        payload = {'sid': str(system_id)}
        unscheduled_errata_result = await _call_uyuni_api(
            client=client,
            method="GET",
            api_path=get_unscheduled_errata,
            params=payload,
            error_context=f"fetching unscheduled errata for system ID {system_id}",
            default_on_error=None
        )

        if isinstance(unscheduled_errata_result, list):
            for item in unscheduled_errata_result:
                item['system_id'] = system_id

            return unscheduled_errata_result
        else:
            if unscheduled_errata_result is not None:
                print(f"Failed to retrieve unscheduled errata for system ID {system_id} or \
                      unexpected API result format. Result: {unscheduled_errata_result}")
            return ""

def main_cli():

    logger.info("Running Uyuni MCP server.")

    if UYUNI_MCP_TRANSPORT == Transport.HTTP.value:
        mcp.run(transport="streamable-http")
    elif UYUNI_MCP_TRANSPORT == Transport.STDIO.value:
        mcp.run(transport="stdio")
    else:
        # Defaults to stdio transport anyway 
        # But I explicitety state it here for clarity
        mcp.run(transport="stdio")
