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

from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp import FastMCP, Context
from mcp import LoggingLevel, ServerSession, types

from .logging_config import get_logger, Transport
from .uyuni_api import call as call_uyuni_api, TIMEOUT_HAPPENED
from .config import CONFIG
from .auth import AuthProvider
from .errors import (
    UnexpectedResponse,
    NotFoundError
)

class ActivationKeySchema(BaseModel):
    activation_key: str

base_url = f'http://{CONFIG["UYUNI_MCP_HOST"]}:{CONFIG["UYUNI_MCP_PORT"]}'
auth_provider = AuthProvider(CONFIG["AUTH_SERVER"], base_url, CONFIG["UYUNI_MCP_WRITE_TOOLS_ENABLED"]) if CONFIG["AUTH_SERVER"] else None
product = CONFIG["UYUNI_PRODUCT_NAME"] if CONFIG["UYUNI_PRODUCT_NAME"] else "Uyuni" 
mcp = FastMCP("mcp-server-uyuni", auth=auth_provider)

logger = get_logger(
    log_file=CONFIG["UYUNI_MCP_LOG_FILE_PATH"],
    transport=CONFIG["UYUNI_MCP_TRANSPORT"],
    log_level=CONFIG["UYUNI_MCP_LOG_LEVEL"]
)

class AuthTokenMiddleware(Middleware):
    async def on_call_tool(self, ctx: MiddlewareContext, call_next):
        """
        Extracts the JWT token from the Authorization header (if present)
        and injects it into the context state for other tools to use.
        """
        fastmcp_ctx = ctx.fastmcp_context
        auth_header = fastmcp_ctx.request_context.request.headers['authorization']
        token = None
        if auth_header:
            # Expecting "Authorization: Bearer <token>"
            parts = auth_header.split()
            if len(parts) == 2 and parts[0] == "Bearer":
                token = parts[1]
                logger.debug("Successfully extracted token from header.")
            else:
                logger.warning(f"Malformed Authorization header received: {auth_header}")
        else:
            logger.debug("No Authorization header found in the request.")

        fastmcp_ctx.set_state('token', token)
        result = await call_next(ctx)
        return result

def write_tool(*decorator_args, **decorator_kwargs):
    """
    A decorator that registers a function as an MCP tool only if write
    tools are enabled via the UYUNI_MCP_WRITE_TOOLS_ENABLED environment variable.
    """
    # 2. This is the actual decorator that gets applied to the tool function.
    def decorator(func):
        if CONFIG["UYUNI_MCP_WRITE_TOOLS_ENABLED"]:
            # 3a. If enabled, it applies the @mcp.tool() decorator, registering the function.
            return mcp.tool(*decorator_args, **decorator_kwargs)(func)

        # 3b. If disabled, it does nothing and just returns the original,
        #     un-decorated function. It is never registered.
        return func

    # 1. The factory returns the decorator.
    return decorator

def _to_bool(value) -> bool:
    """
    Convert truthy string/boolean/integer values to a boolean.
    Accepts: True, 'true', 'yes', '1', 1, etc.
    """
    return str(value).lower() in ("true", "yes", "1")

DYNAMIC_DESCRIPTION = f"""
    Fetches a list of active systems from the {product} server, returning their names and IDs.

    The returned list contains system objects, each of which consists of a 'system_name'
    and a numerical 'system_id' field for an active system.

    You SHOULD use the 'system_id' to call other system related tools.

    Returns:
        A list of system objects (system_name and system_id).
        Returns an empty list if no systems are found.

    Example:
        [
            {{ "system_name": "ubuntu.example.com", "system_id": 100010000 }},
            {{ "system_name": "opensuseleap15.example.com", "system_id": 100010001 }}
        ]
    """
@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def list_systems(ctx: Context) -> List[Dict[str, Any]]:
    log_string = "Getting list of active systems"
    logger.info(log_string)
    await ctx.info(log_string)

    return await _list_systems(ctx.get_state('token'))

async def _list_systems(token: str) -> List[Dict[str, Union[str, int]]]:

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        systems_data_result = await call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/listSystems",
            error_context="fetching active systems",
            token=token
        )

    filtered_systems = []
    if isinstance(systems_data_result, list):
        for system in systems_data_result:
            if isinstance(system, dict):
                filtered_systems.append({'system_name': system.get('name'), 'system_id': system.get('id')})
            else:
                logger.warning(f"Unexpected item format in system list: {system}")
    elif systems_data_result:
        logger.warning(f"Expected a list of systems, but received: {type(systems_data_result)}")

    return filtered_systems

DYNAMIC_DESCRIPTION = f"""Gets details of the specified system.

    Args:
        system_identifier: The system name (e.g., "buildhost.example.com") or system ID (e.g., 1000010000).
            Prefer using numerical system IDs instead of system names when possible.

    Returns:
        An object that contains the following attributes of the system:
            - system_id: The numerical ID of the system within {product} server
            - system_name: The registered system name, usually its main FQDN
            - last_boot: The last boot time of the system known to {product} server
            - uuid: UUID of the system if it is a virtual instance, null otherwise.
            - cpu: An object with the following CPU attributes of the system:
                - family: The CPU family
                - mhz: The CPU clock speed
                - model: The CPU model
                - vendor: The CPU vendor
                - arch: The CPU architecture
            - network: Network addresses and the hostname of the system.
                - hostname: The hostname of the system
                - ip: The IPv4 address of the system
                - ip6: The IPv6 address of the system
            - installed_products: List of installed products on the system.
                You can use this field to identify what OS the system is running.

        Example:
            {{
              "system_id": "100010001",
              "system_name": "opensuse.example.local",
              "last_boot": "2025-04-01T15:21:56Z",
              "uuid": "a8c3f40d-c1ae-406e-9f9b-96e7d5fdf5a3",
              "cpu": {{
                "family": "15",
                "mhz": "1896.436",
                "model": "QEMU Virtual CPU",
                "vendor": "AuthenticAMD",
                "arch": "x86_64"
              }},
              "network": {{
                "hostname": "opensuse.example.local",
                "ip": "192.168.122.193",
                "ip6": "fe80::5054:ff:fe12:3456"
              }},
              "installed_products": [
                {{
                  "release": "0",
                  "name": "SLES",
                  "isBaseProduct": true,
                  "arch": "x86_64",
                  "version": "15.7",
                  "friendlyName": "SUSE Linux Enterprise Server 15 SP7 x86_64"
                }},
                {{
                  "release": "0",
                  "name": "sle-module-basesystem",
                  "isBaseProduct": false,
                  "arch": "x86_64",
                  "version": "15.7",
                  "friendlyName": "Basesystem Module 15 SP7 x86_64"
                }}
              ]
            }}
        """

@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def get_system_details(system_identifier: Union[str, int], ctx: Context):
    log_string = f"Getting details of system {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)
    return await _get_system_details(system_identifier, ctx.get_state('token'))

async def _get_system_details(system_identifier: Union[str, int], token: str) -> Dict[str, Any]:
    system_id = await _resolve_system_id(system_identifier, token)

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        details_call: Coroutine = call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getDetails",
            params={'sid': system_id},
            error_context=f"Fetching details for system {system_id}",
            token=token
        )
        uuid_call: Coroutine = call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getUuid",
            params={'sid': system_id},
            error_context=f"Fetching UUID for system {system_id}",
            token=token
        )
        cpu_call: Coroutine = call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getCpu",
            params={'sid': system_id},
            error_context=f"Fetching CPU information for system {system_id}",
            token=token
        )
        network_call: Coroutine = call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getNetwork",
            params={'sid': system_id},
            error_context=f"Fetching network information for system {system_id}",
            token=token
        )
        products_call: Coroutine = call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getInstalledProducts",
            params={'sid': system_id},
            error_context=f"Fetching installed product information for system {system_id}",
            token=token
        )

        results = await asyncio.gather(
            details_call,
            uuid_call,
            cpu_call,
            network_call,
            products_call
        )

        details_result, uuid_result, cpu_result, network_result, products_result = results

    if isinstance(details_result, dict):
        # Only add the identifier if the API returned actual data
        system_details = {
            "system_id": details_result["id"],
            "system_name": details_result["profile_name"],
            "last_boot": details_result["last_boot"],
            "uuid": uuid_result
        }

        if isinstance(cpu_result, dict):
            cpu_details = {
                "family": cpu_result["family"],
                "mhz": cpu_result["mhz"],
                "model": cpu_result["model"],
                "vendor": cpu_result["vendor"],
                "arch": cpu_result["arch"]
            }
            system_details["cpu"] = cpu_details
        else:
            logger.error(f"Unexpected API response when getting CPU information for system {system_id}")
            logger.error(cpu_result)

        if isinstance(network_result, dict):
            network_details = {
                "hostname": network_result["hostname"],
                "ip": network_result["ip"],
                "ip6": network_result["ip6"]
            }
            system_details["network"] = network_details
        else:
            logger.error(f"Unexpected API response when getting network information for system {system_id}")
            logger.error(network_result)

        if isinstance(products_result, list):
            base_product = [p["friendlyName"] for p in products_result if p["isBaseProduct"]]
            system_details["installed_products"] = base_product
        else:
            logger.error(f"Unexpected API response when getting installed products for system {system_id}")
            logger.error(products_result)

        return system_details
    else:
        logger.error(f"Unexpected API response when getting details for system {system_id}")
        logger.error(details_result)
    return {}

DYNAMIC_DESCRIPTION = f"""Gets the event/action history of the specified system.

    The output of this tool is paginated and can be controlled via 'offset' and 'limit' parameters.

    Optionally, the 'earliest_date' parameter can be set to an ISO-8601 date to specify the earliest date
    for the events to be returned.

    You SHOULD use 'get_system_event_details' tool with an event ID to get the details of an event.

    You SHOULD use this tool to check the status of a reboot. A reboot is finished when
    its related action is completed.

    Args:
        system_identifier: The system name (e.g., "buildhost.example.com") or system ID (e.g., 1000010000).
            Prefer using numerical system IDs instead of system names when possible.
        offset: Number of results to skip
        limit: Maximum number of results
        earliest_date: The earliest ISO-8601 date-time string to filter the events (optional)

    Returns:
        A list of event/action status, newest to oldest.

        A single event object contains the following attributes:

            - id: The ID of the event
            - history_type: The type of the event
            - status: Event's status (completed, failed, etc.)
            - summary: A short summary of the event
            - completed: ISO-8601 date & time of the event's completion timestamp

        Example:
            [
              {{
                "id": 12,
                "history_type": "System reboot",
                "status": "Completed",
                "summary": "System reboot scheduled by admin",
                "completed": "2025-11-27T15:37:28Z"
              }},
              {{
                "id": 357,
                "history_type": "Patch Update",
                "status": "Failed"
                "summary": "Patch Update: Security update for the Linux Kernel",
                "completed": "2025-11-28T13:11:49Z"
              }}
            ]
        """
@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def get_system_event_history(system_identifier: Union[str, int], ctx: Context, offset: int = 0, limit: int = 10, earliest_date: str = None):
    log_string = f"Getting event history of system {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)
    return await _get_system_event_history(system_identifier, limit, offset, earliest_date, ctx.get_state('token'))

async def _get_system_event_history(system_identifier: Union[str, int], limit: int, offset: int, earliest_date: str, token: str) -> list[Any]:
    system_id = await _resolve_system_id(system_identifier, token)

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        params = {'sid': system_id, 'limit': limit, 'offset': offset}
        if earliest_date:
            params['earliestDate'] = earliest_date

        result = await call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getEventHistory",
            params=params,
            error_context=f"Fetching event history for system {system_id}",
            token=token
        )

    if isinstance(result, list):
        return result
    else:
        logger.error(f"Unexpected API response when getting event history for system {system_id}")
        logger.error(result)
    return {}

DYNAMIC_DESCRIPTION = f"""Gets the details of the event associated with the especified server and event ID.

    The event ID must be a value returned by the 'get_system_event_history' tool.

    Args:
        system_identifier: The system name (e.g., "buildhost.example.com") or system ID (e.g., 1000010000).
            Prefer using numerical system IDs instead of system names when possible.
        event_id: The ID of the event

    Returns:
        An object that contains the details of the associated event.

        The event object contains the following attributes:

            - id: The ID of the event
            - history_type: The type of the event
            - status: Event's status (completed, failed, etc.)
            - summary: A short summary of the event
            - created: ISO-8601 date & time of the event's creation timestamp
            - picked_up: ISO-8601 date & time when the event was picked up by the system
            - completed: ISO-8601 date & time of the event's completion timestamp
            - earliest_action: The earliest ISO-8601 date & time this action should occur
            - result_msg: The result string of the action executed on the system
            - result_code: The result code of the action executed on the system
            - additional_info: Additional information on the event, if available

        Example:
            [
              {{
                "id": 12,
                "history_type": "System reboot",
                "status": "Completed",
                "summary": "System reboot scheduled by admin",
                "completed": "2025-11-27T15:37:28Z"
              }},
              {{
                "id": 357,
                "history_type": "Patch Update",
                "status": "Failed"
                "summary": "Patch Update: Security update for the Linux Kernel",
                "completed": "2025-11-28T13:11:49Z"
              }}
            ]
        """

@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def get_system_event_details(system_identifier: Union[str, int], event_id: int, ctx: Context):
    log_string = f"Getting event history of system {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)
    return await _get_system_event_details(system_identifier, event_id, ctx.get_state('token'))

async def _get_system_event_details(system_identifier: Union[str, int], event_id: int, token: str) -> Dict[str, Any]:
    system_id = await _resolve_system_id(system_identifier, token)

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        result = await call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getEventDetails",
            params={'sid': system_id, 'eid': event_id},
            error_context=f"Fetching event details for event {event_id}, system {system_id}",
            token=token
        )

    if isinstance(result, dict):
        return result
    else:
        logger.error(f"Unexpected API response when getting event details for event {event_id}, system {system_id}")
        logger.error(result)
    return {}

DYNAMIC_DESCRIPTION = f"""
    Lists systems that match the provided hostname.

    Args:
        name: The system name (e.g., "buildhost.example.com").

    Returns:
        A list of system objects (system_name and system_id) that match the provided name.
        Returns an empty list if no systems are found.

    Example:
        [
            {{ "system_name": "ubuntu1.example.com", "system_id": 100010000 }},
            {{ "system_name": "ubuntu2.example.com", "system_id": 100010001 }}
        ]
    """
@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def find_systems_by_name(name: str, ctx: Context) -> List[Dict[str, Union[str, int]]]:
    log_string = f"Finding systems with name {name}"
    logger.info(log_string)
    await ctx.info(log_string)

    token = ctx.get_state('token')
    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        systems_data_result = await call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/search/hostname",
            params={'searchTerm': name},
            error_context=f"finding systems with name {name}",
            token=token
        )

    filtered_systems = []
    if isinstance(systems_data_result, list):
        for system in systems_data_result:
            if isinstance(system, dict):
                filtered_systems.append({'system_name': system.get('name'), 'system_id': system.get('id')})
            else:
                logger.warning(f"Unexpected item format in system list: {system}")
    elif systems_data_result:
        logger.warning(f"Expected a list of systems, but received: {type(systems_data_result)}")

    return filtered_systems

DYNAMIC_DESCRIPTION= f"""
    Lists systems that match the provided IP address.

    Args:
        ip_address: The system IP address (e.g., "192.168.122.193").

    Returns:
        A list of system objects (system_name, system_id and ip) that match the provided IP address.
        Returns an empty list if no systems are found.

    Example:
        [
            {{
              "system_name": "ubuntu.example.com",
              "system_id": 100010000,
              "ip": "192.168.122.193"
            }}
        ]
    """
@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def find_systems_by_ip(ip_address: str, ctx: Context) -> List[Dict[str, Union[str, int]]]:
    log_string = f"Finding systems with IP address {ip_address}"
    logger.info(log_string)
    await ctx.info(log_string)

    token = ctx.get_state('token')
    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        systems_data_result = await call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/search/ip",
            params={'searchTerm': ip_address},
            error_context=f"finding systems with IP address {ip_address}",
            token=token
        )

    filtered_systems = []
    if isinstance(systems_data_result, list):
        for system in systems_data_result:
            if isinstance(system, dict):
                filtered_systems.append({'system_name': system.get('name'), 'system_id': system.get('id'), 'ip': system.get('ip')})
            else:
                logger.warning(f"Unexpected item format in system list: {system}")
    elif systems_data_result:
        logger.warning(f"Expected a list of systems, but received: {type(systems_data_result)}")

    return filtered_systems

async def _resolve_system_id(system_identifier: Union[str, int], token: str) -> str:
    """
    Resolves a system identifier, which can be a name or an ID, to a numeric system ID string.

    If the identifier is numeric (or a string of digits), it's returned as a string.
    If it's a non-numeric string, it's treated as a name and the ID is looked up via the system.getId API endpoint.

    Args:
        system_identifier: The system name (e.g., "buildhost.example.com") or system ID (e.g., 1000010000).

    Returns:
        str: The numeric system ID as a string.

    Raises:
        NotFoundError: If no systems match the provided name.
        UnexpectedResponse: If the {product} API returns an unexpected payload (non-list, malformed items,
                            or multiple matches for a single name).
    """
    id_str = str(system_identifier)
    if id_str.isdigit():
        return id_str

    # If it's not a digit string, it must be a name.
    system_name = id_str
    logger.info(f"System identifier '{system_name}' is not numeric, treating as a name and looking up ID.")

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        api_path = "/rhn/manager/api/system/getId"
        # The result from system.getId is an array of system structs
        systems_list = await call_uyuni_api(
            client=client,
            method="GET",
            api_path=api_path,
            params={'name': system_name},
            error_context=f"resolving system ID for name '{system_name}'",
            token=token
        )

    if not isinstance(systems_list, list):
        logger.error(f"Expected a list of systems for name '{system_name}', but received: {type(systems_list)}")
        raise UnexpectedResponse(CONFIG["UYUNI_SERVER"] + api_path, repr(systems_list))

    if not systems_list:
        logger.error(f"System with name '{system_name}' not found.")
        raise NotFoundError("System", system_name)

    if len(systems_list) > 1:
        logger.error(f"Multiple systems found with name '{system_name}'.")
        raise UnexpectedResponse(CONFIG["UYUNI_SERVER"] + api_path, f"Multiple systems found for name {system_name}")

    first_system = systems_list[0]
    if isinstance(first_system, dict) and 'id' in first_system:
        resolved_id = str(first_system['id'])
        logger.info(f"Found ID {resolved_id} for system name '{system_name}'.")
        return resolved_id
    else:
        logger.error(f"System data for '{system_name}' is malformed. Expected a dict with 'id'. Got: {first_system}")
        raise UnexpectedResponse(CONFIG["UYUNI_SERVER"] + api_path, f"Malformed system data: {first_system!r}")

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


    msg = f"Fetching CVEs for advisory {advisory_name}"
    logger.info(msg)
    await ctx.info(msg)

    if not advisory_name:
        msg = f"advisory_name is missing for system ID {system_id}, cannot fetch CVEs."
        logger.error(msg)
        await ctx.error(msg)
        return []

    logger.info(f"Fetching CVEs for advisory: {advisory_name} (system ID: {system_id})")
    cve_list_from_api = await call_uyuni_api(
        client=client,
        method="GET",
        api_path=list_cves_path,
        error_context=f"fetching CVEs for advisory {advisory_name} (system ID: {system_id})",
        params={'advisoryName': advisory_name},
        perform_login=False, # Login is handled by the calling function
    )

    processed_cves = []
    if isinstance(cve_list_from_api, list):
        processed_cves = [str(cve) for cve in cve_list_from_api if cve]

    return processed_cves

DYNAMIC_DESCRIPTION = f"""
    Checks if a specific system in the {product} server has pending updates (relevant errata),
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
                        if no pending updates are found.
    """
@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def get_system_updates(system_identifier: Union[str, int], ctx: Context) -> Dict[str, Any]:

    log_string = f"Checking pending updates for system {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)
    return await _get_system_updates(system_identifier, ctx)

async def _get_system_updates(system_identifier: Union[str, int], ctx: Context) -> Dict[str, Any]:
    token = ctx.get_state('token')
    system_id = await _resolve_system_id(system_identifier, token)

    list_cves_api_path = '/rhn/manager/api/errata/listCves'

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        relevant_errata_call: Coroutine = call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getRelevantErrata",
            params={'sid': system_id},
            error_context=f"checking updates for system {system_identifier}",
            token=token
        )

        unscheduled_errata_call: Coroutine = call_uyuni_api(
            client=client,
            method="GET",
            api_path="/rhn/manager/api/system/getUnscheduledErrata",
            params={'sid': str(system_id)},
            error_context=f"checking unscheduled errata for system ID {system_id}",
            token=token
        )

        results = await asyncio.gather(
            relevant_errata_call,
            unscheduled_errata_call
        )
        relevant_updates_list, unscheduled_updates_list = results

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

DYNAMIC_DESCRIPTION = f"""
    Checks all active systems in the {product} server for pending updates.

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

@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def check_all_systems_for_updates(ctx: Context) -> List[Dict[str, Any]]:
    log_string = "Checking all system for updates"
    logger.info(log_string)
    await ctx.info(log_string)

    systems_with_updates = []
    active_systems = await _list_systems(ctx.get_state('token')) # Get the list of all systems

    if not active_systems:
        msg = "No active systems found."
        logger.warning(msg)
        await ctx.warning(msg)
        return []

    msg = f"Checking {len(active_systems)} systems for updates..."
    logger.info(msg)
    await ctx.info(msg)

    total_systems = len(active_systems)
    for i, system_summary in enumerate(active_systems):
        system_id = system_summary.get('system_id')
        system_name = system_summary.get('system_name')

        await ctx.report_progress(i, total_systems)
        msg = f"Checking updates for system: {system_name} (ID: {system_id})"
        logger.info(msg)
        await ctx.info(msg)
        # Use the existing get_system_updates tool
        update_check_result = await _get_system_updates(system_id, ctx)

        if update_check_result.get('has_pending_updates', False):
            # If the system has updates, add its info and update details to the result list
            systems_with_updates.append({
                'system_name': system_name,
                'system_id': system_id,
                'update_count': update_check_result.get('update_count', 0),
                'updates': update_check_result.get('updates', [])
            })
        # else: System has no updates, do nothing for this system
    await ctx.report_progress(total_systems, total_systems)

    msg = f"Finished checking systems. Found {len(systems_with_updates)} systems with updates."
    logger.info(msg)
    await ctx.info(msg)
    return systems_with_updates

DYNAMIC_DESCRIPTION = f"""
    Checks for pending updates on a system, schedules all of them to be applied,
    and returns the action ID of the scheduled task.

    This tool first calls 'get_system_updates' to determine relevant errata.
    If updates are found, it then calls the 'system/scheduleApplyErrata' API
    endpoint to apply all found errata.

    Args:
        system_identifier: The unique identifier of the system. It can be the system name (e.g. "buildhost") or the system ID (e.g. 1000010000).
        confirm: User confirmation is required to execute this action. This parameter
                 is `False` by default. To obtain the confirmation message that must
                 be presented to the user, the model must first call the tool with
                 `confirm=False`. If the user agrees, the model should call the tool
                 a second time with `confirm=True`.

    Returns:
        str: The action url if updates were successfully scheduled.
             Otherwise, returns an empty string.
    """
@write_tool(description = DYNAMIC_DESCRIPTION)
async def schedule_pending_updates_to_system(system_identifier: Union[str, int], ctx: Context, confirm: Union[bool, str] = False) -> str:

    msg = f"Attempting to apply pending updates for system ID: {system_identifier}"
    logger.info(msg)
    await ctx.info(msg)

    is_confirmed = _to_bool(confirm)
    if not is_confirmed:
        return f"CONFIRMATION REQUIRED: This will apply pending updates to the system {system_identifier}.  Do you confirm?"

    token = ctx.get_state('token')
    update_info = await _get_system_updates(system_identifier, ctx)

    if not update_info or not update_info.get('has_pending_updates'):
        msg = f"No pending updates found for system {system_identifier}."
        logger.info(msg)
        return msg

    errata_list = update_info.get('updates', [])
    if not errata_list:
        # This case should ideally be covered by 'has_pending_updates' being false,
        # but good to have a safeguard.
        msg = f"Update check for system {system_identifier} indicated updates, but the updates list is empty."
        logger.warning(msg)
        return msg

    errata_ids = [erratum.get('update_id') for erratum in errata_list if erratum.get('update_id') is not None]
    if not errata_ids:
        msg = f"Could not extract any valid errata IDs for system {system_identifier} from the update information: {errata_list}"
        logger.error(msg)
        return msg

    system_id = await _resolve_system_id(system_identifier, token)
    msg = f"Found {len(errata_ids)} errata to apply for system {system_identifier} (ID: {system_id}). IDs: {errata_ids}"
    logger.info(msg)
    await ctx.info(msg)

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        payload = {"sid": int(system_id), "errataIds": errata_ids}
        api_result = await call_uyuni_api(
            client=client,
            method="POST",
            api_path="/rhn/manager/api/system/scheduleApplyErrata",
            json_body=payload,
            error_context=f"scheduling errata application for system {system_identifier}",
            token=token
        )

        if isinstance(api_result, list) and api_result and isinstance(api_result[0], int):
            action_id = api_result[0]
            logger.info(f"Successfully scheduled action {action_id} to apply {len(errata_ids)} errata to system {system_identifier}.")
            return "Update successfully scheduled at " + CONFIG["UYUNI_SERVER"] + "/rhn/schedule/ActionDetails.do?aid=" + str(action_id)
        else:
            msg = f"Failed to schedule errata for system {system_identifier}. Unexpected API response format. Result: {api_result}"
            logger.error(msg)
            return msg


DYNAMIC_DESCRIPTION = f"""
    Schedules a specific update (erratum) to be applied to a system.

    Args:
        system_identifier: The unique identifier of the system. It can be the system name (e.g. "buildhost") or the system ID (e.g. 1000010000).
        errata_id: The unique identifier of the erratum (also referred to as update ID) to be applied. It must be an integer.
        confirm: User confirmation is required to execute this action. This parameter
                 is `False` by default. To obtain the confirmation message that must
                 be presented to the user, the model must first call the tool with
                 `confirm=False`. If the user agrees, the model should call the tool
                 a second time with `confirm=True`.

    Returns:
        str: The action URL if the update was successfully scheduled.
             Otherwise, returns an empty string.
    """
@write_tool(description = DYNAMIC_DESCRIPTION)
async def schedule_specific_update(system_identifier: Union[str, int], errata_id: Union[str, int], ctx: Context, confirm: Union[bool, str] = False) -> str:

    log_string = f"Attempting to apply specific update (errata ID: {errata_id}) to system ID: {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)

    is_confirmed = _to_bool(confirm)

    try:
        errata_id_int = int(errata_id)
    except (ValueError, TypeError):
        return f"Invalid errata ID '{errata_id}'. The ID must be an integer."

    token = ctx.get_state('token')
    system_id = await _resolve_system_id(system_identifier, token)

    logger.info(f"Attempting to apply specific update (errata ID: {errata_id}) to system: {system_identifier}")

    if not is_confirmed:
        return f"CONFIRMATION REQUIRED: This will apply specific update (errata ID: {errata_id}) to the system {system_identifier}. Do you confirm?"

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        # The API expects a list of errata IDs, even if it's just one.
        payload = {"sid": int(system_id), "errataIds": [errata_id_int]}
        api_result = await call_uyuni_api(
            client=client,
            method="POST",
            api_path="/rhn/manager/api/system/scheduleApplyErrata",
            json_body=payload,
            error_context=f"scheduling specific update (errata ID: {errata_id_int}) for system {system_identifier}",
            token=token
        )

        if isinstance(api_result, list) and api_result and isinstance(api_result[0], int):
            action_id = api_result[0]
            success_message = f"Update (errata ID: {errata_id_int}) successfully scheduled for system {system_identifier}. Action URL: {CONFIG['UYUNI_SERVER']}/rhn/schedule/ActionDetails.do?aid={action_id}"
            logger.info(success_message)
            return success_message
        # Some schedule APIs might return int directly in result (though scheduleApplyErrata usually returns a list)
        elif isinstance(api_result, int): # Defensive check
            action_id = api_result
            success_message = f"Update (errata ID: {errata_id_int}) successfully scheduled. Action URL: {CONFIG['UYUNI_SERVER']}/rhn/schedule/ActionDetails.do?aid={action_id}"
            logger.info(success_message)
            return success_message
        else:
            msg = f"Failed to schedule specific update (errata ID: {errata_id_int}) for system {system_identifier} or unexpected API result format. Result: {api_result}"
            logger.error(msg)
            return msg

DYNAMIC_DESCRIPTION = f"""
    Adds a new system to be managed by {product}.

    This tool remotely connects to the specified host using SSH to register it.
    It requires an SSH private key to be configured in the UYUNI_SSH_PRIV_KEY
    environment variable for authentication.

    Args:
        host: Hostname or IP address of the target system to add.
        activation_key: The activation key for registering the system.
        ssh_port: The SSH port on the target machine (default: 22).
        ssh_user: The user to connect with via SSH (default: 'root').
        proxy_id: The system ID of a {product} proxy to use (optional).
        salt_ssh: Manage the system with Salt SSH (default: False).
        confirm: User confirmation is required to execute this action. This parameter
                 is `False` by default. To obtain the confirmation message that must
                 be presented to the user, the model must first call the tool with
                 `confirm=False`. If the user agrees, the model should call the tool
                 a second time with `confirm=True`.

    Returns:
        A confirmation message if 'confirm' is False.
        An error message if the UYUNI_SSH_PRIV_KEY environment variable is not set.
        A success message if the system is scheduled for addition successfully.
        An error message if the operation fails.
    """
@write_tool(description = DYNAMIC_DESCRIPTION)
async def add_system(
    host: str,
    ctx: Context,
    activation_key: str = "",
    ssh_port: int = 22,
    ssh_user: str = "root",
    proxy_id: int = None,
    salt_ssh: bool = False,
    confirm: Union[bool, str] = False,
) -> str:
    log_string = f"Attempting to add system ID: {host}"
    logger.info(log_string)
    await ctx.info(log_string)

    is_confirmed = _to_bool(confirm)

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

    token = ctx.get_state('token')

    # Check if the system already exists
    active_systems = await _list_systems(token)
    for system in active_systems:
        if system.get('system_name') == host:
            message = f"System '{host}' already exists in {product}. No action taken."
            logger.info(message)
            await ctx.info(message)
            return message

    if not is_confirmed:
        return f"CONFIRMATION REQUIRED: This will add system {host} with activation key {activation_key} to {product}. Do you confirm?"

    ssh_priv_key_raw = os.environ.get('UYUNI_SSH_PRIV_KEY')
    if not ssh_priv_key_raw:
        return "Error: UYUNI_SSH_PRIV_KEY environment variable is not set. Please set it to your SSH private key."

    # Unescape the raw string from the environment variable to convert literal '\n' to actual newlines for the JSON payload.
    ssh_priv_key = ssh_priv_key_raw.replace('\\n', '\n')

    logger.info(f"Attempting to add system: {host}")

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

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        api_result = await call_uyuni_api(
            client=client, method="POST",
            api_path="/rhn/manager/api/system/bootstrapWithPrivateSshKey",
            json_body=payload,
            error_context=f"adding system {host}",
            token=token,
            expect_timeout=True,
        )

    if api_result is TIMEOUT_HAPPENED:
        # The action was long-running and timed out, which is expected.
        # The task is likely running in the background on product.
        success_message = f"System {host} addition process started. It may take some time. Check the system list later for its status."
        logger.info(success_message)
        return success_message
    elif api_result == 1:  # The API returns 1 on success
        logger.info("api_result was 1")
        success_message = f"System {host} successfully scheduled to be added."
        logger.info(success_message)
        return success_message
    else:
        logger.info(f"api result was NOT 1 {api_result}")
        return f"System {host} was NOT successfully scheduled to be added. Check server logs."

DYNAMIC_DESCRIPTION = f"""
    Removes/deletes a system from being managed by {product}.

    This is a destructive action and requires confirmation.

    Args:
        system_identifier: The unique identifier of the system to remove. It can be the system name (e.g. "buildhost") or the system ID (e.g. 1000010000).
        cleanup: If True (default), {product} will attempt to run cleanup scripts on the client before deletion.
                 If False, the system is deleted from {product} without attempting client-side cleanup.
        confirm: User confirmation is required to execute this action. This parameter
                 is `False` by default. To obtain the confirmation message that must
                 be presented to the user, the model must first call the tool with
                 `confirm=False`. If the user agrees, the model should call the tool
                 a second time with `confirm=True`.

    Returns:
        A confirmation message if 'confirm' is False.
        A success or error message string detailing the outcome.
    """
@write_tool(description = DYNAMIC_DESCRIPTION)
async def remove_system(system_identifier: Union[str, int], ctx: Context, cleanup: bool = True, confirm: Union[bool, str] = False) -> str:
    log_string = f"Attempting to remove system with id {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)

    is_confirmed = _to_bool(confirm)

    token = ctx.get_state('token')
    system_id = await _resolve_system_id(system_identifier, token)

    # Check if the system exists before proceeding
    active_systems = await _list_systems(token)
    if not any(s.get('system_id') == int(system_id) for s in active_systems):
        message = f"System with ID {system_id} not found."
        logger.warning(message)
        return message

    if not is_confirmed:
        return (f"CONFIRMATION REQUIRED: This will permanently remove system {system_id} from {product}. "
                f"Client-side cleanup is currently {'ENABLED' if cleanup else 'DISABLED'}. Do you confirm?")

    cleanup_type = "FORCE_DELETE" if cleanup else "NO_CLEANUP"

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        api_result = await call_uyuni_api(
            client=client,
            method="POST",
            api_path="/rhn/manager/api/system/deleteSystem",
            json_body={"sid": system_id, "cleanupType": cleanup_type},
            error_context=f"removing system ID {system_id}",
            token=token
        )

    if api_result == 1:
        success_message = f"System {system_identifier} was successfully removed."
        logger.info(success_message)
        return success_message
    else:
        error_message = f"Failed to remove system {system_identifier}. The API did not return success. Result: {api_result}"
        logger.error(error_message)
        return error_message

DYNAMIC_DESCRIPTION = f"""
    Finds systems requiring a security update for a specific CVE identifier.

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
@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def list_systems_needing_update_for_cve(cve_identifier: str, ctx: Context) -> List[Dict[str, Any]]:

    log_string = f"Getting systems that need to apply CVE {cve_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)

    affected_systems_map = {}  # Use a dict to store unique systems by ID {system_id: {details}}

    find_by_cve_path = '/rhn/manager/api/errata/findByCve'
    list_affected_systems_path = '/rhn/manager/api/errata/listAffectedSystems'

    token = ctx.get_state('token')
    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        # 1. Call findByCve (login will be handled by the helper)
        logger.info(f"Searching for errata related to CVE: {cve_identifier}")
        errata_list = await call_uyuni_api(
            client=client,
            method="GET",
            api_path=find_by_cve_path,
            params={'cveName': cve_identifier},
            error_context=f"finding errata for CVE {cve_identifier}",
            token=token,
        )

        if errata_list is None: # API call failed
            return []
        if not isinstance(errata_list, list):
            msg = f"Expected a list of errata for CVE {cve_identifier}, but received: {type(errata_list)}"
            logger.error(msg)
            await ctx.error(msg)
            return []
        if not errata_list:
            msg = f"No errata found for CVE {cve_identifier}."
            logger.info(msg)
            await ctx.info(msg)
            return []

        # 2. For each erratum, call listAffectedSystems
        for erratum in errata_list:
            advisory_name = erratum.get('advisory_name')
            if not advisory_name:
                logger.warning(f"Skipping erratum due to missing 'advisory_name': {erratum}")
                continue

            logger.info(f"Fetching systems affected by advisory: {advisory_name} (related to CVE: {cve_identifier})")
            systems_data_result = await call_uyuni_api(
                client=client,
                method="GET",
                api_path=list_affected_systems_path,
                params={'advisoryName': advisory_name},
                error_context=f"listing affected systems for advisory {advisory_name}",
                perform_login=False, # Login already performed for this client session
            )

            if systems_data_result is None: # API call failed for this advisory
                continue # Move to the next advisory
            if not isinstance(systems_data_result, list):
                logger.warning(f"Expected list of affected systems for {advisory_name}, got {type(systems_data_result)}")
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
                        logger.warning(f"Received system data with missing ID or name for advisory {advisory_name}: {system_info}")
                else:
                    logger.warning(f"Unexpected item format in affected systems list for advisory {advisory_name}: {system_info}")

    if not affected_systems_map:
        msg = f"No systems found affected by CVE {cve_identifier} after checking all related errata."
        logger.info(msg)
        await ctx.info(msg)
    else:
        logger.info(f"Found {len(affected_systems_map)} unique system(s) affected by CVE {cve_identifier}.")

    return list(affected_systems_map.values())

DYNAMIC_DESCRIPTION = f"""
    Fetches a list of systems from the {product} server that require a reboot.

    The returned list contains dictionaries, each with 'system_id' (int),
    'system_name' (str), and 'reboot_status' (str, typically 'reboot_required')
    for a system that has been identified by {product} as needing a reboot.

    Returns:
        List[Dict[str, Any]]: A list of system dictionaries (system_id, system_name, reboot_status)
                              for systems requiring a reboot. Returns an empty list
                              if no systems require a reboot.
    """
@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def list_systems_needing_reboot(ctx: Context) -> List[Dict[str, Any]]:

    log_string = "Fetch list of system that require a reboot."
    logger.info(log_string)
    await ctx.info(log_string)

    systems_needing_reboot_list = []
    list_reboot_path = '/rhn/manager/api/system/listSuggestedReboot'

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        reboot_data_result = await call_uyuni_api(
            client=client,
            method="GET",
            api_path=list_reboot_path,
            error_context="fetching systems needing reboot",
            token=ctx.get_state('token')
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
                    logger.warning(f"Unexpected item format in reboot list: {system_info}")
        elif reboot_data_result: # Log if not default empty list but also not a list
            logger.warning(f"Expected a list for systems needing reboot, but received: {type(reboot_data_result)}")

    return systems_needing_reboot_list

DYNAMIC_DESCRIPTION = f"""
    Schedules an immediate reboot for a specific system on the {product} server.

    Args:
        system_identifier: The unique identifier of the system. It can be the system name (e.g. "buildhost") or the system ID (e.g. 1000010000).
        confirm: User confirmation is required to execute this action. This parameter
                 is `False` by default. To obtain the confirmation message that must
                 be presented to the user, the model must first call the tool with
                 `confirm=False`. If the user agrees, the model should call the tool
                 a second time with `confirm=True`.

    The reboot is scheduled to occur as soon as possible (effectively "now").

    Returns:
        str: A message indicating the action ID if the reboot was successfully scheduled,
             e.g., "System reboot successfully scheduled. Action URL: ...".
             Returns an empty string if scheduling fails or an error occurs.
    """
@write_tool(description = DYNAMIC_DESCRIPTION)
async def schedule_system_reboot(system_identifier: Union[str, int], ctx:Context, confirm: Union[bool, str] = False) -> str:

    log_string = f"Schedule system reboot for system {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)

    is_confirmed = _to_bool(confirm)

    token = ctx.get_state('token')
    system_id = await _resolve_system_id(system_identifier, token)

    if not is_confirmed:
        return f"CONFIRMATION REQUIRED: This will reboot system {system_identifier}. Do you confirm?"

    schedule_reboot_path = '/rhn/manager/api/system/scheduleReboot'

    # Generate current time in ISO 8601 format (UTC)
    now_iso = datetime.now(timezone.utc).isoformat()

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        payload = {"sid": int(system_id), "earliestOccurrence": now_iso}
        api_result = await call_uyuni_api(
            client=client,
            method="POST",
            api_path=schedule_reboot_path,
            json_body=payload,
            error_context=f"scheduling reboot for system {system_identifier}",
            token=token
        )

        # uyuni's scheduleReboot API returns an integer action ID directly in 'result'
        if isinstance(api_result, int):
            action_id = api_result
            action_detail_url = f"{CONFIG['UYUNI_SERVER']}/rhn/schedule/ActionDetails.do?aid={action_id}"
            success_message = f"System reboot successfully scheduled. Action URL: {action_detail_url}"
            logger.info(success_message)
            return success_message
        else:
            return "Unexpected API response format when scheduling reboot. Check server logs for details."

DYNAMIC_DESCRIPTION = f"""
    Fetches a list of all scheduled actions from the {product} server.

    You can use this tool to check the status of a reboot. A reboot is finished when
    its related action is completed.

    This includes completed, in-progress, failed, and archived actions.
    Each action in the list is a dictionary containing details such as
    action_id, name, type, scheduler, earliest execution time,
    prerequisite action ID (if any), and counts of systems in
    completed, failed, or in-progress states.

    Returns:
        List[Dict[str, Any]]: A list of action dictionaries.
                              Returns an empty list if no actions are found.
    """
@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def list_all_scheduled_actions(ctx: Context) -> List[Dict[str, Any]]:

    log_string = "Listing all scheduled actions"
    logger.info(log_string)
    await ctx.info(log_string)

    list_actions_path = '/rhn/manager/api/schedule/listAllActions'
    processed_actions_list = []

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        api_result = await call_uyuni_api(
            client=client,
            method="GET",
            api_path=list_actions_path,
            error_context="listing all scheduled actions",
            token=ctx.get_state('token')
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
                    logger.warning(f"Unexpected item format in actions list: {action_dict}")
        elif api_result: # Log if not default empty list but also not a list
            logger.warning(f"Expected a list for all scheduled actions, but received: {type(api_result)}")
    return processed_actions_list

DYNAMIC_DESCRIPTION = f"""
    Cancels a specified action on the {product} server.

    Args:
        action_id: The integer ID of the action to be canceled.
        confirm: User confirmation is required to execute this action. This parameter
                 is `False` by default. To obtain the confirmation message that must
                 be presented to the user, the model must first call the tool with
                 `confirm=False`. If the user agrees, the model should call the tool
                 a second time with `confirm=True`.

    Returns:
        str: A success message if the action was canceled,
             e.g., "Successfully canceled action: 123".
             Returns an error message if the cancellation failed for any reason,
             e.g., "Failed to cancel action 123. Please check the action ID and server logs."
    """

@write_tool(description = DYNAMIC_DESCRIPTION)
async def cancel_action(action_id: int, ctx: Context, confirm: Union[bool, str] = False) -> str:
    log_string = f"Cancel action {action_id}"
    logger.info(log_string)
    await ctx.info(log_string)

    is_confirmed = _to_bool(confirm)

    cancel_actions_path = '/rhn/manager/api/schedule/cancelActions'
 
    if not isinstance(action_id, int): # Basic type check, though FastMCP might handle this
        return "Invalid action ID provided. Must be an integer."

    if not is_confirmed:
        return f"CONFIRMATION REQUIRED: This will schedule action {action_id} to be canceled. Do you confirm?"

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        payload = {"actionIds": [action_id]} # API expects a list
        api_result = await call_uyuni_api(
            client=client,
            method="POST",
            api_path=cancel_actions_path,
            json_body=payload,
            error_context=f"canceling action {action_id}",
            token=ctx.get_state('token')
        )
        if api_result == 1:
            return f"Successfully canceled action: {action_id}"
        else:
            return f"Failed to cancel action: {action_id}. The API did not return success (expected 1, got {api_result}). Check server logs for details."


DYNAMIC_DESCRIPTION = f"""
    Fetches a list of activation keys from the {product} server.

    This tool retrieves all activation keys visible to the user and returns
    a list containing only the key identifier and its description.

    Returns:
        List[Dict[str, str]]: A list of dictionaries, where each dictionary
                              represents an activation key with 'key' and
                              'description' fields. Returns an empty list
                              if no keys are found.
    """
@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def list_activation_keys(ctx: Context) -> List[Dict[str, str]]:
    list_keys_path = '/rhn/manager/api/activationkey/listActivationKeys'

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        api_result = await call_uyuni_api(
            client=client,
            method="GET",
            api_path=list_keys_path,
            error_context="listing activation keys",
            token=ctx.get_state('token')
        )

    filtered_keys = []
    if isinstance(api_result, list):
        for key_data in api_result:
            if isinstance(key_data, dict):
                filtered_keys.append({'key': key_data.get('key'), 'description': key_data.get('description')})
            else:
                msg = f"Unexpected item format in activation key list: {key_data}"
                logger.warning(msg)
                await ctx.warning(msg)
    return filtered_keys

DYNAMIC_DESCRIPTION = f"""
    Provides a list of errata that are applicable to the system with the system_id
    passed as parameter and have not been scheduled yet. All elements in the result are patches that are applicable
    for the system.

    Args:
        system_id: The integer ID of the system for which we want to know the list of applicable errata.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries with each dictionary defining a errata applicable
                            to the system given as a parameter.
                            Returns an empty dictionary if no applicable errata for the system are found.
    """
@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def get_unscheduled_errata(system_id: int, ctx: Context) -> List[Dict[str, Any]]:
    log_string = f"Getting list of unscheduled errata for system {system_id}"
    logger.info(log_string)
    await ctx.info(log_string)

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        get_unscheduled_errata = "/rhn/manager/api/system/getUnscheduledErrata"
        payload = {'sid': str(system_id)}
        unscheduled_errata_result = await call_uyuni_api(
            client=client,
            method="GET",
            api_path=get_unscheduled_errata,
            params=payload,
            error_context=f"fetching unscheduled errata for system ID {system_id}",
            token=ctx.get_state('token')
        )

        if isinstance(unscheduled_errata_result, list):
            for item in unscheduled_errata_result:
                item['system_id'] = system_id

            return unscheduled_errata_result
        else:
            msg = f"Failed to retrieve unscheduled errata for system ID {system_id}. Unexpected API result format. Result: {unscheduled_errata_result}"
            logger.error(msg)
            return msg

DYNAMIC_DESCRIPTION = f"""
    Fetches a list of system groups from the {product} server.

    This tool retrieves all system groups visible to the user and returns a list containing for
    each group the identifier, name, description and system count.

    Returns:
        A list of dictionaries, where each dictionary represents a system group with 'id', 'name',
        'description' and 'system_count' fields. The 'system_count' refers to the number of systems
        assigned to each group.

        Returns an empty list if the API call fails, the response is not in the expected format,
        or no groups are found.

        Example:
            [
                {{
                    "id": "1",
                    "name": "Default Group",
                    "description": "Default group for all systems",
                    "system_count": "10"
                }},
                {{
                    "id": "2",
                    "name": "Test Group",
                    "description": "Group for testing purposes",
                    "system_count": "5"
                }}
            ]
    """
@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def list_system_groups(ctx: Context) -> List[Dict[str, str]]:
    list_groups_path = '/rhn/manager/api/systemgroup/listAllGroups'

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        api_result = await call_uyuni_api(
            client=client,
            method="GET",
            api_path=list_groups_path,
            error_context="listing system groups",
            token=ctx.get_state('token')
        )

    filtered_groups = []
    if isinstance(api_result, list):
        for group_data in api_result:
            if isinstance(group_data, dict):
                filtered_groups.append({'id': str(group_data.get('id')), 'name': group_data.get('name'),
                    'description': group_data.get('description'), 'system_count': str(group_data.get('system_count'))})
            else:
                msg = f"Unexpected item format in system group list: {group_data}"
                logger.warning(msg)
                await ctx.warning(msg)
    return filtered_groups

DYNAMIC_DESCRIPTION = f"""
    Creates a new system group in {product}.

    Args:
        name: The name of the new system group.
        description: An optional description for the system group.
        confirm: User confirmation is required to execute this action. This parameter
                 is `False` by default. To obtain the confirmation message that must
                 be presented to the user, the model must first call the tool with
                 `confirm=False`. If the user agrees, the model should call the tool
                 a second time with `confirm=True`.

    Returns:
        A success message if the group was created, e.g., "Successfully created system group 'my-group'".
        Returns an error message if the creation failed.

        Example:
            Successfully created system group 'my-group'.
    """
@write_tool(description = DYNAMIC_DESCRIPTION)
async def create_system_group(name: str, ctx: Context, description: str = "", confirm: Union[bool, str] = False) -> str:
    log_string = f"Creating system group '{name}'"
    logger.info(log_string)
    await ctx.info(log_string)

    is_confirmed = _to_bool(confirm)

    if not is_confirmed:
        return f"CONFIRMATION REQUIRED: This will create a new system group named '{name}' with description '{description}'. Do you confirm?"

    create_group_path = '/rhn/manager/api/systemgroup/create'

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        api_result = await call_uyuni_api(
            client=client,
            method="POST",
            api_path=create_group_path,
            json_body={"name": name, "description": description},
            error_context=f"creating system group '{name}'",
            token=ctx.get_state('token')
        )

        if isinstance(api_result, dict) and 'id' in api_result:
             # The API returns the created group object
            msg = f"Successfully created system group '{name}'."
            logger.info(msg)
        elif api_result:
             # If it returns something truthy that we didn't expect, but not None (which is error)
             msg = f"Successfully created system group '{name}'. (API returned: {api_result})"
             logger.warning(msg)
        else:
            msg = f"Failed to create system group '{name}'. Check server logs."
            logger.error(msg)
        return msg

DYNAMIC_DESCRIPTION = f"""
    Lists the systems in a system group.

    Args:
        group_name: The name of the system group.

    Returns:
        A list of dictionaries, where each dictionary represents a system with 'system_id' and
        'system_name' fields.

        Returns an empty list if the API call fails or no systems are found.

        Example:
            [
                {{
                    "system_id": "123456789",
                    "system_name": "my-system"
                }},
                {{
                    "system_id": "987654321",
                    "system_name": "my-other-system"
                }}
            ]
    """
@mcp.tool(description = DYNAMIC_DESCRIPTION)
async def list_group_systems(group_name: str, ctx: Context) -> List[Dict[str, Any]]:
    log_string = f"Listing systems in group '{group_name}'"
    logger.info(log_string)
    await ctx.info(log_string)

    list_systems_path = '/rhn/manager/api/systemgroup/listSystemsMinimal'

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        api_result = await call_uyuni_api(
            client=client,
            method="GET",
            api_path=list_systems_path,
            params={"systemGroupName": group_name},
            error_context=f"listing systems in group '{group_name}'",
            token=ctx.get_state('token')
        )

    filtered_systems = []
    if isinstance(api_result, list):
        for system in api_result:
            if isinstance(system, dict):
                filtered_systems.append({
                    'system_id': system.get('id'),
                    'system_name': system.get('name')
                })
            else:
                msg = f"Unexpected item format in group systems list: {system}"
                logger.warning(msg)
                await ctx.warning(msg)
    return filtered_systems

DYNAMIC_DESCRIPTION = f"""
    Adds systems to a system group.

    Args:
        group_name: The name of the system group.
        system_identifiers: A list of system names or IDs to add to the group.
        confirm: User confirmation is required to execute this action. This parameter
                 is `False` by default. To obtain the confirmation message that must
                 be presented to the user, the model must first call the tool with
                 `confirm=False`. If the user agrees, the model should call the tool
                 a second time with `confirm=True`.

    Returns:
        A success message if the systems were added.

        Example:
            Successfully added 1 systems to/from group 'test-group'.
    """
@write_tool(description = DYNAMIC_DESCRIPTION)
async def add_systems_to_group(group_name: str, system_identifiers: List[Union[str, int]], ctx: Context, confirm: Union[bool, str] = False) -> str:
    return await _manage_group_systems(group_name, system_identifiers, True, ctx, confirm)

DYNAMIC_DESCRIPTION = f"""
    Removes systems from a system group.

    Args:
        group_name: The name of the system group.
        system_identifiers: A list of system names or IDs to remove from the group.
        confirm: User confirmation is required to execute this action. This parameter
                 is `False` by default. To obtain the confirmation message that must
                 be presented to the user, the model must first call the tool with
                 `confirm=False`. If the user agrees, the model should call the tool
                 a second time with `confirm=True`.

    Returns:
        A success message if the systems were removed.

        Example:
            Successfully removed 1 systems to/from group 'test-group'.
    """
@write_tool(description = DYNAMIC_DESCRIPTION)
async def remove_systems_from_group(group_name: str, system_identifiers: List[Union[str, int]], ctx: Context, confirm: Union[bool, str] = False) -> str:
    return await _manage_group_systems(group_name, system_identifiers, False, ctx, confirm)

async def _manage_group_systems(group_name: str, system_identifiers: List[Union[str, int]], add: bool, ctx: Context, confirm: Union[bool, str] = False) -> str:
    """
    Internal helper to add or remove systems from a group.
    """
    action_str = ("add", "to") if add else ("remove", "from")
    log_string = f"Attempting to {action_str[0]} systems {system_identifiers} {action_str[1]} group '{group_name}'"
    logger.info(log_string)
    await ctx.info(log_string)

    is_confirmed = _to_bool(confirm)

    if not is_confirmed:
        return f"CONFIRMATION REQUIRED: This will {action_str[0]} {len(system_identifiers)} systems {action_str[1]} group '{group_name}'. Do you confirm?"

    token = ctx.get_state('token')

    # Resolve all system IDs
    resolved_ids = []
    for identifier in system_identifiers:
        sid = await _resolve_system_id(identifier, token)
        if sid:
            resolved_ids.append(int(sid))
        else:
            print(f"Warning: Could not resolve system identifier '{identifier}'. Skipping.")

    if not resolved_ids:
        return "No valid system identifiers found. Aborting."

    add_remove_path = '/rhn/manager/api/systemgroup/addOrRemoveSystems'

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        api_result = await call_uyuni_api(
            client=client,
            method="POST",
            api_path=add_remove_path,
            json_body={"systemGroupName": group_name, "serverIds": resolved_ids, "add": add},
            error_context=f"attempting to {action_str[0]} systems {action_str[1]} group '{group_name}'",
            token=token
        )

        if api_result == 1:
            past_tense_action = "added" if add else "removed"
            return f"Successfully {past_tense_action} {len(resolved_ids)} systems to/from group '{group_name}'."
        else:
            msg = f"Failed to {action_str[0]} systems. Check server logs. (API Result: {api_result})"
            logger.error(msg)

def main_cli():

    logger.info("Running {product} MCP server.")

    if CONFIG["UYUNI_MCP_TRANSPORT"] == Transport.HTTP.value:
        if CONFIG["AUTH_SERVER"]:
            mcp.add_middleware(AuthTokenMiddleware())
        mcp.run(transport="streamable-http", host=CONFIG["UYUNI_MCP_HOST"], port=CONFIG["UYUNI_MCP_PORT"])
    elif CONFIG["UYUNI_MCP_TRANSPORT"] == Transport.STDIO.value:
        mcp.run(transport="stdio")
    else:
        # Defaults to stdio transport anyway
        # But I explicitly state it here for clarity
        mcp.run(transport="stdio")
