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
import asyncio
from typing import Any, List, Dict, Optional, Union, Coroutine
import httpx
from datetime import datetime, timezone
from pydantic import BaseModel

from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp import FastMCP, Context
from mcp import types

from .constants import Transport, AdvisoryType
from .logging_config import get_logger
from .uyuni_api import call as call_uyuni_api, TIMEOUT_HAPPENED
from .config import CONFIG
from .auth import AuthProvider
from .errors import (
    UnexpectedResponse,
    NotFoundError
)
from .utils import (
    to_bool,
    normalize_pagination,
    build_list_meta,
    paginate_items,
    matches_optional_filter,
)

class ActivationKeySchema(BaseModel):
    activation_key: str

base_url = f'http://{CONFIG["UYUNI_MCP_HOST"]}:{CONFIG["UYUNI_MCP_PORT"]}'
auth_provider = AuthProvider(CONFIG["AUTH_SERVER"], base_url, CONFIG["UYUNI_MCP_WRITE_TOOLS_ENABLED"]) if CONFIG["AUTH_SERVER"] else None
product = CONFIG["UYUNI_PRODUCT_NAME"] if CONFIG["UYUNI_PRODUCT_NAME"] else "Uyuni" 
mcp = FastMCP(
    "mcp-server-uyuni",
    auth=auth_provider,
    instructions=f"MCP tools for {product}: manage mixed Linux systems, groups, patches/updates, and scheduled actions via API tools.",
)

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
        auth_header = fastmcp_ctx.request_context.request.headers.get('authorization')
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

@mcp.tool(description=f"""
    List active systems in {product}.
    Inputs: optional `limit`, `offset`.
    `limit` is capped at 500.
    Returns: `items` with active systems (`system_name`, `system_id`) and `meta`.
    Note: use `system_id` for other system tools.
    """)
async def list_systems(ctx: Context, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    log_string = "Getting list of active systems"
    logger.info(log_string)
    await ctx.info(log_string)

    systems = await _list_systems(ctx.get_state('token'))
    normalized_limit, normalized_offset = normalize_pagination(limit=limit, offset=offset, default_limit=50, max_limit=500)
    paged_items, meta = paginate_items(systems, limit=normalized_limit, offset=normalized_offset)
    return {
        'items': paged_items,
        'meta': meta,
    }

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

@mcp.tool()
async def get_system_details(system_identifier: Union[str, int], ctx: Context):
    """Get details for one system.

    Inputs: `system_identifier` (`system_name` or `system_id`).
    Name not found: resolve with `find_systems_by_name`, then pass `system_id`.
    Returns: `system_id`, `system_name`, `last_boot`, `uuid`, `cpu`, `network`, `installed_products`.
    Use system_id when possible.
    """
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

@mcp.tool()
async def get_system_event_history(system_identifier: Union[str, int], ctx: Context, offset: int = 0, limit: int = 10, earliest_date: Optional[str] = None):
    """List events for one system.

    Inputs: `system_identifier` (`system_name` or `system_id`); optional `offset`, `limit`, `earliest_date`.
    Name not found: resolve with `find_systems_by_name`, then pass `system_id`.
    Returns: newest-first event list with `id`, `history_type`, `status`, `summary`, `completed`.
    Use `get_system_event_details` for one event.
    """
    log_string = f"Getting event history of system {system_identifier} with offset {offset} and limit {limit}"
    logger.info(log_string)
    await ctx.info(log_string)
    return await _get_system_event_history(system_identifier, limit, offset, earliest_date, ctx.get_state('token'))

async def _get_system_event_history(system_identifier: Union[str, int], limit: int, offset: int, earliest_date: Optional[str], token: str) -> list[Any]:
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
    return []

@mcp.tool()
async def get_system_event_details(system_identifier: Union[str, int], event_id: int, ctx: Context):
    """Get one event detail.

    Inputs: `system_identifier` (`system_name` or `system_id`), `event_id`.
    Name not found: resolve with `find_systems_by_name`, then pass `system_id`.
    Returns: event object including status, timestamps, result fields, and optional additional_info.
    `event_id` should come from `get_system_event_history`.
    """
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

@mcp.tool()
async def find_systems_by_name(
    name: str,
    ctx: Context,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    """Find systems by hostname.

    Inputs: `name`; optional `limit`, `offset`.
    Use this first when user input is a partial hostname.
    If multiple systems match, ask the user to choose one `system_id`.
    `limit` is capped at 500.
    Returns: `items` with matching systems (`system_name`, `system_id`) and `meta`.
    """
    systems = await _find_systems_by_name(name, ctx)
    normalized_limit, normalized_offset = normalize_pagination(limit=limit, offset=offset, default_limit=50, max_limit=500)
    paged_items, meta = paginate_items(systems, limit=normalized_limit, offset=normalized_offset)
    return {
        'items': paged_items,
        'meta': meta,
    }

async def _find_systems_by_name(name: str, ctx: Context) -> List[Dict[str, Union[str, int]]]:
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

@mcp.tool()
async def find_systems_by_ip(
    ip_address: str,
    ctx: Context,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    """Find systems by IP address.

    Inputs: `ip_address`; optional `limit`, `offset`.
    `limit` is capped at 500.
    Returns: `items` with matching systems (`system_name`, `system_id`, `ip`) and `meta`.
    """
    systems = await _find_systems_by_ip(ip_address, ctx)
    normalized_limit, normalized_offset = normalize_pagination(limit=limit, offset=offset, default_limit=50, max_limit=500)
    paged_items, meta = paginate_items(systems, limit=normalized_limit, offset=normalized_offset)
    return {
        'items': paged_items,
        'meta': meta,
    }

async def _find_systems_by_ip(ip_address: str, ctx: Context) -> List[Dict[str, Union[str, int]]]:
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

@mcp.tool()
async def get_system_updates(system_identifier: Union[str, int], ctx: Context) -> Dict[str, Any]:
    """Get pending updates for one system.

    Inputs: `system_identifier` (`system_name` or `system_id`; prefer `system_id`).
    Name not found: resolve with `find_systems_by_name`, then pass `system_id`.
    Best for compact default update view.
    Returns: compact update list plus counts and `meta`.
    Default behavior omits CVEs for lower token usage.
    For pagination and CVE expansion, use `query_system_updates`.
    """

    log_string = f"Checking pending updates for system {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)
    return await _get_system_updates(
        system_identifier=system_identifier,
        ctx=ctx,
        include_cves=False,
        limit=25,
        offset=0,
        compact_updates=True,
    )

async def _get_system_updates(
    system_identifier: Union[str, int],
    ctx: Context,
    include_cves: bool = False,
    limit: Optional[int] = 25,
    offset: int = 0,
    advisory_types: Optional[List[AdvisoryType]] = None,
    compact_updates: bool = False,
    counts_only: bool = False,
) -> Dict[str, Any]:
    """Fetch, enrich, filter, and paginate updates for a single system."""
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

        if not isinstance(relevant_updates_list, list):
            relevant_updates_list = []
        if not isinstance(unscheduled_updates_list, list):
            unscheduled_updates_list = []

        unscheduled_advisory_names = {erratum.get('advisory_name') for erratum in unscheduled_updates_list}

        advisory_type_filter = {str(item).lower() for item in advisory_types} if advisory_types else None

        if counts_only:
            filtered_relevant_updates = [
                update for update in relevant_updates_list
                if matches_optional_filter(update.get("advisory_type"), advisory_type_filter)
            ]
            pending_count = sum(
                1 for update in filtered_relevant_updates
                if update.get('advisory_name') in unscheduled_advisory_names
            )
            queued_count = len(filtered_relevant_updates) - pending_count

            normalized_limit, normalized_offset = normalize_pagination(limit=limit, offset=offset)
            _, meta = paginate_items(filtered_relevant_updates, limit=normalized_limit, offset=normalized_offset)

            return {
                'system_identifier': system_identifier,
                'has_pending_updates': len(filtered_relevant_updates) > 0,
                'update_count': len(filtered_relevant_updates),
                'pending_update_count': pending_count,
                'queued_update_count': queued_count,
                'updates': [],
                'meta': {
                    **meta,
                    'include_cves': include_cves,
                    'filters': {
                        'advisory_types': advisory_types or [],
                    }
                }
            }

        enriched_updates_list = []

        for erratum_api_data in relevant_updates_list:
            advisory_name = erratum_api_data.get('advisory_name')

            if compact_updates:
                update_details = {
                    'update_id': erratum_api_data.get('id'),
                    'advisory_name': advisory_name,
                    'advisory_type': erratum_api_data.get('advisory_type'),
                    'advisory_synopsis': erratum_api_data.get('advisory_synopsis'),
                }
            else:
                update_details = dict(erratum_api_data)
                if 'id' in update_details:
                    update_details['update_id'] = update_details.pop('id')
                else:
                    update_details['update_id'] = None

            if advisory_name in unscheduled_advisory_names:
                update_details['application_status'] = 'Pending'
            else:
                update_details['application_status'] = 'Queued'

            if include_cves or not compact_updates:
                update_details['cves'] = []

            enriched_updates_list.append(update_details)

        filtered_updates = [
            update for update in enriched_updates_list
            if matches_optional_filter(update.get("advisory_type"), advisory_type_filter)
        ]
        normalized_limit, normalized_offset = normalize_pagination(limit=limit, offset=offset)
        paged_updates, meta = paginate_items(filtered_updates, limit=normalized_limit, offset=normalized_offset)

        if include_cves and paged_updates:
            cve_fetch_updates = [update for update in paged_updates if update.get("advisory_name")]
            cve_fetch_tasks = [
                _fetch_cves_for_erratum(client, update.get("advisory_name"), system_id, list_cves_api_path, ctx)
                for update in cve_fetch_updates
            ]

            all_cve_results = await asyncio.gather(*cve_fetch_tasks)
            for update, cves in zip(cve_fetch_updates, all_cve_results):
                update['cves'] = cves

        pending_count = sum(1 for update in filtered_updates if update.get("application_status") == "Pending")
        queued_count = sum(1 for update in filtered_updates if update.get("application_status") == "Queued")

        return {
            'system_identifier': system_identifier,
            'has_pending_updates': len(filtered_updates) > 0,
            'update_count': len(filtered_updates),
            'pending_update_count': pending_count,
            'queued_update_count': queued_count,
            'updates': paged_updates,
            'meta': {
                **meta,
                'include_cves': include_cves,
                'filters': {
                    'advisory_types': advisory_types or [],
                }
            }
        }


@mcp.tool()
async def summarize_system_updates(
    system_identifier: Union[str, int],
    ctx: Context,
    advisory_types: Optional[List[AdvisoryType]] = None,
) -> Dict[str, Any]:
    """Summarize pending updates for one system.

    Inputs: `system_identifier` (`system_name` or `system_id`); optional `advisory_types`.
    Name not found: resolve with `find_systems_by_name`, then pass `system_id`.
    Best for counts only.
    `advisory_types` accepts: `Security Advisory`, `Product Enhancement Advisory`, `Bug Fix Advisory`.
    Returns: update counts and `meta`.
    """
    result = await _get_system_updates(
        system_identifier=system_identifier,
        ctx=ctx,
        include_cves=False,
        limit=0,
        offset=0,
        advisory_types=advisory_types,
        counts_only=True,
    )
    return {
        'system_identifier': result['system_identifier'],
        'has_pending_updates': result['has_pending_updates'],
        'update_count': result['update_count'],
        'pending_update_count': result['pending_update_count'],
        'queued_update_count': result['queued_update_count'],
        'meta': result.get('meta', {})
    }


@mcp.tool()
async def query_system_updates(
    system_identifier: Union[str, int],
    ctx: Context,
    limit: int = 25,
    offset: int = 0,
    include_cves: bool = False,
    advisory_types: Optional[List[AdvisoryType]] = None,
) -> Dict[str, Any]:
    """Query pending updates for one system.

    Inputs: `system_identifier` (`system_name` or `system_id`); optional `limit`, `offset`, `include_cves`, `advisory_types`.
    Name not found: resolve with `find_systems_by_name`, then pass `system_id`.
    Best for pagination and optional CVE expansion.
    Pagination behavior: `limit <= 0` returns no items (counts still available);
    positive `limit` is capped at 200.
    Returns: `updates` with pending updates for the system and `meta`.
    """
    return await _get_system_updates(
        system_identifier=system_identifier,
        ctx=ctx,
        include_cves=include_cves,
        limit=limit,
        offset=offset,
        advisory_types=advisory_types,
    )

@mcp.tool()
async def check_all_systems_for_updates(
    ctx: Context,
    include_updates: bool = False,
    include_cves: bool = False,
    system_limit: int = 25,
    system_offset: int = 0,
    updates_per_system: int = 10,
) -> Dict[str, Any]:
    """Check all active systems for pending updates.

    Inputs: optional `include_updates`, `include_cves`, `system_limit`, `system_offset`, `updates_per_system`.
    Best for fleet scan; set `include_updates=true` to include per-system update items.
    `system_limit` is capped at 200 for response paging.
    Returns: `items` with systems that have pending updates (plus optional update details) and `meta`.
    """
    return await _check_all_systems_for_updates(
        ctx=ctx,
        include_updates=include_updates,
        include_cves=include_cves,
        system_limit=system_limit,
        system_offset=system_offset,
        updates_per_system=updates_per_system,
    )

async def _check_all_systems_for_updates(
    ctx: Context,
    include_updates: bool = False,
    include_cves: bool = False,
    system_limit: int = 25,
    system_offset: int = 0,
    updates_per_system: int = 10,
) -> Dict[str, Any]:
    """Scan active systems and return a paged list of systems with pending updates."""
    log_string = "Checking all system for updates"
    logger.info(log_string)
    await ctx.info(log_string)

    systems_with_updates: List[Dict[str, Any]] = []
    active_systems = await _list_systems(ctx.get_state('token')) # Get the list of all systems

    if not active_systems:
        msg = "No active systems found."
        logger.warning(msg)
        await ctx.warning(msg)
        return {
            'items': [],
            'meta': build_list_meta(total_count=0, returned_count=0, limit=system_limit, offset=system_offset)
        }

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
        update_check_result = await _get_system_updates(
            system_id,
            ctx,
            include_cves=include_cves,
            limit=updates_per_system if include_updates else 0,
            offset=0,
            counts_only=not include_updates,
        )

        if update_check_result.get('has_pending_updates', False):
            system_result = {
                'system_name': system_name,
                'system_id': system_id,
                'update_count': update_check_result.get('update_count', 0),
                'pending_update_count': update_check_result.get('pending_update_count', 0),
                'queued_update_count': update_check_result.get('queued_update_count', 0),
            }
            if include_updates:
                system_result['updates'] = update_check_result.get('updates', [])
                update_meta = update_check_result.get('meta', {})
                system_result['updates_truncated'] = bool(update_meta.get('truncated', False))
            systems_with_updates.append(system_result)

    await ctx.report_progress(total_systems, total_systems)

    msg = f"Finished checking systems. Found {len(systems_with_updates)} systems with updates."
    logger.info(msg)
    await ctx.info(msg)
    normalized_limit, normalized_offset = normalize_pagination(limit=system_limit, offset=system_offset, default_limit=25, max_limit=200)
    paged_items, meta = paginate_items(systems_with_updates, limit=normalized_limit, offset=normalized_offset)
    meta['include_updates'] = include_updates
    meta['include_cves'] = include_cves
    meta['updates_per_system'] = updates_per_system if include_updates else 0
    return {
        'items': paged_items,
        'meta': meta
    }


@mcp.tool()
async def summarize_fleet_updates(
    ctx: Context,
    system_limit: int = 25,
    system_offset: int = 0,
) -> Dict[str, Any]:
    """Summarize fleet update status.

    Inputs: optional `system_limit`, `system_offset`.
    `system_limit` is capped at 200.
    Returns: paged list of systems with update counts in `items` and `meta`.
    """
    return await _check_all_systems_for_updates(
        ctx=ctx,
        include_updates=False,
        include_cves=False,
        system_limit=system_limit,
        system_offset=system_offset,
        updates_per_system=0,
    )

@write_tool()
async def schedule_pending_updates_to_system(system_identifier: Union[str, int], ctx: Context, confirm: Union[bool, str] = False) -> str:
    """Schedule all pending updates for one system.

    Inputs: `system_identifier` (`system_name` or `system_id`); optional `confirm`.
    Name not found: resolve with `find_systems_by_name`, then pass `system_id`.
    Returns: `CONFIRMATION REQUIRED...` when `confirm=false`; otherwise scheduled action URL or error text.
    Call once with `confirm=false`, then call again with `confirm=true`.
    """
    return await _schedule_pending_updates_to_system(system_identifier, ctx, confirm)

async def _schedule_pending_updates_to_system(system_identifier: Union[str, int], ctx: Context, confirm: Union[bool, str] = False) -> str:
    msg = f"Attempting to apply pending updates for system ID: {system_identifier}"
    logger.info(msg)
    await ctx.info(msg)

    is_confirmed = to_bool(confirm)
    if not is_confirmed:
        return f"CONFIRMATION REQUIRED: This will apply pending updates to the system {system_identifier}.  Do you confirm?"

    token = ctx.get_state('token')
    update_info = await _get_system_updates(
        system_identifier=system_identifier,
        ctx=ctx,
        include_cves=False,
        limit=None,
        offset=0,
    )

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


@write_tool()
async def schedule_specific_update(system_identifier: Union[str, int], errata_id: Union[str, int], ctx: Context, confirm: Union[bool, str] = False) -> str:
    """Schedule one specific update for one system.

    Inputs: `system_identifier` (`system_name` or `system_id`), `errata_id`; optional `confirm`.
    Name not found: resolve with `find_systems_by_name`, then pass `system_id`.
    Returns: `CONFIRMATION REQUIRED...` when `confirm=false`; otherwise scheduled action URL or error text.
    Call once with `confirm=false`, then call again with `confirm=true`.
    """
    return await _schedule_specific_update(system_identifier, errata_id, ctx, confirm)

async def _schedule_specific_update(system_identifier: Union[str, int], errata_id: Union[str, int], ctx: Context, confirm: Union[bool, str] = False) -> str:
    log_string = f"Attempting to apply specific update (errata ID: {errata_id}) to system ID: {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)

    is_confirmed = to_bool(confirm)

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

@write_tool(description=f"""
    Register a new system in {product} via SSH bootstrap.
    Inputs: `host`; optional `activation_key`, `ssh_port`, `ssh_user`, `proxy_id`, `salt_ssh`, `confirm`.
    Returns: `CONFIRMATION REQUIRED...` when `confirm=false`; otherwise success or error message.
    Requires `UYUNI_SSH_PRIV_KEY` on the server.
    """)
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
    return await _add_system(host, ctx, activation_key, ssh_port, ssh_user, proxy_id, salt_ssh, confirm)

async def _add_system(
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

    is_confirmed = to_bool(confirm)

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

@write_tool(description=f"""
    Remove a system from {product}.
    Inputs: `system_identifier` (`system_name` or `system_id`); optional `cleanup`, `confirm`.
    Name not found: resolve with `find_systems_by_name`, then pass `system_id`.
    Returns: `CONFIRMATION REQUIRED...` when `confirm=false`; otherwise success or error message.
    This is a destructive operation.
    """)
async def remove_system(system_identifier: Union[str, int], ctx: Context, cleanup: bool = True, confirm: Union[bool, str] = False) -> str:
    return await _remove_system(system_identifier, ctx, cleanup, confirm)

async def _remove_system(system_identifier: Union[str, int], ctx: Context, cleanup: bool = True, confirm: Union[bool, str] = False) -> str:
    log_string = f"Attempting to remove system with id {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)

    is_confirmed = to_bool(confirm)

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

@mcp.tool()
async def list_systems_needing_update_for_cve(
    cve_identifier: str,
    ctx: Context,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    """List systems affected by a CVE.

    Inputs: `cve_identifier`; optional `limit`, `offset`.
    `limit` is capped at 500.
    Returns: `items` with unique affected systems (`system_id`, `system_name`) and `meta`.
    """
    return await _list_systems_needing_update_for_cve(cve_identifier, ctx, limit, offset)

async def _list_systems_needing_update_for_cve(
    cve_identifier: str,
    ctx: Context,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    log_string = f"Getting systems that need to apply CVE {cve_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)

    affected_systems_map = {}  # Use a dict to store unique systems by ID {system_id: {details}}
    normalized_limit, normalized_offset = normalize_pagination(limit=limit, offset=offset, default_limit=50, max_limit=500)
    empty_result = {
        'items': [],
        'meta': build_list_meta(total_count=0, returned_count=0, limit=normalized_limit, offset=normalized_offset)
    }

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
            return empty_result
        if not isinstance(errata_list, list):
            msg = f"Expected a list of errata for CVE {cve_identifier}, but received: {type(errata_list)}"
            logger.error(msg)
            await ctx.error(msg)
            return empty_result
        if not errata_list:
            msg = f"No errata found for CVE {cve_identifier}."
            logger.info(msg)
            await ctx.info(msg)
            return empty_result

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

    affected_systems_list = list(affected_systems_map.values())

    if not affected_systems_list:
        msg = f"No systems found affected by CVE {cve_identifier} after checking all related errata."
        logger.info(msg)
        await ctx.info(msg)
    else:
        logger.info(f"Found {len(affected_systems_list)} unique system(s) affected by CVE {cve_identifier}.")

    paged_items, meta = paginate_items(affected_systems_list, limit=normalized_limit, offset=normalized_offset)
    meta['filters'] = {
        'cve_identifier': cve_identifier,
    }
    return {
        'items': paged_items,
        'meta': meta,
    }

@mcp.tool()
async def list_systems_needing_reboot(
    ctx: Context,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    """List systems that require reboot.

    Inputs: optional `limit`, `offset`.
    `limit` is capped at 500.
    Returns: `items` with systems requiring reboot (`system_id`, `system_name`, `reboot_status`) and `meta`.
    """
    return await _list_systems_needing_reboot(ctx, limit, offset)

async def _list_systems_needing_reboot(
    ctx: Context,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
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

    normalized_limit, normalized_offset = normalize_pagination(limit=limit, offset=offset, default_limit=50, max_limit=500)
    paged_items, meta = paginate_items(systems_needing_reboot_list, limit=normalized_limit, offset=normalized_offset)
    return {
        'items': paged_items,
        'meta': meta,
    }

@write_tool()
async def schedule_system_reboot(system_identifier: Union[str, int], ctx:Context, confirm: Union[bool, str] = False) -> str:
    """Schedule an immediate reboot for one system.

    Inputs: `system_identifier` (`system_name` or `system_id`); optional `confirm`.
    Name not found: resolve with `find_systems_by_name`, then pass `system_id`.
    Returns: `CONFIRMATION REQUIRED...` when `confirm=false`; otherwise reboot action URL or error text.
    Call once with `confirm=false`, then call again with `confirm=true`.
    """
    return await _schedule_system_reboot(system_identifier, ctx, confirm)

async def _schedule_system_reboot(system_identifier: Union[str, int], ctx:Context, confirm: Union[bool, str] = False) -> str:
    log_string = f"Schedule system reboot for system {system_identifier}"
    logger.info(log_string)
    await ctx.info(log_string)

    is_confirmed = to_bool(confirm)

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

@mcp.tool()
async def list_all_scheduled_actions(
    ctx: Context,
    limit: int = 50,
    offset: int = 0,
    action_types: Optional[List[str]] = None,
    scheduler: Optional[str] = None,
) -> Dict[str, Any]:
    """Query scheduled actions.

    Inputs: optional `limit`, `offset`, `action_types`, `scheduler`.
    `action_types` and `scheduler` are optional exact-match filters; prefer values from `meta.observed_action_types` and `meta.observed_schedulers`.
    `limit` is capped at 500; use `meta.next_offset` to page.
    Returns: `items` with scheduled actions and `meta`.
    """
    return await _list_all_scheduled_actions(
        ctx=ctx,
        limit=limit,
        offset=offset,
        action_types=action_types,
        scheduler=scheduler,
    )

async def _list_all_scheduled_actions(
    ctx: Context,
    limit: int = 50,
    offset: int = 0,
    action_types: Optional[List[str]] = None,
    scheduler: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch scheduled actions, apply optional filters, and return paged results.
    """
    log_string = "Listing all scheduled actions"
    logger.info(log_string)
    await ctx.info(log_string)

    list_actions_path = '/rhn/manager/api/schedule/listAllActions'
    processed_actions_list: List[Dict[str, Any]] = []

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
    action_types_filter = {str(item).lower() for item in action_types} if action_types else None
    observed_action_types = sorted({str(action.get('type')) for action in processed_actions_list if action.get('type')})
    observed_schedulers = sorted({str(action.get('scheduler')) for action in processed_actions_list if action.get('scheduler')})

    filtered_actions: List[Dict[str, Any]] = []
    for action in processed_actions_list:
        if not matches_optional_filter(action.get('type'), action_types_filter):
            continue
        if scheduler and str(action.get('scheduler', '')).lower() != str(scheduler).lower():
            continue
        filtered_actions.append(action)

    normalized_limit, normalized_offset = normalize_pagination(limit=limit, offset=offset, default_limit=50, max_limit=500)
    paged_items, meta = paginate_items(filtered_actions, limit=normalized_limit, offset=normalized_offset)
    meta['filters'] = {
        'action_types': action_types or [],
        'scheduler': scheduler,
    }
    meta['observed_action_types'] = observed_action_types
    meta['observed_schedulers'] = observed_schedulers

    return {
        'items': paged_items,
        'meta': meta,
    }

@write_tool()
async def cancel_action(action_id: int, ctx: Context, confirm: Union[bool, str] = False) -> str:
    """Cancel a scheduled action.

    Inputs: `action_id`; optional `confirm`.
    Returns: `CONFIRMATION REQUIRED...` when `confirm=false`; otherwise success or error message.
    Call once with `confirm=false`, then call again with `confirm=true`.
    """
    return await _cancel_action(action_id, ctx, confirm)

async def _cancel_action(action_id: int, ctx: Context, confirm: Union[bool, str] = False) -> str:
    log_string = f"Cancel action {action_id}"
    logger.info(log_string)
    await ctx.info(log_string)

    is_confirmed = to_bool(confirm)

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


@mcp.tool()
async def list_activation_keys(ctx: Context) -> List[Dict[str, str]]:
    """List activation keys available to the current user.

    Inputs: none.
    Returns: list of objects with `key` and `description`.
    """
    return await _list_activation_keys(ctx)

async def _list_activation_keys(ctx: Context) -> List[Dict[str, str]]:
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

@mcp.tool()
async def get_unscheduled_errata(system_id: int, ctx: Context) -> List[Dict[str, Any]]:
    """List unscheduled errata for one system.

    Inputs: `system_id`.
    This tool accepts numeric `system_id` only.
    Returns: errata list for that system.
    """
    return await _get_unscheduled_errata(system_id, ctx)

async def _get_unscheduled_errata(system_id: int, ctx: Context) -> List[Dict[str, Any]]:
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
            return []

@mcp.tool()
async def list_system_groups(ctx: Context) -> List[Dict[str, str]]:
    """List system groups.

    Inputs: none.
    Returns: list with `id`, `name`, `description`, and `system_count`.
    """
    return await _list_system_groups(ctx)

async def _list_system_groups(ctx: Context) -> List[Dict[str, str]]:
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

@write_tool(description=f"""
    Create a new system group in {product}.

    Inputs: `name`; optional `description`, `confirm`.
    System groups in {product} are flat (no nesting).
    Returns: `CONFIRMATION REQUIRED...` when `confirm=false`; otherwise success or error message.
    Call once with `confirm=false`, then call again with `confirm=true`.
    """)
async def create_system_group(name: str, ctx: Context, description: str = "", confirm: Union[bool, str] = False) -> str:
    return await _create_system_group(name, ctx, description, confirm)

async def _create_system_group(name: str, ctx: Context, description: str = "", confirm: Union[bool, str] = False) -> str:
    log_string = f"Creating system group '{name}'"
    logger.info(log_string)
    await ctx.info(log_string)

    is_confirmed = to_bool(confirm)

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

@mcp.tool()
async def list_group_systems(group_name: str, ctx: Context) -> List[Dict[str, Any]]:
    """List systems in one group.

    Inputs: `group_name`.
    Returns: list of `system_id` and `system_name`.
    """
    log_string = f"Listing systems in group '{group_name}'"
    logger.info(log_string)
    await ctx.info(log_string)
    return await _list_group_systems(group_name, ctx.get_state('token'))

async def _list_group_systems(group_name: str, token: str) -> List[Dict[str, Any]]:
    list_systems_path = '/rhn/manager/api/systemgroup/listSystemsMinimal'

    async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
        api_result = await call_uyuni_api(
            client=client,
            method="GET",
            api_path=list_systems_path,
            params={"systemGroupName": group_name},
            error_context=f"listing systems in group '{group_name}'",
            token=token
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
    return filtered_systems

@write_tool()
async def add_systems_to_group(group_name: str, system_identifiers: List[Union[str, int]], ctx: Context, confirm: Union[bool, str] = False) -> str:
    """Add systems to a group.

    Inputs: `group_name`, `system_identifiers`; optional `confirm`.
    Returns: `CONFIRMATION REQUIRED...` when `confirm=false`; otherwise success or error message.
    Call once with `confirm=false`, then call again with `confirm=true`.
    """
    return await _manage_group_systems(group_name, system_identifiers, True, ctx, confirm)

@write_tool()
async def remove_systems_from_group(group_name: str, system_identifiers: List[Union[str, int]], ctx: Context, confirm: Union[bool, str] = False) -> str:
    """Remove systems from a group.

    Inputs: `group_name`, `system_identifiers`; optional `confirm`.
    Returns: `CONFIRMATION REQUIRED...` when `confirm=false`; otherwise success or error message.
    Call once with `confirm=false`, then call again with `confirm=true`.
    """
    return await _manage_group_systems(group_name, system_identifiers, False, ctx, confirm)

async def _manage_group_systems(group_name: str, system_identifiers: List[Union[str, int]], add: bool, ctx: Context, confirm: Union[bool, str] = False) -> str:
    """
    Internal helper to add or remove systems from a group.
    """
    action_str = ("add", "to") if add else ("remove", "from")
    log_string = f"Attempting to {action_str[0]} systems {system_identifiers} {action_str[1]} group '{group_name}'"
    logger.info(log_string)
    await ctx.info(log_string)

    is_confirmed = to_bool(confirm)

    if not is_confirmed:
        return f"CONFIRMATION REQUIRED: This will {action_str[0]} {len(system_identifiers)} systems {action_str[1]} group '{group_name}'. Do you confirm?"

    token = ctx.get_state('token')

    # Resolve all system IDs in parallel
    resolved_sid_values = await asyncio.gather(
        *[_resolve_system_id(identifier, token) for identifier in system_identifiers]
    )
    resolved_ids = [int(sid) for sid in resolved_sid_values]

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
