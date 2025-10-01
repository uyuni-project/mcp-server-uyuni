from typing import Any, Dict, List, Optional, Union
from fastmcp import Context
from mcp_server_uyuni.config import CONFIG
import httpx

from mcp_server_uyuni.logging_config import get_logger
logger = get_logger(__name__)

# This module-level variable will hold the API calling function.
_call_uyuni_api = None

def attach_tools(mcp, call_uyuni_api_func, write_tool_decorator) -> None:
    """
    Defines and attaches system-related tools to the MCP server.
    Args:
        mcp: The FastMCP server instance.
        call_uyuni_api_func: The function to use for making API calls.
    """
    global _call_uyuni_api
    global write_tool

    _call_uyuni_api = call_uyuni_api_func
    write_tool = write_tool_decorator

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

        async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
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
        elif systems_data_result: # Log if not the default empty list but also not a list
            print(f"Warning: Expected a list of systems, but received: {type(systems_data_result)}")

        return filtered_systems

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
        active_systems = await mcp.tools["get_list_of_active_systems"].run(ctx=ctx)

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
            cpu_info = await mcp.tools["get_cpu_of_a_system"].run(system_identifier=str(system_id), ctx=ctx)

            all_systems_cpu_data.append({
                'system_name': system_name,
                'system_id': system_id,
                'cpu_info': cpu_info
            })

        return all_systems_cpu_data

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
        active_systems = await mcp.tools["get_list_of_active_systems"].run(ctx=ctx) # Get the list of all systems

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
            update_check_result = await mcp.tools["check_system_updates"].run(system_identifier=system_id, ctx=ctx)

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

        async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
            print(f"Searching for errata related to CVE: {cve_identifier}")
            errata_list = await _call_uyuni_api(
                client=client,
                method="GET",
                api_path=find_by_cve_path,
                params={'cveName': cve_identifier},
                error_context=f"finding errata for CVE {cve_identifier}",
                default_on_error=None # Distinguish API error from empty list
            )

            if errata_list is None: return []
            if not isinstance(errata_list, list):
                print(f"Warning: Expected a list of errata for CVE {cve_identifier}, but received: {type(errata_list)}")
                return []
            if not errata_list:
                print(f"No errata found for CVE {cve_identifier}.")
                return []

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

                if systems_data_result is None: continue
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

        async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
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

        async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
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
    async def list_activation_keys(ctx: Context) -> List[Dict[str, str]]:
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

        log_string = "Listing activation keys"
        logger.info(log_string)
        await ctx.info(log_string)

        async with httpx.AsyncClient(verify=CONFIG["UYUNI_MCP_SSL_VERIFY"]) as client:
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
