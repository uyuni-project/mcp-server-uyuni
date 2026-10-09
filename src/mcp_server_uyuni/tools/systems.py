"""MCP contracts for system discovery, events, and updates."""

import inspect

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError

from ..api.client import UyuniSession
from ..constants import AdvisoryType, ApplicationStatus, ResponseFormat
from ..workflows.systems.discovery import SystemNotFoundError, get_system, search_systems
from ..workflows.systems.events import get_event, list_events
from ..workflows.systems.updates import SingleSystemUpdateFormat, get_updates, search_updates


READ_ONLY = {
    "readOnlyHint": True,
    "openWorldHint": False,
}


def register_system_tools(server: FastMCP, session_factory=UyuniSession) -> None:
    """Register only on an explicitly supplied new-catalog server."""

    async def run_with_api(ctx, operation, **kwargs):
        """Run a workflow with the caller's Uyuni session."""
        token = ctx.get_state("token")
        if inspect.isawaitable(token):
            token = await token
        async with session_factory(token) as api:
            try:
                return await operation(api, **kwargs)
            except (ValueError, SystemNotFoundError) as exc:
                raise ToolError(str(exc)) from exc

    @server.tool(
        name="systems_search",
        annotations=READ_ONLY,
        tags={"core"},
        output_schema=None,
    )
    async def systems_search(
        ctx: Context,
        hostname: str | None = None,
        ip: str | None = None,
        uuid: str | None = None,
        name: str | None = None,
        group_name: str | None = None,
        reboot_required: bool | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> dict:
        """Find managed systems by hostname, IP, UUID, name or description, group, or reboot requirement.

        Combine filters to narrow the results. Returns paged system IDs and
        names; use systems_get when an ID is known or full details are needed.
        """
        return await run_with_api(
            ctx, search_systems,
            hostname=hostname, ip=ip, uuid=uuid, name=name,
            group_name=group_name, reboot_required=reboot_required,
            limit=limit, offset=offset,
        )

    @server.tool(
        name="systems_get",
        annotations=READ_ONLY,
        tags={"core"},
        output_schema=None,
    )
    async def systems_get(
        ctx: Context,
        system_id: int | None = None,
        system_name: str | None = None,
    ) -> dict:
        """Get a managed system's identity, hardware, network, and installed products.

        Supply exactly one system ID or exact system name. Use systems_search
        to find an ID when the name is unknown or ambiguous.
        """
        return await run_with_api(
            ctx, get_system, system_id=system_id, system_name=system_name,
        )

    @server.tool(
        name="systems_events_list",
        annotations=READ_ONLY,
        tags={"operations"},
        output_schema=None,
    )
    async def systems_events_list(
        ctx: Context,
        system_id: int | None = None,
        system_name: str | None = None,
        limit: int = 25,
        offset: int = 0,
        earliest_date: str | None = None,
    ) -> dict:
        """List action and event history for one managed system, newest first.

        Supply exactly one system ID or exact system name. Filter by earliest
        date or page through summaries; use systems_events_get for one event.
        """
        return await run_with_api(
            ctx, list_events,
            system_id=system_id, system_name=system_name,
            limit=limit, offset=offset, earliest_date=earliest_date,
        )

    @server.tool(
        name="systems_events_get",
        annotations=READ_ONLY,
        tags={"operations"},
        output_schema=None,
    )
    async def systems_events_get(
        ctx: Context,
        event_id: int,
        system_id: int | None = None,
        system_name: str | None = None,
    ) -> dict:
        """Get the status, timing, and result of one system event.

        Supply its event ID and exactly one owning system ID or exact system
        name. Use systems_events_list to find event IDs.
        """
        return await run_with_api(
            ctx, get_event,
            event_id=event_id, system_id=system_id, system_name=system_name,
        )

    @server.tool(
        name="systems_updates_get",
        annotations=READ_ONLY,
        tags={"patching"},
        output_schema=None,
    )
    async def systems_updates_get(
        ctx: Context,
        system_id: int | None = None,
        system_name: str | None = None,
        response_format: SingleSystemUpdateFormat = "summary",
        advisory_types: list[AdvisoryType] | None = None,
        application_status: ApplicationStatus | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> dict:
        """List relevant update advisories for one managed system.

        Supply exactly one system ID or exact system name. Filter by advisory
        type or application status: Pending means not scheduled; Queued means
        scheduled. Counts returns totals without advisory items; offset must be
        zero and limit has no effect. Summary gives brief paged advisories,
        standard adds synopsis and restart hints, and detailed includes CVEs.
        """
        return await run_with_api(
            ctx, get_updates,
            system_id=system_id, system_name=system_name,
            response_format=response_format, advisory_types=advisory_types,
            application_status=application_status, limit=limit, offset=offset,
        )

    @server.tool(
        name="systems_updates_search",
        annotations=READ_ONLY,
        tags={"patching"},
        output_schema=None,
    )
    async def systems_updates_search(
        ctx: Context,
        group_name: str | None = None,
        response_format: ResponseFormat = "summary",
        limit: int = 25,
        offset: int = 0,
    ) -> dict:
        """Find managed systems with available package updates, optionally within a group.

        Returns paged package update and advisory counts for each system. Some
        systems have package updates without advisories. Standard and detailed
        formats add advisory previews; detailed includes CVEs. Use
        systems_updates_get for all advisories on one system.
        """
        return await run_with_api(
            ctx, search_updates,
            group_name=group_name, response_format=response_format,
            limit=limit, offset=offset,
        )
