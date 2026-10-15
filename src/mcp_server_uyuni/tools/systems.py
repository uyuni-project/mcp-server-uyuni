"""MCP contracts for system discovery and events (temporary new catalog)."""

import inspect

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError

from ..api.client import UyuniSession
from ..workflows.systems.discovery import SystemNotFoundError, get_system, search_systems
from ..workflows.systems.events import get_event, list_events


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
        """Search by hostname, IP, UUID, name, description, group, or reboot need.

        Use systems_get for an exact ID. Returns compact references with
        response-only pagination; Uyuni may return a full collection first.
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
        """Get canonical identity, boot, CPU, network, UUID, and installed products.

        Supply exactly one of system_id or system_name. Use systems_search for
        discovery; an ambiguous name requires retrying with an ID.
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
        """List newest-first event summaries for one system with native pagination.

        Supply exactly one of system_id or system_name. Use systems_events_get
        with an event_id for full details.
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
        """Get one event returned by systems_events_list.

        Supply event_id and exactly one owning system_id or system_name.
        Returns status, timestamps, results, and additional information.
        """
        return await run_with_api(
            ctx, get_event,
            event_id=event_id, system_id=system_id, system_name=system_name,
        )


def build_test_system_catalog(session_factory=UyuniSession) -> FastMCP:
    """Temporary opt-in catalog for contract tests; production still uses legacy tools."""
    server = FastMCP("uyuni-system-catalog-test")
    register_system_tools(server, session_factory)
    return server
