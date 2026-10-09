"""Public CVE patch-status search contract."""

import inspect

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError

from ..api.client import UyuniSession
from ..workflows.cve import PatchStatus, search_cve_systems


def register_cve_tools(server: FastMCP, session_factory=UyuniSession) -> None:
    """Register the audit-backed read tool on a new-catalog server."""

    @server.tool(
        name="cve_systems_search",
        annotations={"readOnlyHint": True, "openWorldHint": False},
        tags={"patching"},
        output_schema=None,
    )
    async def cve_systems_search(
        ctx: Context,
        cve_identifier: str,
        patch_statuses: list[PatchStatus] | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> dict:
        """Find managed systems by CVE and patch state.

        By default, returns systems that need an advisory for this CVE.
        Supply patch_statuses to find systems in specific patch states,
        including patched or unaffected systems. Paged results include patch
        status, channel labels, and advisory names when available.
        """
        token = ctx.get_state("token")
        if inspect.isawaitable(token):
            token = await token
        async with session_factory(token) as api:
            try:
                return await search_cve_systems(
                    api, cve_identifier=cve_identifier,
                    patch_statuses=patch_statuses, limit=limit, offset=offset,
                )
            except ValueError as exc:
                raise ToolError(str(exc)) from exc
