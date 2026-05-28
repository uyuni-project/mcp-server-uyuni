from fastmcp import Context
from mcp import types
from pydantic import BaseModel


class ActionApprovalSchema(BaseModel):
    approve: bool


def client_supports_elicitation(ctx: Context) -> bool:
    return ctx.session.check_client_capability(
        types.ClientCapabilities(elicitation=types.ElicitationCapability())
    )


async def elicit_approval(ctx: Context, prompt: str) -> bool:
    if not client_supports_elicitation(ctx):
        return True

    result = await ctx.elicit(prompt, ActionApprovalSchema)
    if result.action != "accept":
        return False

    data = result.data
    if hasattr(data, "approve"):
        return bool(data.approve)
    if isinstance(data, dict):
        return bool(data.get("approve"))
    return False
