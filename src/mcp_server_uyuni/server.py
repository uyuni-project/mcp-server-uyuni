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

from mcp_server_uyuni.config import CONFIG
from mcp_server_uyuni.uyuni_api import call as _call_uyuni_api, TIMEOUT_HAPPENED
from tools import systems as systems_tools
from tools import system as system_tools

mcp = FastMCP("mcp-server-uyuni")

logger = get_logger(log_file=CONFIG["UYUNI_MCP_LOG_FILE_PATH"], transport=CONFIG["UYUNI_MCP_TRANSPORT"])

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

systems_tools.attach_tools(mcp, _call_uyuni_api, write_tool)
system_tools.attach_tools(mcp, _call_uyuni_api, write_tool, TIMEOUT_HAPPENED)

class ActivationKeySchema(BaseModel):
    activation_key: str

async def _resolve_system_id_from_tool(system_identifier: Union[str, int]) -> Optional[str]:
    """Helper to call the internal _resolve_system_id method on the registered tool."""
    # This function is now less reliable as the helper is not part of the tool object.
    # The direct call to system_tools._resolve_system_id is preferred.
    # This is kept for fallback during transition.
    if hasattr(system_tools, '_resolve_system_id'): # type: ignore
        return await system_tools._resolve_system_id(system_identifier)
    logger.error("_resolve_system_id helper not found on tools module.")
    return None

def main_cli():

    logger.info("Running Uyuni MCP server.")

    if CONFIG["UYUNI_MCP_TRANSPORT"] == Transport.HTTP.value:
        mcp.run(transport="streamable-http")
    elif CONFIG["UYUNI_MCP_TRANSPORT"] == Transport.STDIO.value:
        mcp.run(transport="stdio")
    else:
        # Defaults to stdio transport anyway 
        # But I explicitety state it here for clarity
        mcp.run(transport="stdio")
