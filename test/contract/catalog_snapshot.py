"""Generate the environment-independent legacy MCP catalog baseline."""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

BASELINE = Path(__file__).resolve().parents[1] / "results" / "legacy_tool_catalog.v0.6.1.json"


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _capture(write_enabled):
    from mcp_server_uyuni.server import mcp

    tools = asyncio.run(mcp.list_tools())
    entries = []
    for tool in tools:
        wire_tool = tool.to_mcp_tool()
        entry = {
            "name": wire_tool.name,
            "description": wire_tool.description,
            "input_schema": wire_tool.inputSchema,
            "output_schema": wire_tool.outputSchema,
            "annotations": (
                wire_tool.annotations.model_dump(exclude_none=True, mode="json")
                if wire_tool.annotations else None
            ),
        }
        entry["serialized_schema_bytes"] = len(_json(entry).encode("utf-8"))
        entries.append(entry)
    return {
        "write_enabled": write_enabled,
        "tool_count": len(entries),
        "serialized_schema_bytes": sum(entry["serialized_schema_bytes"] for entry in entries),
        "tools": entries,
    }


def generate():
    catalogs = []
    for write_enabled in (False, True):
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "UYUNI_SERVER": "https://baseline.invalid",
            "UYUNI_USER": "baseline",
            "UYUNI_PASS": "baseline",
            "UYUNI_PRODUCT_NAME": "Uyuni",
            "UYUNI_MCP_TRANSPORT": "stdio",
            "UYUNI_MCP_WRITE_TOOLS_ENABLED": str(write_enabled).lower(),
        }
        completed = subprocess.run(
            [sys.executable, __file__, "--state", str(write_enabled).lower()],
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        )
        catalogs.append(json.loads(completed.stdout))
    return {"version": "0.6.1", "catalogs": catalogs}


def serialized_baseline():
    return json.dumps(generate(), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--state":
        print(_json(_capture(sys.argv[2] == "true")))
    elif sys.argv[1:] == ["--write"]:
        BASELINE.write_text(serialized_baseline())
    else:
        raise SystemExit("Usage: catalog_snapshot.py --write")
