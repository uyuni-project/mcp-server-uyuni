# Legacy catalog baseline

`legacy_tool_catalog.v0.6.1.json` records the ordered MCP tool catalog on
FastMCP 3.4.5 with writes disabled (18 tools) and enabled (27 tools). Each tool
entry includes its name, description, input and output schemas, annotations,
and serialized schema size. The size is the UTF-8 byte length of compact,
sorted JSON for those fields; each catalog total is the sum of its tool sizes.
