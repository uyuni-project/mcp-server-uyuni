# mcp-server-uyuni

Model Context Protocol Server for Uyuni Server API.

## Tools

* get_list_of_active_systems
* get_cpu_of_a_system

## Usage

You need `uv` installed. See https://docs.astral.sh/uv

Once you have `uv`, install the dependencies with:

`uv sync`

You need to create the `.venv/credentials` with a content like this:

```
UYUNI_SERVER=192.168.1.124:8443
UYUNI_USER=admin
UYUNI_PASS=admin
```

Replace the values by the ones that make sense for you.

Then, you can use this command with an `mcp-client`:

`uv run --env-file=.venv/credentials --directory PATH OF THIS CHECKOUT mcp-server-uyuni.py`

## Debug with mcp inspect

You can run

`npx @modelcontextprotocol/inspector uv --env-file=.venv/credentials --directory PATH OF THIS CHECKOUT run mcp-server-uyuni.py`

## Use with langflow

You can add an `MCP Server tool` and set the `MCP Command` to:

`uv run --env-file=.venv/credentials --directory PATH OF THIS CHECKOUT mcp-server-uyuni.py`

## License

MIT

