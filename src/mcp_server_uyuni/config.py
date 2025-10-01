import os

REQUIRED_VARS = [
    "UYUNI_SERVER",
    "UYUNI_USER",
    "UYUNI_PASS",
]

missing_vars = [key for key in REQUIRED_VARS if key not in os.environ]
if missing_vars:
    raise ImportError(
        f"Failed to import config: Missing required environment variables: {', '.join(missing_vars)}"
    )

UYUNI_SERVER = 'https://' + os.environ["UYUNI_SERVER"]
UYUNI_USER = os.environ["UYUNI_USER"]
UYUNI_PASS = os.environ["UYUNI_PASS"]

UYUNI_MCP_SSL_VERIFY = (
    os.environ.get("UYUNI_MCP_SSL_VERIFY", "true").lower()
    not in ("false", "0", "no")
)
UYUNI_MCP_WRITE_TOOLS_ENABLED = os.environ.get('UYUNI_MCP_WRITE_TOOLS_ENABLED', 'false').lower() in ('true', '1', 'yes')
UYUNI_MCP_TRANSPORT = os.environ.get('UYUNI_MCP_TRANSPORT', 'stdio')
UYUNI_MCP_LOG_FILE_PATH = os.environ.get('UYUNI_MCP_LOG_FILE_PATH') # Defaults to None if not set


CONFIG = {
    "UYUNI_SERVER": UYUNI_SERVER,
    "UYUNI_USER": UYUNI_USER,
    "UYUNI_PASS": UYUNI_PASS,
    "UYUNI_MCP_SSL_VERIFY": UYUNI_MCP_SSL_VERIFY,
    "UYUNI_MCP_WRITE_TOOLS_ENABLED": UYUNI_MCP_WRITE_TOOLS_ENABLED,
    "UYUNI_MCP_TRANSPORT": UYUNI_MCP_TRANSPORT,
    "UYUNI_MCP_LOG_FILE_PATH": UYUNI_MCP_LOG_FILE_PATH,
}
