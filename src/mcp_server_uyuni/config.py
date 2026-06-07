import os
import logging
from urllib.parse import urlparse, urlunparse

REQUIRED_VARS = [
    "UYUNI_SERVER"
]

missing_vars = [key for key in REQUIRED_VARS if key not in os.environ]
if missing_vars:
    raise ImportError(
        f"Failed to import config: Missing required environment variables: {', '.join(missing_vars)}"
    )


def _normalize_uri(raw_value: str, var_name: str, allow_path: bool, default_scheme: str) -> str:
    value = raw_value.strip()
    if not value:
        raise ImportError(f"Failed to import config: {var_name} must not be empty")

    if "://" not in value:
        value = f"{default_scheme}://{value}"

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ImportError(
            f"Failed to import config: {var_name} must use http or https and include a host"
        )

    if parsed.params or parsed.query or parsed.fragment:
        raise ImportError(
            f"Failed to import config: {var_name} must not include params, query, or fragment"
        )

    if not allow_path and parsed.path not in ("", "/"):
        raise ImportError(
            f"Failed to import config: {var_name} must not include a path"
        )

    normalized_path = parsed.path.rstrip("/") if allow_path else ""
    normalized = parsed._replace(path=normalized_path, params="", query="", fragment="")
    return urlunparse(normalized)


UYUNI_SERVER = _normalize_uri(
    os.environ["UYUNI_SERVER"],
    "UYUNI_SERVER",
    allow_path=False,
    default_scheme="https",
)
UYUNI_USER = os.environ.get("UYUNI_USER")
UYUNI_PASS = os.environ.get("UYUNI_PASS")

UYUNI_MCP_HOST = os.environ.get("UYUNI_MCP_HOST", "127.0.0.1")
UYUNI_MCP_PORT = int(os.environ.get("UYUNI_MCP_PORT", "8000"))
UYUNI_MCP_PUBLIC_URL = os.environ.get("UYUNI_MCP_PUBLIC_URL")

UYUNI_AUTH_SERVER = os.environ.get("UYUNI_AUTH_SERVER")
UYUNI_AUTH_SERVER = (
    _normalize_uri(
        UYUNI_AUTH_SERVER,
        "UYUNI_AUTH_SERVER",
        allow_path=True,
        default_scheme="https",
    )
    if UYUNI_AUTH_SERVER and UYUNI_AUTH_SERVER.strip()
    else None
)

UYUNI_MCP_SSL_VERIFY = (
    os.environ.get("UYUNI_MCP_SSL_VERIFY", "true").lower()
    not in ("false", "0", "no")
)

UYUNI_MCP_WRITE_TOOLS_ENABLED = (
    os.environ.get('UYUNI_MCP_WRITE_TOOLS_ENABLED', 'false').lower()
    in ('true', '1', 'yes')
)

UYUNI_MCP_TIMEOUT = float(os.environ.get('UYUNI_MCP_TIMEOUT', '30'))
UYUNI_MCP_TRANSPORT = os.environ.get('UYUNI_MCP_TRANSPORT', 'stdio').strip().lower()
if UYUNI_MCP_TRANSPORT not in ('stdio', 'http'):
    raise ImportError(
        "Failed to import config: UYUNI_MCP_TRANSPORT must be either 'stdio' or 'http'"
    )
UYUNI_MCP_LOG_FILE_PATH = os.environ.get('UYUNI_MCP_LOG_FILE_PATH')

log_level_str = os.environ.get('UYUNI_MCP_LOG_LEVEL', 'info').upper()
UYUNI_MCP_LOG_LEVEL = getattr(logging, log_level_str, logging.INFO)

UYUNI_PRODUCT_NAME= os.environ.get("UYUNI_PRODUCT_NAME", "Uyuni")


CONFIG = {
    "UYUNI_SERVER": UYUNI_SERVER,
    "UYUNI_USER": UYUNI_USER,
    "UYUNI_PASS": UYUNI_PASS,
    "UYUNI_MCP_SSL_VERIFY": UYUNI_MCP_SSL_VERIFY,
    "UYUNI_MCP_WRITE_TOOLS_ENABLED": UYUNI_MCP_WRITE_TOOLS_ENABLED,
    "UYUNI_MCP_TIMEOUT": UYUNI_MCP_TIMEOUT,
    "UYUNI_MCP_TRANSPORT": UYUNI_MCP_TRANSPORT,
    "UYUNI_MCP_LOG_FILE_PATH": UYUNI_MCP_LOG_FILE_PATH,
    "UYUNI_MCP_LOG_LEVEL": UYUNI_MCP_LOG_LEVEL,
    "UYUNI_MCP_HOST": UYUNI_MCP_HOST,
    "UYUNI_MCP_PORT": UYUNI_MCP_PORT,
    "UYUNI_MCP_PUBLIC_URL": UYUNI_MCP_PUBLIC_URL,
    "AUTH_SERVER": UYUNI_AUTH_SERVER,
    "UYUNI_PRODUCT_NAME": UYUNI_PRODUCT_NAME
}
