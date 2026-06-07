from typing import Any, Dict, Literal, Optional
import httpx

from .logging_config import get_logger
from .config import CONFIG
from .errors import (
    APIError,
    HTTPError,
    AuthError,
    NetworkError,
    UnexpectedResponse
)

logger = get_logger(__name__, log_level=CONFIG["UYUNI_MCP_LOG_LEVEL"])

TIMEOUT_HAPPENED = object()

class UyuniApi:
    def __init__(self, base_url: str, verify: bool, timeout: Optional[httpx.Timeout] = None):
        self.base_url = base_url.rstrip("/")
        self.verify = verify
        self.timeout = timeout or httpx.Timeout(30.0, connect=10.0)


async def _authenticate_client(
    client: httpx.AsyncClient,
    token: Optional[str] = None,
    error_context: Optional[str] = None,
) -> None:
    """Authenticate an AsyncClient using token (OIDC) or username/password."""
    login_url = CONFIG["UYUNI_SERVER"] + '/rhn/manager/api/login'

    try:
        if token:
            login_url = CONFIG["UYUNI_SERVER"] + '/rhn/manager/api/oidcLogin'
            response = await client.post(
                login_url,
                headers={"Authorization": f"Bearer {token}"}
            )
        elif CONFIG["UYUNI_USER"] and CONFIG["UYUNI_PASS"]:
            response = await client.post(
                login_url,
                json={"login": CONFIG["UYUNI_USER"], "password": CONFIG["UYUNI_PASS"]}
            )
        else:
            logger.warning(
                "Skipping authentication%s: no token and no username/password configured.",
                f" for {error_context}" if error_context else "",
            )
            return

        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        status = e.response.status_code if e.response is not None else None
        body = e.response.text if e.response is not None else ''
        request_url = getattr(e.request, 'url', login_url)

        if error_context is None:
            logger.error(f"HTTP error during login: {request_url} - {status} - {body}")
        else:
            logger.error(f"HTTP error during login for {error_context}: {request_url} - {status} - {body}")

        if status in (401, 403):
            raise AuthError(status, login_url, body)
        raise HTTPError(status or -1, login_url, body)
    except httpx.RequestError as e:
        request_url = getattr(e.request, 'url', login_url)

        if error_context is None:
            logger.exception(f"Request error during login: {request_url} - {e}")
        else:
            logger.exception(f"Request error during login for {error_context}: {request_url} - {e}")

        raise NetworkError(login_url, e)

async def login(client: httpx.AsyncClient, token: Optional[str] = None) -> None:
    """
    Authenticate the given AsyncClient against Uyuni.
    After this call the client holds a session cookie that can be reused
    for subsequent requests without re-logging in.
    """
    await _authenticate_client(client, token=token)

async def call(
    client: httpx.AsyncClient,
    method: Literal["GET", "POST"],
    api_path: str,
    error_context: str,
    token: Optional[str] = None,
    params: Dict[str, Any] = None,
    json_body: Dict[str, Any] = None,
    perform_login: bool = True,
    expected_result_key: str = 'result',
    expect_timeout: bool = False
) -> Any:
    """
    Helper function to make authenticated API calls to Uyuni.
    Handles login, request execution, error handling, and basic response parsing.
    """

    if method not in ("GET", "POST"):
        raise APIError(
            f"Unsupported HTTP method '{method}'. Expected 'GET' or 'POST'."
        )

    # Safety check: Do not allow POST requests if write tools are disabled.
    # This acts as a secondary guard after the @write_tool decorator.
    if method == 'POST' and not CONFIG["UYUNI_MCP_WRITE_TOOLS_ENABLED"]:
        error_msg = (
            f"Attempted to call a write API ({api_path}) while write tools are disabled. "
            "Please set UYUNI_MCP_WRITE_TOOLS_ENABLED to 'true' to enable them."
        )
        logger.error(error_msg)
        raise APIError(error_msg)

    full_api_url = CONFIG["UYUNI_SERVER"] + api_path
    if perform_login:
        await _authenticate_client(
            client,
            token=token,
            error_context=error_context,
        )

    try:
        logger.info(f"{method} request to {full_api_url}")

        response = await client.request(
            method=method,
            url=full_api_url,
            params=params,
            json=json_body,
        )

        logger.debug(f"{method} response status: {response.status_code}")
        logger.debug(f"{method} response text: {response.text}")

        response.raise_for_status()

        # Parse JSON if possible, otherwise fall back to raw text
        try:
            response_data = response.json()
        except Exception:
            response_data = response.text

        # If response is a dict and follows Uyuni's {success: bool, result: ...} pattern
        if isinstance(response_data, dict) and 'success' in response_data:
            if response_data.get('success'):
                # Prefer the expected_result_key but return full response dict as a fallback
                return response_data.get(expected_result_key, response_data)
            else:
                logger.error(f"Uyuni API reported failure for {error_context}. Response: {response_data}")
                raise UnexpectedResponse(full_api_url, response_data.get('message', response_data))

        # Otherwise return whatever we received (list, dict, string, etc.)
        return response_data

    except httpx.HTTPStatusError as e:
        status = e.response.status_code if e.response is not None else None
        body = e.response.text if e.response is not None else ''
        request_url = getattr(e.request, "url", full_api_url)
        logger.error(
            f"HTTP error occurred while {error_context}: "
            f"{request_url} - {status} - {body}"
        )
        if status in (401, 403):
            raise AuthError(status, full_api_url, body)
        raise HTTPError(status or -1, full_api_url, body)

    except httpx.TimeoutException as e:
        logger.debug(f"Timeout! timeout expected? {expect_timeout}")
        request_url = getattr(e.request, "url", full_api_url)
        if expect_timeout:
            logger.info(
                f"A timeout occurred while {error_context} "
                f"(expected for a long-running action): {request_url} - {e}"
            )
            return TIMEOUT_HAPPENED
        logger.warning(
            f"A timeout occurred while {error_context}: {request_url} - {e}"
        )
        raise NetworkError(full_api_url, e, timed_out=True)

    except httpx.RequestError as e:
        request_url = getattr(e.request, "url", full_api_url)
        logger.exception(
            f"Request error occurred while {error_context}: {request_url} - {e}"
        )
        raise NetworkError(full_api_url, e)

    except UnexpectedResponse:
        # Propagate API-specific failures unchanged
        raise

    except Exception as e:  # Catch other potential errors like JSONDecodeError
        logger.exception(f"An unexpected error occurred while {error_context}: {e}")
        raise APIError(f"Unexpected error while {error_context}: {e}")
