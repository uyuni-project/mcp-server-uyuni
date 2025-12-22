from typing import Any, Dict, Optional
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

logger = get_logger(__name__)

TIMEOUT_HAPPENED = object()

class UyuniApi:
    def __init__(self, base_url: str, verify: bool, timeout: Optional[httpx.Timeout] = None):
        self.base_url = base_url.rstrip("/")
        self.verify = verify
        self.timeout = timeout or httpx.Timeout(30.0, connect=10.0)

async def call(
    client: httpx.AsyncClient,
    method: str,
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

    # Safety check: Do not allow POST requests if write tools are disabled.
    # This acts as a secondary guard after the @write_tool decorator.
    if method.upper() == 'POST' and not CONFIG["UYUNI_MCP_WRITE_TOOLS_ENABLED"]:
        error_msg = (
            f"Attempted to call a write API ({api_path}) while write tools are disabled. "
            "Please set UYUNI_MCP_WRITE_TOOLS_ENABLED to 'true' to enable them."
        )
        logger.error(error_msg)
        raise APIError(error_msg)

    full_api_url = CONFIG["UYUNI_SERVER"] + api_path
    if perform_login:
        try:
            if token:
                # Try OIDC login with provided token
                login_response = await client.post(
                    CONFIG["UYUNI_SERVER"] + '/rhn/manager/api/oidcLogin',
                    headers={"Authorization": f"Bearer {token}"}
                )
                login_response.raise_for_status()
            elif CONFIG["UYUNI_USER"] and CONFIG["UYUNI_PASS"]:
                login_response = await client.post(
                    CONFIG["UYUNI_SERVER"] + '/rhn/manager/api/login',
                    json={"login": CONFIG["UYUNI_USER"], "password": CONFIG["UYUNI_PASS"]}
                )
                login_response.raise_for_status()
            else:
                logger.warning(f"perform_login=True but no token or username/password available for {error_context}; skipping login.")
        except httpx.HTTPStatusError as e:
            status = e.response.status_code if e.response is not None else None
            body = e.response.text if e.response is not None else ''
            logger.error(f"HTTP error during login for {error_context}: {getattr(e.request,'url',full_api_url)} - {status} - {body}")
            if status in (401, 403):
                raise AuthError(status, str(getattr(e.request, 'url', full_api_url)), body)
            raise HTTPError(status or -1, str(getattr(e.request, 'url', full_api_url)), body)
        except httpx.RequestError as e:
            logger.exception(f"Request error during login for {error_context}: {getattr(e.request,'url',full_api_url)} - {e}")
            raise NetworkError(getattr(e.request, 'url', full_api_url), e)

    try:
        method_upper = method.upper()
        if method_upper == 'GET':
            response = await client.get(full_api_url, params=params)
        elif method_upper == 'POST':
            logger.info(f"POSTing to {full_api_url}")
            response = await client.post(full_api_url, json=json_body, params=params)
            logger.debug(f"POST response status: {response.status_code}")
        else:
            raise APIError(f"Unsupported HTTP method '{method}' for {error_context}.")

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
                message = response_data.get('message', str(response_data))
                logger.warning(f"Uyuni API reported failure for {error_context}. Response: {response_data}")
                raise UnexpectedResponse(full_api_url, message)

        # Otherwise return whatever we received (list, dict, string, etc.)
        return response_data

    except httpx.HTTPStatusError as e:
        status = e.response.status_code if e.response is not None else None
        body = e.response.text if e.response is not None else ''
        logger.error(f"HTTP error occurred while {error_context}: {getattr(e.request,'url',full_api_url)} - {status} - {body}")
        if status in (401, 403):
            raise AuthError(status, str(getattr(e.request, 'url', full_api_url)), body)
        raise HTTPError(status or -1, str(getattr(e.request, 'url', full_api_url)), body)
    except httpx.TimeoutException as e:
        logger.debug(f"Timeout! timeout expected? {expect_timeout}")
        if expect_timeout:
            logger.info(f"A timeout occurred while {error_context} (expected for a long-running action): {getattr(e.request,'url',full_api_url)} - {e}")
            return TIMEOUT_HAPPENED
        logger.warning(f"A timeout occurred while {error_context}: {getattr(e.request,'url',full_api_url)} - {e}")
        raise NetworkError(getattr(e.request, 'url', full_api_url), e, timed_out=True)
    except httpx.RequestError as e:
        logger.exception(f"Request error occurred while {error_context}: {getattr(e.request,'url',full_api_url)} - {e}")
        raise NetworkError(getattr(e.request, 'url', full_api_url), e)
    except UnexpectedResponse:
        # Propagate API-specific failures unchanged
        raise
    except Exception as e: # Catch other potential errors like JSONDecodeError
        logger.exception(f"An unexpected error occurred while {error_context}: {e}")
        raise APIError(f"Unexpected error while {error_context}: {e}")
