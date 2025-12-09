from typing import Any, Dict, Optional
import httpx
from mcp_server_uyuni.logging_config import get_logger

from mcp_server_uyuni.config import CONFIG

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
    params: Dict[str, Any] = None,
    json_body: Dict[str, Any] = None,
    perform_login: bool = True,
    default_on_error: Any = None,
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
        error_msg = (f"Attempted to call a write API ({api_path}) while write tools are disabled. "
                     "Please set UYUNI_MCP_WRITE_TOOLS_ENABLED to 'true' to enable them.")
        logger.error(error_msg)
        return error_msg

    if perform_login:
        login_data = {"login": CONFIG["UYUNI_USER"], "password": CONFIG["UYUNI_PASS"]}
        try:
            login_response = await client.post(CONFIG["UYUNI_SERVER"] + '/rhn/manager/api/login', json=login_data)
            login_response.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error during login for {error_context}: {e.request.url} - {e.response.status_code} - {e.response.text}")
            return default_on_error
        except httpx.RequestError as e:
            logger.exception(f"Request error during login for {error_context}: {e.request.url} - {e}")
            return default_on_error
        except Exception as e:
            logger.exception(f"An unexpected error occurred during login for {error_context}: {e}")
            return default_on_error

    full_api_url = CONFIG["UYUNI_SERVER"] + api_path

    try:
        if method.upper() == 'GET':
            response = await client.get(full_api_url, params=params)
        elif method.upper() == 'POST':
            logger.info(f"POSTing to {full_api_url}")
            response = await client.post(full_api_url, json=json_body, params=params)
            logger.info(f"POST response: {response.text}")
        else:
            logger.info(f"Unsupported HTTP method '{method}' for {error_context}.")
            return default_on_error
        response.raise_for_status()
        response_data = response.json()

        if response_data.get('success'):
            if expected_result_key in response_data:
                return response_data[expected_result_key]
            # If 'success' is true, but the expected_result_key is not there (e.g. 'result' is missing)
            logger.info(f"API call for {error_context} succeeded but '{expected_result_key}' not found in response. Response: {response_data}")
            return default_on_error
        else:
            print(f"API call for {error_context} reported failure. Response: {response_data}")
            return default_on_error

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error occurred while {error_context}: {e.request.url} - {e.response.status_code} - {e.response.text}")
        return default_on_error
    except httpx.TimeoutException as e:
        logger.info(f"timeout! timeout expected? {expect_timeout}")
        if expect_timeout:
            logger.info(f"A timeout occurred while {error_context} (expected for a long-running action): {e.request.url} - {e}")
            return TIMEOUT_HAPPENED
        logger.warning(f"A timeout occurred while {error_context}: {e.request.url} - {e}")
        return default_on_error
    except httpx.RequestError as e:
        logger.exception(f"Request error occurred while {error_context}: {e.request.url} - {e}")
        return default_on_error
    except Exception as e: # Catch other potential errors like JSONDecodeError
        logger.exception(f"An unexpected error occurred while {error_context}: {e}")
        return default_on_error
