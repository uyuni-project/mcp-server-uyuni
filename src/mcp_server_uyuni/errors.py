"""Centralized API exception classes for the MCP server.

This module exposes a small hierarchy of exceptions that describe
transport, HTTP and application-level failures when talking to Uyuni.
"""

class APIError(Exception):
    """Base class for API errors."""


class HTTPError(APIError):
    """HTTP status related error.

    Attributes:
        status_code: HTTP status code returned by the server.
        url: URL that was requested.
        body: Optional response body.
    """

    def __init__(self, status_code: int, url: str, body: str | None = None):
        msg = f"HTTP error {status_code} for {url}. Response body: {body!r}"
        super().__init__(msg)
        self.status_code = status_code
        self.url = url
        self.body = body


class AuthError(HTTPError):
    """Authentication-related HTTP error.
    """
    # No custom constructor: behave exactly like HTTPError.
    pass


class NetworkError(APIError):
    """Network/transport level error.

    Represents both timeouts and other connection-level failures. Callers
    can inspect the `timed_out` attribute to distinguish timeouts.
    """

    def __init__(self, url: str, original: Exception | None = None, timed_out: bool = False):
        if timed_out:
            msg = (
                f"Timeout while contacting Uyuni at {url}. This may indicate a long-running "
                "action or network issues. Original: {original}"
            )
        else:
            msg = f"Network error while contacting Uyuni at {url}: {original}"
        super().__init__(msg)
        self.url = url
        self.original = original
        self.timed_out = timed_out


class UnexpectedResponse(APIError):
    """Application-level unexpected response from Uyuni.

    This represents business-logic level failures returned by the Uyuni API
    (for example: resource not found, entity already exists, validation
    failures, etc.). The `response` should be a human-readable string with
    the message/reason returned by Uyuni.
    """

    def __init__(self, url: str, response: str | None = None):
        msg = f"Unexpected response from Uyuni at {url}: {response!r}"
        super().__init__(msg)
        self.url = url
        self.response = response


class NotFoundError(APIError):
    """
    Raised when an entity/resource is not found in Uyuni or MCP APIs.
    Can be used for missing systems, packages, events, etc.
    The identifier is either an int or a str.
    """
    def __init__(self, what: str, identifier: int | str = None):
        msg = f"{what} not found" + (f" (identifier: {identifier})" if identifier is not None else "")
        super().__init__(msg)
        self.what = what
        self.identifier: int | str | None = identifier


__all__ = [
    "APIError",
    "HTTPError",
    "AuthError",
    "NetworkError",
    "UnexpectedResponse",
    "NotFoundError",
]
