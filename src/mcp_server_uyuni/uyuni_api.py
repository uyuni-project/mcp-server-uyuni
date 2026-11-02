"""Compatibility imports for the legacy Uyuni API module."""

from .api.client import TIMEOUT_HAPPENED, UyuniApi, _authenticate_client, call, logger, login

__all__ = ["TIMEOUT_HAPPENED", "UyuniApi", "call", "login"]
