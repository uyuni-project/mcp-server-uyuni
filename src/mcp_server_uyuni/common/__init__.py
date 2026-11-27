"""Shared contracts used across workflows."""

from .pagination import (
    build_list_meta,
    build_page,
    normalize_pagination,
    paginate_items,
    validate_page_bounds,
)

__all__ = [
    "build_list_meta",
    "build_page",
    "normalize_pagination",
    "paginate_items",
    "validate_page_bounds",
]
