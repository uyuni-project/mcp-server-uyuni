from typing import Any, Dict, List, Optional


def to_bool(value) -> bool:
    """
    Convert truthy string/boolean/integer values to a boolean.
    Accepts: True, 'true', 'yes', '1', 1, etc.
    """
    return str(value).lower() in ("true", "yes", "1")


def normalize_pagination(limit: Optional[int], offset: int, default_limit: int = 25, max_limit: int = 200) -> tuple[Optional[int], int]:
    """Return a safe `(limit, offset)` tuple for pagination.

    `offset` is cast to `int` and clamped to `>= 0`. `limit=None` means no explicit limit;
    otherwise `limit` is cast to `int`, `<= 0` is preserved as `0` (empty page/count-only),
    and positive values are clamped to `max_limit`.
    """
    normalized_offset = max(0, int(offset))
    if limit is None:
        return None, normalized_offset
    limit_value = int(limit)
    if limit_value <= 0:
        return 0, normalized_offset
    normalized_limit = min(limit_value, max_limit)
    if normalized_limit == 0:
        normalized_limit = default_limit
    return normalized_limit, normalized_offset


def build_list_meta(total_count: int, returned_count: int, limit: Optional[int], offset: int) -> Dict[str, Any]:
    """Build a standard metadata object for paged list responses."""
    if limit is None:
        next_offset = None
        truncated = False
    else:
        next_offset = offset + returned_count if (offset + returned_count) < total_count else None
        truncated = (offset + returned_count) < total_count
    return {
        "total_count": total_count,
        "returned_count": returned_count,
        "limit": limit,
        "offset": offset,
        "next_offset": next_offset,
        "truncated": truncated,
    }


def paginate_items(items: List[Dict[str, Any]], limit: Optional[int], offset: int) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Slice a list using pagination settings and return items with metadata."""
    total_count = len(items)
    if limit is None:
        paged_items = items[offset:] if offset else items
    else:
        paged_items = items[offset: offset + limit]
    meta = build_list_meta(total_count=total_count, returned_count=len(paged_items), limit=limit, offset=offset)
    return paged_items, meta


def matches_optional_filter(value: Optional[str], accepted_values: Optional[set[str]]) -> bool:
    """Return True when a value matches an optional case-insensitive filter set."""
    if not accepted_values:
        return True
    if value is None:
        return False
    return str(value).lower() in accepted_values
