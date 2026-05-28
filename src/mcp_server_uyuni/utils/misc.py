from typing import Optional


def matches_optional_filter(
    value: Optional[str],
    accepted_values: Optional[set[str]],
) -> bool:
    """Return True when a value matches an optional case-insensitive filter set."""
    if not accepted_values:
        return True
    if value is None:
        return False
    return str(value).lower() in accepted_values
