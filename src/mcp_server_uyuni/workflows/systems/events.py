"""System event retrieval."""

from datetime import datetime

from ...common.pagination import build_page, validate_page_bounds
from .discovery import resolve_system, timestamp


async def list_events(api, system_id=None, system_name=None, limit: int = 25, offset: int = 0,
                      earliest_date: str | None = None):
    """Return one native Uyuni page of compact events for a resolved system."""
    validate_page_bounds(limit, offset)
    if earliest_date is not None:
        try:
            datetime.fromisoformat(earliest_date.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("earliest_date must be ISO 8601") from exc
    system = await resolve_system(api, system_id, system_name)
    # Request one extra row to detect whether another page exists. Uyuni
    # returns event history newest first.
    rows = await api.systems.get_event_history(
        system["system_id"], offset, limit + 1, earliest_date
    )
    events = []
    for row in rows:
        events.append({
            "event_id": row.get("id"),
            "history_type": row.get("history_type"),
            "status": row.get("status"),
            "summary": row.get("summary"),
            "completed": timestamp(row.get("completed")),
        })

    result = build_page(events, offset, limit, "native")
    result["system"] = system
    return result


async def get_event(api, event_id: int, system_id=None, system_name=None):
    """Get an event using both its ID and the owning system reference."""
    if type(event_id) is not int or event_id <= 0:
        raise ValueError("event_id must be a positive integer")

    system = await resolve_system(api, system_id, system_name)
    row = await api.systems.get_event_details(system["system_id"], event_id)
    if row.get("id") != event_id:
        raise ValueError("Uyuni returned an event with a different ID")

    return {
        "system": system,
        "event_id": event_id,
        "history_type": row.get("history_type"),
        "status": row.get("status"),
        "summary": row.get("summary"),
        "created": timestamp(row.get("created")),
        "picked_up": timestamp(row.get("picked_up")),
        "completed": timestamp(row.get("completed")),
        "earliest_action": timestamp(row.get("earliest_action")),
        "result_msg": row.get("result_msg"),
        "result_code": row.get("result_code"),
        "additional_info": row.get("additional_info") or [],
    }
