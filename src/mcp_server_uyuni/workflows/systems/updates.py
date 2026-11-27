"""Bounded update views for one system and system searches."""

import asyncio
from typing import Literal, get_args

from ...common.pagination import build_page, validate_page_bounds
from ...constants import AdvisoryType, ApplicationStatus, ResponseFormat
from .discovery import reference, resolve_system

SingleSystemUpdateFormat = Literal["counts", "summary", "standard", "detailed"]

RESPONSE_FORMATS = get_args(ResponseFormat)
SINGLE_SYSTEM_FORMATS = get_args(SingleSystemUpdateFormat)
ADVISORY_TYPES = get_args(AdvisoryType)
APPLICATION_STATUSES = get_args(ApplicationStatus)


def _validate_response_format(response_format: str, supported=RESPONSE_FORMATS):
    if response_format not in supported:
        raise ValueError(f"response_format must be one of: {', '.join(supported)}")


def _validate_update_filters(advisory_types: list[AdvisoryType] | None,
                             application_status: ApplicationStatus | None):
    if advisory_types is not None:
        if not isinstance(advisory_types, list) or any(
            item not in ADVISORY_TYPES for item in advisory_types
        ):
            raise ValueError("advisory_types contains an unsupported advisory type")
    if application_status is not None and application_status not in APPLICATION_STATUSES:
        raise ValueError(f"application_status must be one of: {', '.join(APPLICATION_STATUSES)}")


def _normalize_errata(rows):
    if not isinstance(rows, list):
        raise ValueError("Uyuni returned invalid errata")
    result = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Uyuni returned invalid errata")
        raw_id = row.get("id")
        if type(raw_id) not in (int, str) or not isinstance(row.get("advisory_name"), str):
            raise ValueError("Uyuni returned errata without an ID or advisory name")
        try:
            result.append({**row, "id": int(raw_id)})
        except ValueError:
            raise ValueError("Uyuni returned errata without an ID or advisory name") from None
    return result


def _select_updates(rows, unscheduled_ids, advisory_types: list[AdvisoryType] | None = None,
                    application_status: ApplicationStatus | None = None):
    """Filter updates and classify their pending or queued status."""
    allowed = set(advisory_types) if advisory_types is not None else None
    selected = []
    for row in rows:
        advisory_type = row.get("advisory_type")
        if allowed is not None and advisory_type not in allowed:
            continue
        status = "Pending" if row["id"] in unscheduled_ids else "Queued"
        if application_status is None or status == application_status:
            selected.append((row, status))
    return selected


def _counts(rows, unscheduled_ids=None):
    counts = {"update_count": len(rows), "by_advisory_type": {}}
    for row in rows:
        kind = row.get("advisory_type") or "Unknown"
        counts["by_advisory_type"][kind] = counts["by_advisory_type"].get(kind, 0) + 1
    if unscheduled_ids is not None:
        pending = sum(row["id"] in unscheduled_ids for row in rows)
        counts["pending_update_count"] = pending
        counts["queued_update_count"] = len(rows) - pending
    return counts


def _item(row, response_format: ResponseFormat, status: ApplicationStatus | None = None):
    item = {
        "update_id": row["id"],
        "advisory_name": row["advisory_name"],
        "advisory_type": row.get("advisory_type"),
    }
    if response_format in ("standard", "detailed"):
        item["advisory_synopsis"] = row.get("advisory_synopsis")
        item["reboot_suggested"] = row.get("reboot_suggested")
        item["restart_suggested"] = row.get("restart_suggested")
    if response_format == "detailed":
        item["advisory_status"] = row.get("advisory_status")
        item["issue_date"] = row.get("issue_date")
        item["update_date"] = row.get("update_date")
    if status is not None:
        item["application_status"] = status
    return item


async def _add_cves(api, updates):
    """Expand only advisories that will appear in the response."""
    names = list(dict.fromkeys(update["advisory_name"] for update in updates))
    cve_lists = await asyncio.gather(*(api.errata.list_cves(name) for name in names))
    cves_by_name = dict(zip(names, cve_lists))
    for update in updates:
        update["cves"] = cves_by_name[update["advisory_name"]]


async def _batch_errata_for_page(api, systems):
    """Read relevant errata once for the selected page and verify every system."""
    if not systems:
        return {}

    system_ids = [system["system_id"] for system in systems]
    # limit is at most 100, matching the maximum Uyuni batch size.
    rows = await api.systems.get_relevant_errata_batch(system_ids)
    if not isinstance(rows, list):
        raise ValueError("Uyuni returned invalid batch errata")

    errata_by_id = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Uyuni returned invalid batch errata")
        try:
            system_id = int(row["system_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Uyuni returned invalid batch system ID") from exc
        if system_id in errata_by_id:
            raise ValueError("Uyuni returned duplicate batch system ID")
        errata_by_id[system_id] = _normalize_errata(row.get("errata"))

    if set(errata_by_id) != set(system_ids):
        raise ValueError("Uyuni returned errata for unexpected or missing systems")
    return errata_by_id


async def get_updates(api, system_id: int | None = None, system_name: str | None = None,
                      response_format: SingleSystemUpdateFormat = "summary", limit: int = 25,
                      offset: int = 0, advisory_types: list[AdvisoryType] | None = None,
                      application_status: ApplicationStatus | None = None):
    """Report relevant updates, distinguishing unscheduled from queued errata."""
    validate_page_bounds(limit, offset)
    _validate_response_format(response_format, SINGLE_SYSTEM_FORMATS)
    _validate_update_filters(advisory_types, application_status)
    if response_format == "counts" and offset != 0:
        raise ValueError("offset must be 0 when response_format is counts")
    system = await resolve_system(api, system_id, system_name)
    sid = system["system_id"]
    relevant, unscheduled = await asyncio.gather(
        api.systems.get_relevant_errata(sid), api.systems.get_unscheduled_errata(sid)
    )
    relevant = _normalize_errata(relevant)
    unscheduled_ids = {row["id"] for row in _normalize_errata(unscheduled)}
    selected = _select_updates(relevant, unscheduled_ids, advisory_types, application_status)

    if response_format == "counts":
        # No advisory page is requested; the summary still counts all matches.
        result = build_page([], 0, limit, "response_only")
    else:
        page_updates = selected[offset:offset + limit + 1]
        items = [_item(row, response_format, status) for row, status in page_updates]
        if response_format == "detailed":
            await _add_cves(api, items[:limit])
        result = build_page(items, offset, limit, "response_only")
    result["system"] = system
    result["summary"] = _counts([row for row, _ in selected], unscheduled_ids)
    result["response_format"] = response_format
    return result


async def search_updates(api, group_name: str | None = None,
                         response_format: ResponseFormat = "summary",
                         limit: int = 25, offset: int = 0):
    """Page systems with outdated packages, then enrich the selected page."""
    validate_page_bounds(limit, offset)
    _validate_response_format(response_format)
    if group_name is not None and (not isinstance(group_name, str) or not group_name.strip()):
        raise ValueError("group_name must be non-empty")

    systems_by_id = {}
    for row in await api.systems.list_out_of_date_systems():
        system = reference(row)
        count = row.get("outdated_pkg_count")
        if type(count) is not int or count <= 0:
            raise ValueError("Uyuni returned an invalid outdated package count")
        sid = system["system_id"]
        if sid in systems_by_id:
            raise ValueError("Uyuni returned a duplicate out-of-date system")
        systems_by_id[sid] = {**system, "outdated_package_count": count}

    if group_name:
        group_ids = {
            reference(row)["system_id"]
            for row in await api.systems.list_group_systems(group_name)
        }
        systems_by_id = {sid: system for sid, system in systems_by_id.items() if sid in group_ids}

    systems = [systems_by_id[sid] for sid in sorted(systems_by_id)]
    result = build_page(systems[offset:offset + limit + 1], offset, limit, "response_only")
    page_systems = result["items"]
    errata_by_id = await _batch_errata_for_page(api, page_systems)

    items = []
    for system in page_systems:
        rows = errata_by_id[system["system_id"]]
        counts = _counts(rows)
        item = {
            **system,
            "relevant_advisory_count": counts["update_count"],
            "by_advisory_type": counts["by_advisory_type"],
        }
        if response_format != "summary":
            preview_limit = 5 if response_format == "detailed" else 25
            item["updates"] = [_item(row, response_format) for row in rows[:preview_limit]]
            item["updates_truncated"] = len(rows) > preview_limit
        items.append(item)
    result["items"] = items
    if response_format == "detailed":
        # Expand only the visible systems and their bounded advisory previews.
        updates = [
            update
            for item in result["items"]
            for update in item["updates"]
        ]
        await _add_cves(api, updates)
    result["response_format"] = response_format
    return result
