"""CVE system search using needed advisories and native audit data."""

import asyncio
import re
from typing import Literal

from ..common.pagination import build_page, validate_page_bounds

PatchStatus = Literal[
    "AFFECTED_PATCH_INAPPLICABLE", "AFFECTED_PATCH_APPLICABLE",
    "NOT_AFFECTED", "PATCHED",
]
PATCH_STATUSES = set(PatchStatus.__args__)


def _normalize_cve(identifier: str) -> str:
    """Require a real CVE identifier and normalize case."""
    if not isinstance(identifier, str):
        raise ValueError("cve_identifier must be a string")
    normalized = identifier.strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
        raise ValueError("cve_identifier must look like CVE-YYYY-NNNN")
    return normalized


def _audit_items(rows):
    """Validate audit rows while retaining source status and advisory fields."""
    items = []
    for row in rows:
        sid = row.get("system_id")
        status = row.get("patch_status")
        channels = row.get("channel_labels")
        advisories = row.get("errata_advisories")
        valid_identity = type(sid) is int and isinstance(status, str) and bool(status)
        valid_channels = isinstance(channels, list) and all(
            isinstance(label, str) for label in channels
        )
        valid_advisories = isinstance(advisories, list) and all(
            isinstance(name, str) for name in advisories
        )
        if not (valid_identity and valid_channels and valid_advisories):
            raise ValueError("Uyuni returned an invalid CVE audit system")
        items.append({
            "system_id": sid,
            "patch_status": status,
            "channel_labels": channels,
            "errata_advisories": advisories,
        })
    return items


async def _systems_with_needed_advisory(errata_api, cve_identifier):
    """Use the same needed-errata membership query as the legacy CVE tool."""
    advisories = await errata_api.find_by_cve(cve_identifier)
    names = []
    seen_names = set()
    for row in advisories:
        name = row.get("advisory_name")
        if not isinstance(name, str) or not name:
            raise ValueError("Uyuni returned a CVE advisory without a name")
        if name not in seen_names:
            names.append(name)
            seen_names.add(name)

    # Uyuni offers no batch listAffectedSystems overload. Bound concurrency
    # when a CVE has several advisories, then deduplicate their systems.
    semaphore = asyncio.Semaphore(8)

    async def affected(name):
        async with semaphore:
            return await errata_api.list_affected_systems(name)

    collections = await asyncio.gather(*(affected(name) for name in names))
    systems_by_id = {}
    for rows in collections:
        for row in rows:
            sid = row.get("id")
            name = row.get("name")
            if type(sid) is not int or not isinstance(name, str) or not name:
                raise ValueError("Uyuni returned an invalid affected system")
            systems_by_id[sid] = {"system_id": sid, "system_name": name}
    return sorted(systems_by_id.values(), key=lambda row: (row["system_name"].lower(), row["system_id"]))


async def search_cve_systems(api, cve_identifier: str,
                             patch_statuses: list[PatchStatus] | None = None,
                             limit: int = 25, offset: int = 0):
    """Match legacy needed-advisory scope by default; use native status filters explicitly."""
    validate_page_bounds(limit, offset)
    cve = _normalize_cve(cve_identifier)
    if patch_statuses is not None and (
        not isinstance(patch_statuses, list) or
        any(item not in PATCH_STATUSES for item in patch_statuses)
    ):
        raise ValueError("patch_statuses contains an unsupported patch status")

    if patch_statuses is not None:
        rows = await api.audit.list_systems_by_patch_status(cve, patch_statuses)
        items = _audit_items(rows)
        result = build_page(items[offset:offset + limit + 1], offset, limit, "response_only")
        result["cve_identifier"] = cve
        result["patch_statuses"] = patch_statuses
        return result

    systems = await _systems_with_needed_advisory(api.errata, cve)
    audit_by_id = {}
    if systems:
        audit_rows = _audit_items(await api.audit.list_systems_by_patch_status(cve))
        audit_by_id = {row["system_id"]: row for row in audit_rows}
    items = []
    missing_count = 0
    for system in systems:
        audit = audit_by_id.get(system["system_id"])
        if audit is None:
            missing_count += 1
        items.append({
            **system,
            "patch_status": audit["patch_status"] if audit else None,
            "channel_labels": audit["channel_labels"] if audit else [],
            "errata_advisories": audit["errata_advisories"] if audit else [],
        })
    result = build_page(items[offset:offset + limit + 1], offset, limit, "response_only")
    if missing_count:
        result["warnings"].append(
            f"Audit data unavailable for {missing_count} matching systems"
        )

    result["cve_identifier"] = cve
    result["patch_statuses"] = patch_statuses
    return result
