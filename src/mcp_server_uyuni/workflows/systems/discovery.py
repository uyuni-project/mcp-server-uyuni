"""System search, reference resolution, and canonical details."""

import asyncio
from datetime import datetime, timezone

from ...common.pagination import build_page, validate_page_bounds


class SystemNotFoundError(LookupError):
    """The requested system name has no exact match."""

    pass


class AmbiguousSystemError(ValueError):
    """An exact system name matches multiple visible systems."""

    def __init__(self, name: str, candidates: list[dict]):
        self.candidates = candidates
        super().__init__(
            f"System name {name!r} is ambiguous. "
            f"Retry with system_id; candidates: {candidates}"
        )


def timestamp(value):
    """Render datetime values as UTC without changing Uyuni date strings."""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return value


def reference(raw: dict) -> dict:
    """Normalize the name fields used by different Uyuni system methods."""
    sid = raw.get("id", raw.get("system_id"))
    name = raw.get("name", raw.get("profile_name", raw.get("system_name")))
    if type(sid) is not int or not isinstance(name, str):
        raise ValueError("Uyuni returned an invalid system reference")
    return {"system_id": sid, "system_name": name}


async def resolve_id(api, system_id: int | None = None, system_name: str | None = None) -> int:
    """Resolve exactly one identifier through Uyuni's exact-name lookup."""
    if (system_id is None) == (system_name is None):
        raise ValueError("Provide exactly one of system_id or system_name")
    if system_id is not None:
        if type(system_id) is not int or system_id <= 0:
            raise ValueError("system_id must be a positive integer")
        return system_id
    if not isinstance(system_name, str) or not system_name.strip():
        raise ValueError("system_name must be non-empty")

    name = system_name.strip()
    matches = [reference(row) for row in await api.systems.get_id(name)]
    if not matches:
        raise SystemNotFoundError(f"System {name!r} not found")
    if len(matches) > 1:
        raise AmbiguousSystemError(name, matches[:25])
    return matches[0]["system_id"]


async def resolve_system(api, system_id: int | None = None, system_name: str | None = None) -> dict:
    """Return an ID and name for event responses."""
    sid = await resolve_id(api, system_id, system_name)
    details = await api.systems.get_details(sid)
    return reference(details)


async def search_systems(api, hostname=None, ip=None, uuid=None, name=None, group_name=None,
                         reboot_required: bool | None = None, limit: int = 25,
                         offset: int = 0):
    """Intersect Uyuni search, group, and reboot results."""
    validate_page_bounds(limit, offset)
    filters = {
        "hostname": hostname,
        "ip": ip,
        "uuid": uuid,
        "nameAndDescription": name,
    }
    for value in (*filters.values(), group_name):
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ValueError("Search filters must be non-empty strings")
    if reboot_required is not None and type(reboot_required) is not bool:
        raise ValueError("reboot_required must be boolean")

    # Group and reboot searches have dedicated Uyuni methods. General searches
    # have no native pagination, so we intersect their complete results here.
    sources = []
    if group_name:
        sources.append(await api.systems.list_group_systems(group_name))
    # True intersects the reboot list; False removes those IDs afterward.
    excluded_reboot_ids = set()
    if reboot_required is not None:
        reboot_systems = await api.systems.list_suggested_reboot()
        if reboot_required:
            sources.append(reboot_systems)
        else:
            excluded_reboot_ids = {reference(row)["system_id"] for row in reboot_systems}
    for field, term in filters.items():
        if term:
            sources.append(await api.systems.search(field, term))
    if not sources:
        sources.append(await api.systems.list_systems())

    candidate_ids = {reference(row)["system_id"] for row in sources[0]}
    for source in sources[1:]:
        source_ids = {reference(row)["system_id"] for row in source}
        candidate_ids.intersection_update(source_ids)

    candidate_ids.difference_update(excluded_reboot_ids)

    references_by_id = {}
    for source in sources:
        for row in source:
            system = reference(row)
            references_by_id[system["system_id"]] = system

    matches = [references_by_id[sid] for sid in sorted(candidate_ids)]
    requested_slice = matches[offset:offset + limit + 1]
    return build_page(requested_slice, offset, limit, "response_only")


async def get_system(api, system_id=None, system_name=None):
    """Combine Uyuni's detail endpoints into one stable system response."""
    sid = await resolve_id(api, system_id, system_name)
    details, cpu, network, uuid, products = await asyncio.gather(
        api.systems.get_details(sid),
        api.systems.get_cpu(sid),
        api.systems.get_network(sid),
        api.systems.get_uuid(sid),
        api.systems.get_installed_products(sid),
    )

    installed_products = []
    for product in products:
        installed_products.append({
            "name": product.get("name"),
            "friendly_name": product.get("friendlyName"),
            "is_base_product": product.get("isBaseProduct"),
            "version": product.get("version"),
            "release": product.get("release"),
            "arch": product.get("arch"),
        })

    system = reference(details)
    cpu_fields = (
        "family", "mhz", "model", "vendor", "arch", "count",
        "socket_count", "core_count", "thread_count",
    )
    return {
        **system,
        "hostname": details.get("hostname") or network.get("hostname"),
        "description": details.get("description"),
        "last_boot": timestamp(details.get("last_boot")),
        "uuid": uuid or None,
        "cpu": {field: cpu.get(field) for field in cpu_fields},
        "network": {
            "hostname": network.get("hostname"),
            "ip": network.get("ip"),
            "ip6": network.get("ip6"),
        },
        "installed_products": installed_products,
    }
