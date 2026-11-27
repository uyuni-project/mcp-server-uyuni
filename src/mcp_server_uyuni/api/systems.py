"""Raw, read-only Uyuni system operations."""

from typing import Any


class SystemsApi:
    def __init__(self, session):
        self.session = session

    async def _get(self, namespace: str, method: str, params: dict | None = None, kind: type = list) -> Any:
        path = f"/rhn/manager/api/{namespace}/{method}"
        return await self.session.get(path, f"reading {namespace}.{method}",
                                      params=params, response_type=kind)

    async def list_systems(self):
        return await self._get("system", "listSystems")

    async def list_out_of_date_systems(self):
        """List visible systems with outdated packages."""
        return await self._get("system", "listOutOfDateSystems")

    async def search(self, field: str, term: str):
        if field not in {"hostname", "ip", "uuid", "nameAndDescription"}:
            raise ValueError("Unsupported system search field")
        return await self._get("system/search", field, {"searchTerm": term})

    async def get_id(self, name: str):
        """Return systems whose profile name exactly matches ``name``."""
        return await self._get("system", "getId", {"name": name})

    async def list_group_systems(self, group_name: str):
        return await self._get("systemgroup", "listSystemsMinimal", {"systemGroupName": group_name})

    async def list_suggested_reboot(self):
        return await self._get("system", "listSuggestedReboot")

    async def get_details(self, sid: int):
        return await self._get("system", "getDetails", {"sid": sid}, dict)

    async def get_cpu(self, sid: int):
        return await self._get("system", "getCpu", {"sid": sid}, dict)

    async def get_network(self, sid: int):
        return await self._get("system", "getNetwork", {"sid": sid}, dict)

    async def get_uuid(self, sid: int):
        return await self._get("system", "getUuid", {"sid": sid}, str)

    async def get_installed_products(self, sid: int):
        return await self._get("system", "getInstalledProducts", {"sid": sid})

    async def get_event_history(self, sid: int, offset: int, limit: int, earliest_date: str | None = None):
        params = {"sid": sid, "offset": offset, "limit": limit}
        if earliest_date is not None:
            params["earliestDate"] = earliest_date
        return await self._get("system", "getEventHistory", params)

    async def get_event_details(self, sid: int, eid: int):
        return await self._get("system", "getEventDetails", {"sid": sid, "eid": eid}, dict)

    async def get_relevant_errata(self, sid: int):
        """Get relevant errata for one system."""
        return await self._get("system", "getRelevantErrata", {"sid": sid})

    async def get_relevant_errata_batch(self, sids: list[int]):
        """Get relevant errata for multiple systems."""
        return await self._get("system", "getRelevantErrata", {"sids": sids})

    async def get_unscheduled_errata(self, sid: int):
        """Get applicable errata without a queued action."""
        return await self._get("system", "getUnscheduledErrata", {"sid": sid})
