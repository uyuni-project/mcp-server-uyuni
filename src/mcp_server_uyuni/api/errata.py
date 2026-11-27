"""Raw Uyuni errata reads."""


class ErrataApi:
    """Raw errata operations through the shared authenticated session."""

    def __init__(self, session):
        self.session = session

    async def find_by_cve(self, cve_identifier: str) -> list[dict]:
        """Find visible advisories associated with a CVE."""
        path = "/rhn/manager/api/errata/findByCve"
        return await self.session.get(path, "reading errata.findByCve",
                                      params={"cveName": cve_identifier})

    async def list_affected_systems(self, advisory_name: str) -> list[dict]:
        """Find systems with a needed instance of an advisory."""
        path = "/rhn/manager/api/errata/listAffectedSystems"
        return await self.session.get(path, "reading errata.listAffectedSystems",
                                      params={"advisoryName": advisory_name})

    async def list_cves(self, advisory_name: str) -> list[str]:
        path = "/rhn/manager/api/errata/listCves"
        return await self.session.get(path, "reading errata.listCves",
                                      params={"advisoryName": advisory_name}, item_type=str)
