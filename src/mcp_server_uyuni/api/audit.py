"""Raw Uyuni CVE audit reads."""


class AuditApi:
    def __init__(self, session):
        self.session = session

    async def list_systems_by_patch_status(self, cve_identifier: str,
                                           patch_statuses: list[str] | None = None):
        """Pass native status labels to the audit overload when supplied."""
        path = "/rhn/manager/api/audit/listSystemsByPatchStatus"
        params = {"cveIdentifier": cve_identifier}
        if patch_statuses is not None:
            params["patchStatusLabels"] = patch_statuses
        return await self.session.get(path, "reading audit.listSystemsByPatchStatus",
                                      params=params)
