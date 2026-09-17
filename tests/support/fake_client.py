"""Test-only stand-in for `CxApiClient`, backed by a JSON data file.

Used by `tests/test_routes.py` to drive the real ASGI app end-to-end without a
live tenant. The writes here are no-ops that return plausible ids; the scan
"runs" through a few polls and completes. The baseline severity counts are
real, taken from the WebGoatNet scan named in the data file; the after-numbers
are invented.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

from config import Settings, settings as default_settings
from cx.errors import CxApiError

DATA_FILE = pathlib.Path(__file__).resolve().parent / "webgoatnet.json"

#: How many polls the fake scan spends Running before completing, so the live
#: status panel can be exercised.
FAKE_SCAN_POLLS = 3


def _severity_counters(totals: dict[str, int]) -> list[dict]:
    return [
        {"severity": severity, "counter": count}
        for severity, count in totals.items()
        if count or severity in totals
    ]


class FakeClient:
    """Drop-in stand-in for CxApiClient. Read-only against a JSON data file."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or default_settings
        self.data: dict[str, Any] = json.loads(DATA_FILE.read_text())
        self._poll_counts: dict[str, int] = {}
        # Seeded from the data file so a base project answers with a real SAST
        # configuration. Without it every parity check under test would
        # compare two empty documents and report a perfect match.
        self._configs: dict[str, list[dict]] = {
            pid: list(params)
            for pid, params in (self.data.get("configs") or {}).items()
        }
        self._canceled: set[str] = set()
        self._disconnected: set[str] = set()
        # repoId per connected project, and the repo's own settings. Populated
        # by a conversion, exactly as the platform populates them.
        self._repo_ids: dict[str, int] = {}
        self._repo_settings: dict[str, dict] = {}
        self._rescans: list[str] = []
        self._conversions: dict[str, int] = {}
        self._converted: dict[str, dict] = {}

    # -- reads ----------------------------------------------------------------

    def get_projects(self) -> list[dict]:
        return list(self.data["projects"])

    def get_project(self, project_id: str) -> dict:
        for project in self.data["projects"]:
            if project["id"] == project_id:
                record = dict(project)
                repo_id = self._repo_ids.get(project_id)
                if repo_id:
                    record["repoId"] = repo_id
                if project_id in self._disconnected:
                    # A disconnected project is manual: it keeps its name and
                    # its history, but the repository record goes with the
                    # connection. Dropping only `origin` would leave it looking
                    # connected to the manual/SCM classifier.
                    record["origin"] = None
                    record.pop("repoId", None)
                    record.pop("scmRepoId", None)
                return record
        raise KeyError(f"No fixture project {project_id}")

    def get_last_sast_scan(self, project_id: str, branch: str | None = None) -> dict | None:
        scan = self.data["baseline_scan"]
        if scan["projectId"] == project_id:
            if branch and branch != scan["branch"]:
                return None
            return dict(scan)
        # Every other demo project resolves to its declared portfolio baseline.
        # Without this the detail page and the run flow worked for exactly one
        # project, and the stale-baseline and parity paths could not be seen at
        # all without a tenant.
        return self.get_last_sast_scans([project_id], branch=branch).get(project_id)

    def get_scan(self, scan_id: str) -> dict:
        if scan_id == self.data["baseline_scan"]["id"]:
            return dict(self.data["baseline_scan"])
        handler = self._scan_handler(scan_id)
        if handler:
            # A scan whose source Checkmarx cloned. The re-onboarding preview
            # reads this to tell a project driven by source control apart from
            # one that only ever had archives uploaded to it.
            return {"id": scan_id, "status": "Completed",
                    "metadata": {"Handler": handler}}
        if scan_id in self._canceled:
            return {"id": scan_id, "status": "Canceled"}
        seen = self._poll_counts.get(scan_id, 0)
        self._poll_counts[scan_id] = seen + 1
        if seen == 0:
            return {"id": scan_id, "status": "Queued", "positionInQueue": 1}
        if seen < FAKE_SCAN_POLLS:
            return {"id": scan_id, "status": "Running"}
        return {"id": scan_id, "status": "Completed"}

    def get_recent_scans(self, project_id: str, limit: int = 20) -> list[dict]:
        """Recent scan rows, carrying the `sourceType` the classifier reads.

        A project the fixture says nothing about has only ever had archives
        uploaded to it, which is what `zip` means.
        """
        types = (self.data.get("scan_source_types") or {}).get(project_id) or ["zip"]
        return [
            {"id": f"{project_id}-scan-{index}", "projectId": project_id,
             "sourceType": source_type}
            for index, source_type in enumerate(types[:limit])
        ]

    def get_scan_summary(self, scan_id: str) -> dict:
        portfolio = self.get_scan_summaries([scan_id]).get(scan_id)
        if portfolio:
            return portfolio
        is_baseline = scan_id == self.data["baseline_scan"]["id"]
        totals: dict[str, int] = {}
        for category in self.data["categories"]:
            count = category["before"] - (0 if is_baseline else category["removed"])
            totals[category["severity"]] = totals.get(category["severity"], 0) + count
        counters: dict[str, Any] = {"severityCounters": _severity_counters(totals)}
        if is_baseline:
            counters["statusCounters"] = list(self.data["baseline_status_counters"])
        else:
            # A first scan on a fresh project: everything is NEW, which is why
            # the whole backlog is eligible here and only new findings would be
            # on an established project.
            counters["statusCounters"] = [
                {"status": "NEW", "counter": sum(totals.values())}
            ]
        return {"scanId": scan_id, "sastCounters": counters}

    def compare_results(
        self,
        base_scan_id: str,
        scan_id: str,
        *,
        status: str | None = None,
        severity: str | None = None,
    ) -> list[dict]:
        """One row per finding across both scans, as the compare API returns it.

        No row is ever NEW and no CRITICAL is ever FIXED - that is what a clean
        comparison looks like, and it is deliberately the shape the live tenant
        did not produce. See README for what a real re-onboarding did instead.
        """
        rows: list[dict] = []
        similarity = 100000
        for category in self.data["categories"]:
            for index in range(category["before"]):
                similarity += 1
                rows.append(
                    {
                        "ID": f"fixture-{similarity}",
                        "similarityID": similarity,
                        "severity": category["severity"],
                        "status": "FIXED" if index < category["removed"] else "RECURRENT",
                        "state": "TO_VERIFY",
                        "queryName": category["queryName"],
                        "cweID": category["cwe"],
                        "languageName": "CSharp",
                    }
                )
        if status:
            rows = [row for row in rows if row["status"] == status]
        if severity:
            rows = [row for row in rows if row["severity"] == severity]
        return rows

    def compare_summary(self, base_scan_id: str, scan_id: str) -> dict:
        by_severity: dict[str, dict[str, int]] = {}
        for row in self.compare_results(base_scan_id, scan_id):
            bucket = by_severity.setdefault(row["severity"], {})
            bucket[row["status"]] = bucket.get(row["status"], 0) + 1

        return {
            "severityStatusCounters": [
                {
                    "severity": severity,
                    "results": [
                        {"status": status, "count": count}
                        for status, count in statuses.items()
                    ],
                }
                for severity, statuses in by_severity.items()
            ],
            "baseScanCounters": {
                severity: sum(statuses.values())
                for severity, statuses in by_severity.items()
            },
            "scanCounters": {
                severity: statuses.get("RECURRENT", 0) + statuses.get("NEW", 0)
                for severity, statuses in by_severity.items()
            },
        }

    # -- portfolio ------------------------------------------------------------

    def _portfolio(self, project_id: str) -> dict:
        return (self.data.get("portfolio") or {}).get(project_id, {})

    @staticmethod
    def _portfolio_scan_id(project_id: str) -> str:
        return f"{project_id}-baseline"

    def _scan_handler(self, scan_id: str) -> dict | None:
        """The `metadata.Handler` a fixture project's baseline scan records."""
        handlers = self.data.get("scan_handlers") or {}
        for project_id, handler in handlers.items():
            if scan_id == self._portfolio_scan_id(project_id):
                return handler
        return None

    def get_last_sast_scans(
        self, project_ids: list[str], branch: str | None = None
    ) -> dict[str, dict]:
        """Only projects whose fixture declares severities have a baseline.

        Mirrors the live endpoint, which omits a project entirely rather than
        returning an empty scan - that absence is what the "no completed SAST
        scan" row is built from.
        """
        resolved: dict[str, dict] = {}
        for project in self.data["projects"]:
            pid = project["id"]
            if pid not in project_ids:
                continue
            if self._portfolio(pid).get("severities") is None:
                continue
            main = project.get("mainBranch") or "master"
            if branch and branch != main:
                continue
            facts = self._portfolio(pid)
            resolved[pid] = {
                "id": self._portfolio_scan_id(pid),
                "projectId": pid,
                "branch": main,
                "status": "Completed",
                "createdAt": facts.get("baseline_created_at"),
                "engines": list(facts.get("engines") or ["sast"]),
                "sourceType": self._source_type(project),
            }
        return resolved

    def get_scan_summaries(self, scan_ids: list[str]) -> dict[str, dict]:
        summaries: dict[str, dict] = {}
        for project in self.data["projects"]:
            scan_id = self._portfolio_scan_id(project["id"])
            if scan_id not in scan_ids:
                continue
            severities = self._portfolio(project["id"]).get("severities")
            if severities is None:
                continue
            summaries[scan_id] = {
                "scanId": scan_id,
                "sastCounters": {"severityCounters": _severity_counters(severities)},
            }
        return summaries

    def iter_all_scans(self):
        """Synthesise the declared scan history, one row per scan.

        Emitted as individual rows rather than as counts so the test exercises
        the same grouping code the live path uses.
        """
        for project in self.data["projects"]:
            pid = project["id"]
            facts = self._portfolio(pid)
            branches = max(1, int(facts.get("branches", 0) or 0))
            total = int(facts.get("scans", 0) or 0)
            main = project.get("mainBranch") or "master"
            for index in range(total):
                # Spread scans across the declared branches, main first.
                position = index % branches
                yield {
                    "id": f"{pid}-scan-{index}",
                    "projectId": pid,
                    "branch": main if position == 0 else f"feature/branch-{position}",
                }

    @staticmethod
    def _source_type(project: dict) -> str:
        """Which SCM a fixture project's repo URL sits on."""
        url = (project.get("repoUrl") or "").lower()
        for fragment, scm_type in (
            ("gitlab.", "gitlab"), ("github.", "github"),
            ("bitbucket.", "bitbucket"), ("dev.azure.com", "azure"),
        ):
            if fragment in url:
                return scm_type
        return ""

    def _project_by_id(self, project_id: str) -> dict:
        for project in self.data["projects"]:
            if project["id"] == project_id:
                return project
        return {}

    # -- code repository integration ------------------------------------------

    def list_scms(self) -> list[dict]:
        return [dict(scm) for scm in self.data.get("scms") or []]

    def list_scm_projects(self, scm_id) -> list[str]:
        names = list((self.data.get("scm_projects") or {}).get(str(scm_id), []))
        # A disconnected project stops being connected, exactly as in a tenant.
        return [
            name for name in names
            if name not in {
                self._project_by_id(pid).get("name") for pid in self._disconnected
            }
        ]

    def get_protected_branches(self, project_name: str) -> list[dict]:
        return [
            dict(row)
            for row in (self.data.get("protected_branches") or {}).get(project_name, [])
        ]

    def get_conversion_status(self, process_id: str) -> dict:
        """IN_PROGRESS once, then OK - so the poller is exercised, not skipped."""
        seen = self._conversions.get(process_id, 0)
        self._conversions[process_id] = seen + 1
        converted = self._converted.get(process_id, {})
        if seen == 0:
            return {
                "migrationStatus": "IN_PROGRESS",
                "summary": "Converting projects",
                "totalProjects": 1,
                "migratedProjects": 0,
                "successfulProjectsList": [],
                "failedProjectList": [],
            }
        return {
            "migrationStatus": "OK",
            "summary": "Finished converting projects",
            "totalProjects": 1,
            "migratedProjects": 1,
            "successfulProjectsList": [converted.get("repo") or "converted"],
            "failedProjectList": [],
        }

    def get_project_config(self, project_id: str) -> list[dict]:
        return list(self._configs.get(project_id, []))

    def licensed_engines(self) -> tuple[str, ...]:
        return tuple(self.data.get("license_engines") or ())

    def get_repo_settings(self, repo_id) -> dict:
        """Settings in the platform's shape: value plus editability per field."""
        stored = self._repo_settings.get(str(repo_id))
        if stored is None:
            raise CxApiError(f"SCM repo with ID: {repo_id} was not found", status_code=404)
        return {key: dict(value) for key, value in stored.items()}

    def has_source(self, scan_id: str) -> bool:
        return True

    # -- writes (no-ops) ------------------------------------------------------

    def download_code(self, scan_id: str, dest) -> int:
        payload = b"PK\x05\x06" + b"\x00" * 18  # empty-zip end-of-central-directory
        dest.write(payload)
        return len(payload)

    def create_project(self, name: str, **kwargs) -> dict:
        project_id = f"fixture-{name}"
        # A new project carries no project-level overrides, so
        # `/api/configuration/project` answers with the tenant's own defaults.
        # Seeding the copy from those - not from the base project - is what lets
        # the test show a real parity mismatch: a base that overrides a setting
        # genuinely does not pass that override on to a fresh copy.
        defaults = self.data.get("tenant_config") or []
        self._configs[project_id] = [dict(row) for row in defaults]
        # Joins the tenant, as a created project does. Without this it existed
        # only as an id the run remembered, and reading it back - which the
        # re-onboarding preview does, to see what it is currently called - found
        # nothing.
        self.data["projects"].append({
            "id": project_id,
            "name": name,
            "repoUrl": kwargs.get("repo_url") or "",
            "mainBranch": kwargs.get("main_branch") or "",
            "origin": kwargs.get("origin") or "findings-analysis-dashboard",
        })
        return {"id": project_id, "name": name}

    def set_project_config(self, project_id: str, params: list[dict]) -> None:
        """Merge by key, as the live PATCH does.

        Replacing the list wholesale would drop every other SAST setting on the
        project, and the parity check reading the document back would then see
        six keys vanish and report six mismatches that the tenant never had.
        """
        current = {row["key"]: row for row in self._configs.get(project_id, [])}
        for param in params:
            key = param.get("key")
            if not key:
                continue
            current[key] = {**current.get(key, {}), **param}
        self._configs[project_id] = list(current.values())

    def create_upload_url(self) -> str:
        return "https://fixture.invalid/upload/presigned"

    def put_upload(self, url: str, data: bytes) -> None:
        return None

    def create_scan(self, payload: dict) -> dict:
        return {"id": "fixture-fa-scan", "status": "Queued"}

    def cancel_scan(self, scan_id: str) -> None:
        self._canceled.add(scan_id)

    def rename_project(self, project_id: str, name: str) -> None:
        """Rename in place. The project keeps its id and everything else."""
        for project in self.data["projects"]:
            if project["id"] == project_id:
                project["name"] = name
                return
        # A project this tool created during the run, not one from the fixture.
        self.data["projects"].append({"id": project_id, "name": name})

    def disconnect_project(self, project_id: str) -> None:
        """Records the disconnect. Never removes the project - nor does the API."""
        self._disconnected.add(project_id)

    def convert_project(self, payload: dict) -> dict:
        process_id = f"fixture-conversion-{len(self._conversions) + 1}"
        first = (payload.get("projects") or [{}])[0]
        self._converted[process_id] = {
            "repo": first.get("scmRepositoryUrl"),
            "cxProjectId": first.get("cxProjectId"),
        }
        self._conversions[process_id] = 0
        # A converted project gains a repoId and a repo settings document, which
        # is what the post-conversion rescan reads.
        project_id = first.get("cxProjectId")
        if project_id:
            repo_id = 70000 + len(self._repo_ids)
            self._repo_ids[project_id] = repo_id
            self._repo_settings[str(repo_id)] = {
                key: dict(value)
                for key, value in (self.data.get("repo_settings") or {}).items()
            }
        return {"processId": process_id, "message": "Started to convert projects."}

    def update_repo_settings(self, repo_id, project_id: str, payload: dict) -> dict:
        """Merge, and refuse a field the repo declares non-editable.

        The live API applies "license/FF + cascade enforcement" and reports what
        it refused, so a fake that accepted everything would make the skip path
        untestable without a tenant.
        """
        stored = self._repo_settings.get(str(repo_id))
        if stored is None:
            raise CxApiError(f"SCM repo with ID: {repo_id} was not found", status_code=404)
        for key, value in (payload or {}).items():
            field = stored.get(key)
            if field and field.get("isEditable"):
                field["value"] = bool(value)
        return {key: dict(value) for key, value in stored.items()}

    def rescan_project(self, project_id: str) -> dict:
        self._rescans.append(project_id)
        return {"id": f"fixture-rescan-{len(self._rescans)}"}

    def close(self) -> None:
        return None
