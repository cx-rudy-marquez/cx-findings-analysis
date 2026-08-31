"""Checkmarx One REST client for the Findings Analysis impact dashboard.

Reads are ported from the sibling cx-analytics-and-risk-orchestration project,
whose live-verified quirks are preserved verbatim because each one cost real
debugging to find:

* Pagination is not uniform across this API and cannot be abstracted into one
  helper. `/api/projects` and `/api/scans` take conventional row offsets;
  `/api/sast-results/compare` also takes a row offset but returns only 20 rows
  unless `limit` is passed; and `/api/results` treats `offset` as a **page
  index**, where `limit=1000&offset=1000` skips a million rows and returns
  nothing. Each walk is written out where it is used.
* A Checkmarx API key is an OAuth refresh token - see `cx/auth.py`.

The writes are new, and are the reason this project exists. They are kept in
their own block below the reads: every one of them creates or consumes tenant
resources, and none of them may ever fire from a page load.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Iterator

import httpx

from analysis.licensing import allowed_engines
from config import Settings, settings as default_settings
from cx.auth import CxAuthClient
from cx.errors import CxApiError

log = logging.getLogger(__name__)

MAX_RETRIES = 3
BACKOFF_BASE_SECONDS = 0.5
RESULTS_PAGE_SIZE = 5000
LIST_PAGE_SIZE = 100
#: Scan ids per `/api/scan-summary` call. They travel in the query string, so a
#: whole tenant's worth at once would build an unreasonably long URL.
SUMMARY_BATCH_SIZE = 20
#: `scms/{id}/projects` caps `limit` at 100.
SCM_PROJECTS_PAGE_SIZE = 100
REQUEST_TIMEOUT = 180.0
#: Source archives are large; downloads and uploads get their own longer budget.
TRANSFER_TIMEOUT = 900.0

#: The Configuration and Scans services reject a bare `application/json` body.
VERSIONED_JSON = "application/json; version=1.0"

#: The Code Repository Management and Project Conversion services require the
#: API version on the *Accept* header, not just the body content type, and
#: answer 406 without it.
VERSIONED_ACCEPT = "*/*; version=1.0"

TERMINAL_SCAN_STATUSES = frozenset({"Completed", "Failed", "Partial", "Canceled"})


class CxApiClient:
    def __init__(
        self,
        auth: CxAuthClient | None = None,
        settings: Settings | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.settings = settings or default_settings
        self.auth = auth or CxAuthClient(self.settings)
        self._client = client or httpx.Client(timeout=REQUEST_TIMEOUT)
        self._owns_client = client is None

    # -- transport ------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        content_type: str | None = None,
        accept: str | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        """One HTTP call with retry, backoff, and a single 401 token refresh.

        Retries cover transport errors and 5xx only. A 4xx is a contract
        problem: retrying it just makes the same mistake more times.
        """
        url = f"{self.settings.base_url}{path}"
        attempt = 0
        refreshed = False
        while True:
            headers = dict(self.auth.auth_header())
            if content_type:
                headers["Content-Type"] = content_type
            if accept:
                headers["Accept"] = accept
            started = time.monotonic()
            try:
                response = self._client.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=headers,
                    timeout=timeout or REQUEST_TIMEOUT,
                )
                log.debug(
                    "%s %s params=%s -> %s in %.0fms",
                    method,
                    path,
                    _loggable(params),
                    response.status_code,
                    (time.monotonic() - started) * 1000,
                )
            except httpx.HTTPError as exc:
                attempt += 1
                if attempt >= MAX_RETRIES:
                    raise CxApiError(f"{method} {path} failed: {exc}") from None
                _sleep_backoff(attempt)
                continue

            if response.status_code == 401 and not refreshed:
                # Token may have been revoked or rotated mid-run; one retry only.
                refreshed = True
                self.auth.get_token(force_refresh=True)
                continue

            if response.status_code >= 500:
                attempt += 1
                if attempt >= MAX_RETRIES:
                    raise CxApiError(
                        f"{method} {path} failed after {MAX_RETRIES} attempts: "
                        f"{response.status_code} {response.text[:200]}",
                        status_code=response.status_code,
                    )
                _sleep_backoff(attempt)
                continue

            return response

    def _json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        content_type: str | None = None,
        accept: str | None = None,
    ) -> Any:
        response = self._request(
            method,
            path,
            params=params,
            json_body=json_body,
            content_type=content_type,
            accept=accept,
        )
        if response.status_code >= 400:
            raise CxApiError(
                f"{method} {path} returned {response.status_code}: {response.text[:300]}",
                status_code=response.status_code,
            )
        if response.status_code == 204 or not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise CxApiError(f"{method} {path} returned non-JSON: {exc}") from None

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict:
        return self._json("GET", path, params=params)

    # -- reads ----------------------------------------------------------------

    def get_projects(self) -> list[dict]:
        return list(self._paginate_rows("/api/projects", "projects"))

    def get_project(self, project_id: str) -> dict:
        return self.get(f"/api/projects/{project_id}")

    def get_scan(self, scan_id: str) -> dict:
        return self.get(f"/api/scans/{scan_id}")

    def get_completed_scans(
        self, project_id: str | None = None, branch: str | None = None
    ) -> list[dict]:
        params: dict[str, Any] = {"statuses": "Completed", "sort": "-created_at"}
        if project_id:
            params["project-id"] = project_id
        if branch:
            params["branch"] = branch
        return list(self._paginate_rows("/api/scans", "scans", params))

    def get_last_sast_scan(
        self, project_id: str, branch: str | None = None
    ) -> dict | None:
        """The project's most recent scan that actually ran the SAST engine.

        The `engine` filter is the whole point. A project's newest scan labelled
        "Full Scan" in the UI may have run SCA only, in which case it carries no
        SAST results and is the wrong baseline - picking by recency or by label
        silently compares against nothing. `engine=sast` makes the API answer
        the question we are actually asking.
        """
        params: dict[str, Any] = {
            "project-ids": project_id,
            "engine": "sast",
            "scan-status": "Completed",
            "limit": 1,
            "offset": 0,
        }
        if branch:
            params["branch"] = branch
        payload = self.get("/api/projects/last-scan", params)
        # Response is a map of project-id -> scan, not a list.
        scan = payload.get(project_id) if isinstance(payload, dict) else None
        return scan or None

    def get_last_sast_scans(
        self, project_ids: list[str], branch: str | None = None
    ) -> dict[str, dict]:
        """Batched `get_last_sast_scan`: one call for a whole tenant.

        `project-ids` is an array parameter, so the portfolio view resolves 46
        baselines in a single request rather than 46. Only projects with a
        matching scan appear in the response, so a missing key means "no
        completed SAST scan on this branch", not an error.
        """
        if not project_ids:
            return {}
        params: dict[str, Any] = {
            "project-ids": ",".join(project_ids),
            "engine": "sast",
            "scan-status": "Completed",
            "limit": len(project_ids),
            "offset": 0,
        }
        if branch:
            params["branch"] = branch
        payload = self.get("/api/projects/last-scan", params)
        if not isinstance(payload, dict):
            return {}
        return {pid: scan for pid, scan in payload.items() if isinstance(scan, dict)}

    def get_scan_summaries(self, scan_ids: list[str]) -> dict[str, dict]:
        """Batched `get_scan_summary`, keyed by scan id.

        Chunked: `scan-ids` goes in the query string, and a few hundred UUIDs
        would build a URL long enough for an intermediary to reject.
        """
        summaries: dict[str, dict] = {}
        for start in range(0, len(scan_ids), SUMMARY_BATCH_SIZE):
            chunk = scan_ids[start : start + SUMMARY_BATCH_SIZE]
            payload = self.get(
                "/api/scan-summary",
                {
                    "scan-ids": ",".join(chunk),
                    "include-severity-status": "true",
                    "include-status-counters": "true",
                    "apply-predicates": "true",
                },
            )
            for summary in payload.get("scansSummaries") or []:
                scan_id = summary.get("scanId")
                if scan_id:
                    summaries[scan_id] = summary
        return summaries

    def iter_all_scans(self) -> Iterator[dict]:
        """Every scan in the tenant, unfiltered.

        Deliberately unfiltered: the portfolio's scan and branch counts must
        cover every branch and every engine, because that is what re-onboarding
        would discard. Each row carries `projectId` and `branch`, so one walk
        yields both counts for every project - cheaper and more accurate than
        `/api/projects/branches` per project, whose default `limit` of 20 would
        silently undercount a project with more branches than that.
        """
        return self._paginate_rows("/api/scans", "scans")

    def get_recent_scans(self, project_id: str, limit: int = 20) -> list[dict]:
        """The project's newest scans, one page, every status and engine.

        Deliberately unfiltered and bounded: the re-onboarding preview reads
        these only for their `sourceType`, to find out whether Checkmarx has
        ever cloned this project's source. A completed-only filter would miss a
        failed clone, which says just as much, and paginating the whole history
        would cost a great deal to learn something the first page already says.
        """
        payload = self.get(
            "/api/scans",
            {"project-id": project_id, "limit": limit, "sort": "-created_at"},
        )
        return payload.get("scans") or []

    def get_branches(self, project_id: str) -> list[str]:
        payload = self.get(
            "/api/projects/branches", {"project-id": project_id, "limit": LIST_PAGE_SIZE}
        )
        if isinstance(payload, list):
            return [b for b in payload if isinstance(b, str)]
        return list(payload.get("branches") or [])

    def get_scan_summary(self, scan_id: str) -> dict:
        """Per-engine counters for one scan.

        This is what makes a SAST-only "before" number trustworthy: the response
        separates `sastCounters` from `scaCounters`, so there is no need to
        subtract one engine's findings from a combined total by hand and hope
        the arithmetic holds. Findings Analysis only ever touches SAST.
        """
        payload = self.get(
            "/api/scan-summary",
            {
                "scan-ids": scan_id,
                "include-severity-status": "true",
                "include-status-counters": "true",
                "apply-predicates": "true",
            },
        )
        summaries = payload.get("scansSummaries") or []
        return summaries[0] if summaries else {}

    def compare_summary(self, base_scan_id: str, scan_id: str) -> dict:
        """Severity x status counts for a pair of scans, in one call.

        Note the path. The Compare spec's `servers.url` is
        `/api/scans-compare/sast` and the operation lives at `/status`, so the
        base alone 404s - the same trap as Repostore.

        This is the authoritative "before" as well as the "after": the response
        carries `baseScanCounters` and `scanCounters` measured the same way. The
        older route of reading each scan's `/api/scan-summary` separately does
        not agree with it - `severityCounters` there exclude FIXED results,
        which understated WebGoatNet's baseline Critical count as 63 against
        this endpoint's 68.

        `evaluation-status=true` is deliberately not sent. It promises to
        reclassify FIXED as NOT_EVALUATED when a configuration change
        invalidates the comparison, which is exactly what we would want, but it
        answers 500 (`code 5001`) on this tenant.
        """
        return self.get(
            "/api/scans-compare/sast/status",
            {"base-scan-id": base_scan_id, "scan-id": scan_id},
        )

    def compare_results(
        self,
        base_scan_id: str,
        scan_id: str,
        *,
        status: str | None = None,
        severity: str | None = None,
    ) -> list[dict]:
        """Every finding across both scans, each labelled NEW / RECURRENT / FIXED.

        Two traps, both verified against the live tenant:

        * `offset` here is a **row** offset. On `/api/results` the same
          parameter is a *page index* - walking this one that way would advance
          three rows at a time while believing it had advanced three pages.
        * `limit` must be passed. Omitted, the endpoint returns its default of
          20 rows alongside an honest `totalCount` - a truncated answer shaped
          exactly like a complete one.
        """
        rows: list[dict] = []
        params: dict[str, Any] = {
            "base-scan-id": base_scan_id,
            "scan-id": scan_id,
            "limit": RESULTS_PAGE_SIZE,
        }
        if status:
            params["status"] = status
        if severity:
            params["severity"] = severity

        while True:
            payload = self.get(
                "/api/sast-results/compare", {**params, "offset": len(rows)}
            )
            batch = payload.get("results") or []
            rows.extend(batch)
            total = payload.get("totalCount")
            if not batch or (total is not None and len(rows) >= total):
                break
        return rows

    def get_project_config(self, project_id: str) -> list[dict]:
        payload = self._request(
            "GET", "/api/configuration/project", params={"project-id": project_id}
        )
        if payload.status_code >= 400:
            raise CxApiError(
                f"GET /api/configuration/project returned {payload.status_code}: "
                f"{payload.text[:300]}",
                status_code=payload.status_code,
            )
        body = payload.json()
        return body if isinstance(body, list) else list(body.get("parameters") or [])

    # -- reads: code repository integration -----------------------------------
    # Everything here is read-only. It exists so the re-onboarding preview can
    # be built entirely from the tenant's own state before anything is written.

    def list_scms(self) -> list[dict]:
        """The SCM integrations configured on this tenant.

        Each row carries `id`, `type` (github/gitlab/azure/bitbucket/githubApp)
        and `repoBaseUrl`. The `id` is what `scms/{id}/projects` needs, and the
        `type` is the vocabulary the conversion API's `scmType` expects.
        """
        payload = self._json(
            "GET", "/api/repos-manager/v2/scms", accept=VERSIONED_ACCEPT
        )
        return payload if isinstance(payload, list) else list(payload.get("scms") or [])

    def list_scm_projects(self, scm_id: Any) -> list[str]:
        """Names of the Checkmarx projects connected through one integration.

        Names, not ids - that is all the endpoint returns. Used for two things:
        confirming a project really is SCM-connected, and counting how many
        others are, which decides whether a disconnect would strip the
        credential the conversion depends on.
        """
        names: list[str] = []
        offset = 0
        while True:
            payload = self._json(
                "GET",
                f"/api/repos-manager/scms/{scm_id}/projects",
                params={"limit": SCM_PROJECTS_PAGE_SIZE, "offset": offset},
                accept=VERSIONED_ACCEPT,
            )
            batch = (payload or {}).get("projects") or []
            names.extend(batch)
            # `hasMore` is documented "NOT FULLY SUPPORTED", so a full page is
            # treated as more to come even when the flag says otherwise. An
            # empty page always ends the walk, so neither signal can loop.
            if not batch:
                return names
            if not payload.get("hasMore") and len(batch) < SCM_PROJECTS_PAGE_SIZE:
                return names
            offset += SCM_PROJECTS_PAGE_SIZE

    def get_protected_branches(self, project_name: str) -> list[dict]:
        """The protected-branch patterns on an SCM-connected project.

        Keyed by project *name*, not id - the endpoint takes `cxProjectName`.
        """
        payload = self._json(
            "GET",
            "/api/repos-manager/protected-branches",
            params={"cxProjectName": project_name},
            accept=VERSIONED_ACCEPT,
        )
        return payload if isinstance(payload, list) else []

    def get_repo_settings(self, repo_id: int | str) -> dict:
        """A connected repository's scan settings, keyed by the project's `repoId`.

        `repoId` comes straight off `GET /api/projects/{id}` once a project is
        connected - there is no lookup to do. That matters: every repos-manager
        endpoint that reaches the provider to list organisations or repositories
        returned `500 ReposManager generic exception` on the reference tenant,
        the same unreliability already documented for `scms/{id}/projects`.

        Each setting arrives as `{"value": bool, "isEditable": bool}`, not as a
        bare boolean. `analysis/licensing.py` reads that shape.
        """
        return self._json(
            "GET",
            f"/api/repos-manager/repo/{repo_id}",
            accept=VERSIONED_ACCEPT,
        )

    def licensed_engines(self) -> tuple[str, ...]:
        """Engines this tenant is entitled to, from the token it already holds."""
        return allowed_engines(self.auth.token_claims())

    def get_conversion_status(self, process_id: str) -> dict:
        """Progress of a conversion process.

        Note the path: the status lives on the same `/project-conversion`
        resource as the POST, via GET with a `processId` query parameter. The
        `message` in the POST response advertises a `/conversion/status` URL on
        an internal host, which does not exist on the public API.
        """
        return self._json(
            "GET",
            "/api/repos-manager/project-conversion",
            params={"processId": process_id},
            accept=VERSIONED_ACCEPT,
        )

    def has_source(self, scan_id: str) -> bool:
        """Whether Checkmarx still retains the scanned source for this scan.

        Cheaper and far clearer than discovering the same thing as a failed
        download halfway through a run: a 404 here means the tenant's retention
        window has already passed and no comparison is possible.
        """
        response = self._request("HEAD", f"/api/repostore/scans/{scan_id}")
        if response.status_code == 404:
            return False
        if response.status_code >= 400:
            raise CxApiError(
                f"HEAD /api/repostore/scans/{scan_id} returned {response.status_code}",
                status_code=response.status_code,
            )
        return True

    # -- writes ---------------------------------------------------------------
    # Everything below creates or consumes tenant resources. Each is called
    # exactly once, from cx/flow.py, behind an explicit user confirmation.

    def download_code(self, scan_id: str, dest) -> int:
        """Stream a scan's source archive to `dest`, returning bytes written.

        Note the path: the Repostore service's OpenAPI `servers.url` is
        `/api/repostore`, so the endpoint is `/api/repostore/code/{scan-id}`.
        The bare `/api/code/{scan-id}` seen in the Swagger UI's path list omits
        that base and 404s.

        The endpoint answers 302, not 200: the body is a redirect to a
        presigned archive URL on the tenant's own storage gateway
        (`<base_url>/storage/...`). Redirects must be followed, and the bearer
        token must survive the hop - the gateway enforces tenant auth itself
        and answers a bare presigned GET with 401. Same-host redirect, so httpx
        keeps the header rather than stripping it as it would cross-origin.
        """
        url = f"{self.settings.base_url}/api/repostore/code/{scan_id}"
        written = 0
        with self._client.stream(
            "GET",
            url,
            headers=self.auth.auth_header(),
            timeout=TRANSFER_TIMEOUT,
            follow_redirects=True,
        ) as response:
            if response.status_code >= 400:
                response.read()
                raise CxApiError(
                    f"GET /api/repostore/code/{scan_id} returned "
                    f"{response.status_code}: {response.text[:300]}",
                    status_code=response.status_code,
                )
            first = b""
            for chunk in response.iter_bytes():
                if not first:
                    first = chunk[:4]
                dest.write(chunk)
                written += len(chunk)

        # An unfollowed redirect or a proxy error page is a 2xx-shaped success
        # carrying a few hundred bytes of HTML. Uploading that would produce a
        # scan of nothing and a comparison that looks real, so check the magic
        # bytes rather than trusting the status code.
        if first[:2] != b"PK":
            raise CxApiError(
                f"Scan {scan_id} source download returned {written} bytes that "
                f"are not a zip archive (starts with {first!r})"
            )
        return written

    def create_project(
        self,
        name: str,
        *,
        repo_url: str | None = None,
        main_branch: str | None = None,
        origin: str = "findings-analysis-dashboard",
        tags: dict[str, str] | None = None,
        criticality: int = 3,
        groups: list[str] | None = None,
    ) -> dict:
        body: dict[str, Any] = {
            "name": name,
            "origin": origin,
            "criticality": criticality,
            "tags": tags or {},
            "groups": groups or [],
        }
        if repo_url:
            body["repoUrl"] = repo_url
        if main_branch:
            body["mainBranch"] = main_branch
        return self._json("POST", "/api/projects/", json_body=body,
                          content_type=VERSIONED_JSON)

    def rename_project(self, project_id: str, name: str) -> None:
        """Rename a project. Everything else about it is left alone.

        A PATCH with only `name` in the body: the project keeps its id, its scan
        history, its tags and its configuration. Used by the re-onboarding flow
        to free a name so the copy can take it.
        """
        response = self._request(
            "PATCH",
            f"/api/projects/{project_id}",
            json_body={"name": name},
            content_type=VERSIONED_JSON,
        )
        if response.status_code >= 400:
            raise CxApiError(
                f"PATCH /api/projects/{project_id} returned {response.status_code}: "
                f"{response.text[:300]}",
                status_code=response.status_code,
            )

    def set_project_config(self, project_id: str, params: list[dict]) -> None:
        """PATCH project-level scan configuration. Returns 204 on success.

        `setParameter` in the Configuration spec defines exactly three fields -
        key, value, allowOverride - so that is all this sends.
        """
        response = self._request(
            "PATCH",
            "/api/configuration/project",
            params={"project-id": project_id},
            json_body=params,
            content_type=VERSIONED_JSON,
        )
        if response.status_code >= 400:
            raise CxApiError(
                f"PATCH /api/configuration/project returned {response.status_code}: "
                f"{response.text[:300]}",
                status_code=response.status_code,
            )

    def create_upload_url(self) -> str:
        payload = self._json("POST", "/api/uploads/", content_type=VERSIONED_JSON)
        url = payload.get("url")
        if not url:
            raise CxApiError("POST /api/uploads/ returned no pre-signed URL")
        return url

    def put_upload(self, url: str, data: bytes) -> None:
        """PUT the archive to the pre-signed URL.

        Authenticated, despite the signature already in the URL. The URL points
        at the tenant's own storage gateway (`<base_url>/storage/...`), not at
        raw S3, and that gateway rejects an unauthenticated PUT with 401
        regardless of Content-Type. The token goes to the same host that issued
        it, so nothing leaves the tenant boundary.
        """
        if not url.startswith(self.settings.base_url):
            # Defensive: if a future tenant hands back a true third-party S3
            # URL, send the bytes without the bearer rather than posting the
            # tenant token to an unrelated host.
            headers = {"Content-Type": "application/zip"}
        else:
            headers = {**self.auth.auth_header(), "Content-Type": "application/zip"}
        try:
            response = self._client.put(
                url,
                content=data,
                headers=headers,
                timeout=TRANSFER_TIMEOUT,
            )
        except httpx.HTTPError as exc:
            raise CxApiError(f"Upload PUT failed: {exc}") from None
        if response.status_code >= 400:
            raise CxApiError(
                f"Upload PUT returned {response.status_code}: {response.text[:300]}",
                status_code=response.status_code,
            )

    def create_scan(self, payload: dict) -> dict:
        return self._json("POST", "/api/scans/", json_body=payload,
                          content_type=VERSIONED_JSON)

    def disconnect_project(self, project_id: str) -> None:
        """Detach a project from its SCM repository, making it manual.

        The project's scan history is preserved and its webhook is removed. It
        is **not** deleted, and nothing in this application ever deletes it.
        200 covers "already manual", so the call is idempotent.
        """
        response = self._request(
            "POST",
            f"/api/repos-manager/projects/{project_id}/disconnect",
            accept=VERSIONED_ACCEPT,
        )
        if response.status_code >= 400:
            raise CxApiError(
                f"POST /api/repos-manager/projects/{project_id}/disconnect returned "
                f"{response.status_code}: {response.text[:300]}",
                status_code=response.status_code,
            )

    def convert_project(self, payload: dict) -> dict:
        """Connect a manual project to an SCM repo. Returns `{processId, ...}`.

        The conversion runs asynchronously; the returned `processId` is polled
        through `get_conversion_status`.
        """
        return self._json(
            "POST",
            "/api/repos-manager/project-conversion",
            json_body=payload,
            content_type=VERSIONED_JSON,
            accept=VERSIONED_ACCEPT,
        )

    def update_repo_settings(
        self, repo_id: int | str, project_id: str, payload: dict
    ) -> dict:
        """Set scanner flags on a connected repository. Returns the read-back.

        The API documents this route as applying "license/FF + cascade
        enforcement only", so it is the final authority on what may be turned
        on - the response is what actually stuck, not an echo of the request,
        and is recorded as such.
        """
        return self._json(
            "PATCH",
            f"/api/repos-manager/repo/{repo_id}",
            params={"projectId": project_id},
            json_body=payload,
            content_type=VERSIONED_JSON,
            accept=VERSIONED_ACCEPT,
        )

    def rescan_project(self, project_id: str) -> dict:
        """Queue a fresh scan of a connected project's default branch.

        Note the snake_case body key. It is what the endpoint documents, and it
        is the one field in this flow that could not be confirmed by a read-only
        probe - a GET on this path falls through to `GET /api/scans/{id}`. The
        caller records the request and the response verbatim so a wrong shape
        shows up in the audit trail rather than as silence.
        """
        return self._json(
            "POST",
            "/api/scans/rescan",
            json_body={"project_id": project_id},
            content_type=VERSIONED_JSON,
        )

    def cancel_scan(self, scan_id: str) -> None:
        response = self._request(
            "PATCH",
            f"/api/scans/{scan_id}",
            json_body={"status": "Canceled"},
            content_type=VERSIONED_JSON,
        )
        if response.status_code >= 400:
            raise CxApiError(
                f"PATCH /api/scans/{scan_id} returned {response.status_code}: "
                f"{response.text[:300]}",
                status_code=response.status_code,
            )

    # -- helpers --------------------------------------------------------------

    def _paginate_rows(
        self, path: str, key: str, params: dict[str, Any] | None = None
    ) -> Iterator[dict]:
        """Conventional row-offset pagination (projects / scans)."""
        offset = 0
        seen = 0
        while True:
            payload = self.get(
                path, {**(params or {}), "limit": LIST_PAGE_SIZE, "offset": offset}
            )
            batch = payload.get(key) or []
            yield from batch
            seen += len(batch)
            total = payload.get("totalCount")
            if not batch or (total is not None and seen >= total):
                return
            offset += LIST_PAGE_SIZE

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
        self.auth.close()


def _sleep_backoff(attempt: int) -> None:
    time.sleep(BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))


def _loggable(params: dict[str, Any] | None) -> dict[str, Any]:
    """Params here are non-sensitive, but keep the log line short."""
    if not params:
        return {}
    return {k: v for k, v in params.items() if k != "include-nodes"}
