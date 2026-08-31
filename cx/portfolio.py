"""Building the portfolio snapshot: every project's counts and history.

Read-only against the tenant, but expensive enough (~15s on a 45-project tenant)
that it runs only when someone asks, and its output is cached in `store.py`.

The cost is concentrated in three places, and each is batched or fanned out as
far as the API allows:

* Severity counts - `last-scan` and `scan-summary` both take array parameters,
  so the whole tenant needs a handful of calls rather than two per project.
* Scan and branch history - one unfiltered walk of `/api/scans` yields both
  counts for every project at once, because each row carries `projectId` and
  `branch`.
* The Findings Analysis flag - `/api/configuration/project` takes exactly one
  project id (a comma-separated list returns 400, repeated parameters return one
  unattributable document), so this is genuinely one call per project and the
  only lever left is concurrency.

Baseline resolution deliberately mirrors `cx/flow.py:resolve_baseline`. If the
portfolio ranked projects by one baseline and the detail page then measured a
different one, the two pages would disagree about the same project.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from analysis.compare import severity_counts
from analysis.parity import findings_analysis_enabled
from analysis.portfolio import ProjectRow, is_converted_original
from config import PREFERRED_BRANCHES
from cx.errors import CxError
from cx.flow import fa_project_name

log = logging.getLogger(__name__)


def _branch_candidates(projects: list[dict]) -> list[str]:
    """Distinct branches worth a batched lookup, in preference order.

    Batched `last-scan` filters on one branch per call, so matching Phase 1's
    per-project preference means one call per distinct candidate. A project's
    own `mainBranch` comes first; `main` and `master` cover the common case
    where none is set.
    """
    seen: list[str] = []
    for project in projects:
        branch = (project.get("mainBranch") or "").strip()
        if branch and branch not in seen:
            seen.append(branch)
    for branch in PREFERRED_BRANCHES:
        if branch not in seen:
            seen.append(branch)
    return seen


def _resolve_baselines(client, projects: list[dict]) -> dict[str, dict]:
    """The baseline SAST scan per project, following Phase 1's precedence.

    Order per project: its own `mainBranch`, then `main`, then `master`, then
    the most recent SAST scan on any branch.
    """
    project_ids = [p["id"] for p in projects]
    by_branch: dict[str, dict[str, dict]] = {}
    for branch in _branch_candidates(projects):
        by_branch[branch] = client.get_last_sast_scans(project_ids, branch=branch)
    # Fallback pass: no branch filter at all.
    any_branch = client.get_last_sast_scans(project_ids)

    resolved: dict[str, dict] = {}
    for project in projects:
        pid = project["id"]
        order = []
        main_branch = (project.get("mainBranch") or "").strip()
        if main_branch:
            order.append(main_branch)
        order.extend(b for b in PREFERRED_BRANCHES if b != main_branch)

        for branch in order:
            scan = by_branch.get(branch, {}).get(pid)
            if scan:
                resolved[pid] = {**scan, "_branch": branch}
                break
        else:
            scan = any_branch.get(pid)
            if scan:
                resolved[pid] = {**scan, "_branch": scan.get("branch") or "unknown"}
    return resolved


def _history(client) -> tuple[dict[str, int], dict[str, set]]:
    """Scans per project and the set of branches ever scanned, in one walk."""
    scans: dict[str, int] = defaultdict(int)
    branches: dict[str, set] = defaultdict(set)
    for scan in client.iter_all_scans():
        pid = scan.get("projectId")
        if not pid:
            continue
        scans[pid] += 1
        branch = scan.get("branch")
        if branch:
            branches[pid].add(branch)
    return scans, branches


#: Parallel config reads per refresh. The auth client holds a lock and httpx's
#: client is thread-safe, so the only real limit is politeness to the tenant.
#: Eight turns ~32s of serial calls into ~5s without looking like a scraper.
CONFIG_FETCH_WORKERS = 8


def _findings_analysis_flags(client, projects: list[dict]) -> dict[str, bool]:
    """Which projects already have the capability turned on at project level.

    Projects excluded by name are skipped: they are hidden either way, and the
    call would be spent to learn nothing.

    A failed read counts as *not* enabled, which leaves the project visible. The
    failure direction matters - dropping a genuine candidate off the list
    because one HTTP call timed out is a silent loss, while showing a project
    that turns out to be already enabled costs someone one click.
    """
    targets = [p["id"] for p in projects if not is_converted_original(p.get("name") or "")]

    def read(pid: str) -> tuple[str, bool]:
        try:
            return pid, findings_analysis_enabled(client.get_project_config(pid))
        except CxError as exc:
            log.warning("Could not read config for project %s: %s", pid, exc)
            return pid, False

    with ThreadPoolExecutor(max_workers=CONFIG_FETCH_WORKERS) as pool:
        return dict(pool.map(read, targets))


def build_rows(client) -> list[ProjectRow]:
    """Fetch everything the portfolio needs. Scoring happens separately."""
    projects = client.get_projects()

    baselines = _resolve_baselines(client, projects)
    summaries = client.get_scan_summaries(
        [scan["id"] for scan in baselines.values() if scan.get("id")]
    )
    scan_counts, branch_sets = _history(client)
    fa_enabled = _findings_analysis_flags(client, projects)
    # The same test the project page runs before it redirects to an existing
    # run, done once for the whole tenant: a project has been analysed when the
    # copy this tool would create is already there.
    names = {project.get("name") or "" for project in projects}

    rows: list[ProjectRow] = []
    for project in projects:
        pid = project["id"]
        baseline = baselines.get(pid)
        counts = None
        note = ""
        if baseline:
            summary = summaries.get(baseline.get("id"))
            if summary:
                counts = severity_counts(summary.get("sastCounters"))
            else:
                note = "Baseline scan found, but no summary was returned for it."
        else:
            note = "No completed scan that ran the SAST engine."

        rows.append(
            ProjectRow(
                id=pid,
                name=project.get("name") or pid,
                main_branch=project.get("mainBranch"),
                repo_url=project.get("repoUrl"),
                criticality=project.get("criticality"),
                counts=counts,
                baseline_scan_id=(baseline or {}).get("id"),
                baseline_branch=(baseline or {}).get("_branch"),
                # Already on the scan dict from `last-scan` - the age of the
                # baseline costs nothing extra to carry, and without it the list
                # cannot say which projects are measuring against stale ground.
                baseline_created_at=(baseline or {}).get("createdAt"),
                findings_analysis_enabled=fa_enabled.get(pid, False),
                analysed=fa_project_name(project.get("name") or "") in names,
                scans=scan_counts.get(pid, 0),
                branches=len(branch_sets.get(pid, ())),
                note=note,
            )
        )
    log.info(
        "Portfolio built: %d projects, %d with a SAST baseline, "
        "%d already running Findings Analysis",
        len(rows),
        sum(1 for row in rows if row.has_baseline),
        sum(1 for row in rows if row.findings_analysis_enabled),
    )
    return rows


def rows_to_json(rows: list[ProjectRow]) -> list[dict]:
    """Snapshot payload. Only fetched facts - never the score or risk label.

    Those are derived from the current settings at render time, so retuning a
    weight re-ranks the stored snapshot without another tenant call.
    """
    return [
        {
            "id": row.id,
            "name": row.name,
            "main_branch": row.main_branch,
            "repo_url": row.repo_url,
            "criticality": row.criticality,
            "counts": row.counts,
            "baseline_scan_id": row.baseline_scan_id,
            "baseline_branch": row.baseline_branch,
            "baseline_created_at": row.baseline_created_at,
            "findings_analysis_enabled": row.findings_analysis_enabled,
            "analysed": row.analysed,
            "scans": row.scans,
            "branches": row.branches,
            "note": row.note,
        }
        for row in rows
    ]


#: Snapshot keys `ProjectRow` accepts. A snapshot written by an older build is
#: missing the newer ones and keeps its defaults; one written by a newer build
#: and read here would otherwise raise `TypeError` on an unexpected keyword and
#: take the whole page down over a cached file.
_ROW_FIELDS = frozenset(ProjectRow.__dataclass_fields__)


def rows_from_json(payload: list[dict] | None) -> list[ProjectRow]:
    return [
        ProjectRow(**{k: v for k, v in row.items() if k in _ROW_FIELDS})
        for row in payload or []
    ]
