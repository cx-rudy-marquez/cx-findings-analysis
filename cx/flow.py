"""The re-onboarding flow: copy a project, enable Findings Analysis, rescan.

This is the only module that writes to a tenant. It runs as a background task
and reports progress by writing into `store.py`, so the UI polls the database
rather than holding a run in process memory.

Ordering matters and is not negotiable: the configuration PATCH must land
*before* the scan is submitted, because the scan reads its configuration at
submission time. Enabling the flag afterwards produces a scan that looks
correct and proves nothing.

The scan is deliberately submitted as a **full** scan. Findings Analysis only
evaluates findings in NEW state; on a brand-new project's first scan every
finding is NEW, which is exactly what makes the before/after comparison total
rather than marginal. An incremental scan here would measure almost nothing.
"""

from __future__ import annotations

import io
import logging
import time

from analysis import categorize
from analysis.compare import new_state_share
from analysis.parity import compare_config, findings_analysis_enabled, report_to_json
from config import (
    FA_PROJECT_SUFFIX,
    FA_PROJECT_TAGS,
    FINDINGS_ANALYSIS_KEY,
    PREFERRED_BRANCHES,
    SAST_PRESET_KEY,
    Settings,
    settings as default_settings,
)
from cx.client import TERMINAL_SCAN_STATUSES, CxApiClient
from cx.errors import CxError
from store import CANCELED, COMPLETED, FAILED, RUNNING, Store

log = logging.getLogger(__name__)

#: Give up waiting for the scan after this long. The run is not cancelled - the
#: scan may still finish - but the dashboard stops holding a worker for it.
MAX_POLL_SECONDS = 60 * 90


class FlowAborted(CxError):
    """A precondition failed. Nothing further should be created in the tenant."""


def resolve_baseline(client: CxApiClient, project: dict) -> tuple[dict, str]:
    """The scan to measure against, and the branch it ran on.

    Tries main, then master, then falls back to the most recent SAST scan on any
    branch. The `engine=sast` filter is doing the real work: a project's newest
    run labelled "Full Scan" may have executed SCA only and carry no SAST
    results at all, and comparing against that would be comparing against
    nothing.
    """
    project_id = project["id"]
    candidates = [project.get("mainBranch")] if project.get("mainBranch") else []
    candidates += [b for b in PREFERRED_BRANCHES if b != project.get("mainBranch")]

    for branch in candidates:
        scan = client.get_last_sast_scan(project_id, branch=branch)
        if scan:
            return scan, branch

    scan = client.get_last_sast_scan(project_id)
    if scan:
        return scan, scan.get("branch") or "unknown"

    raise FlowAborted(
        f"Project '{project.get('name')}' has no completed scan that ran the SAST "
        "engine, so there is no baseline to compare against."
    )


def build_scan_payload(
    fa_project_id: str, upload_url: str, branch: str, repo_url: str | None,
    preset_name: str | None = None,
) -> dict:
    """Scan request mirroring the baseline's own SAST configuration.

    `preset_name` is omitted unless the source project pins one. There is no
    preset literally named "Default" - a hardcoded one fails the scan outright
    with "Preset not found" (errorCode 1024100) - and an empty value is what the
    baseline itself ran, meaning "inherit from project/tenant configuration".
    Substituting a different rule set would change which findings exist at all,
    and the before/after difference would then measure the preset swap rather
    than Findings Analysis.
    """
    sast_config: dict[str, str] = {
        # Full, not incremental - see the module docstring.
        "incremental": "false",
    }
    if preset_name:
        sast_config["presetName"] = preset_name

    return {
        "type": "upload",
        "handler": {
            "uploadUrl": upload_url,
            "branch": branch,
            **({"repoUrl": repo_url} if repo_url else {}),
        },
        "project": {"id": fa_project_id},
        "config": [{"type": "sast", "value": sast_config}],
        "tags": dict(FA_PROJECT_TAGS),
    }


def read_project_config(client, project_id: str) -> list[dict]:
    """A project's scan configuration, or an empty list if it cannot be read.

    Swallows the error deliberately. Both callers - the preset lookup and the
    parity check - are advisory: neither is worth aborting a run over, and an
    empty list degrades into "inherits" and "not set" rather than a stack trace.
    """
    try:
        return client.get_project_config(project_id) or []
    except CxError:
        return []


def source_preset_name(
    client, project_id: str, config: list[dict] | None = None
) -> str | None:
    """The SAST preset the source project pins, or None when it inherits.

    `config` lets a caller that has already read the project's configuration
    pass it in, so the flow does not fetch the same document twice.
    """
    if config is None:
        config = read_project_config(client, project_id)
    for row in config or []:
        if row.get("key") == SAST_PRESET_KEY:
            value = str(row.get("value") or "").strip()
            return value or None
    return None


def fa_project_name(base_name: str) -> str:
    """The name this flow gives the copy it creates. One definition, three uses.

    The run flow names the project it creates; the project page and `POST /runs`
    both look for that same name to decide whether the project has already been
    analysed. If those three ever disagreed, the guard would miss the very
    project the flow is about to collide with.
    """
    return f"{base_name}{FA_PROJECT_SUFFIX}"


def find_fa_twin(client: CxApiClient, base_name: str) -> dict | None:
    """The `<base>_FA` project, if the tenant already has one."""
    return _find_existing_fa_project(client, fa_project_name(base_name))


def _find_existing_fa_project(client: CxApiClient, name: str) -> dict | None:
    for project in client.get_projects():
        if project.get("name") == name:
            return project
    return None


def run_flow(
    run_id: str,
    source_project_id: str,
    store: Store,
    client: CxApiClient,
    settings: Settings | None = None,
    reuse_existing: bool = True,
) -> None:
    """Execute the full flow, journalling each step. Never raises to the caller.

    Errors are recorded on the run and re-rendered in the UI; a background task
    that raises into the event loop would leave the run stuck at `running`
    forever with no explanation.
    """
    settings = settings or default_settings
    step = store.log_step

    try:
        store.update_run(run_id, status=RUNNING, phase="resolving baseline")
        project = client.get_project(source_project_id)
        baseline, branch = resolve_baseline(client, project)
        baseline_scan_id = baseline.get("id")
        step(run_id, "resolve-baseline", "ok",
             f"scan {baseline_scan_id} on branch {branch}")
        store.update_run(
            run_id, baseline_scan_id=baseline_scan_id, baseline_branch=branch
        )

        store.update_run(run_id, phase="reading baseline results")
        # Only the baseline's own status mix is captured here - the before/after
        # figures come from the compare endpoints once the second scan exists,
        # so that both halves are measured with the same instrument.
        baseline_counters = client.get_scan_summary(baseline_scan_id).get(
            "sastCounters"
        )
        store.update_run(run_id, baseline_counters=baseline_counters)
        new_share = new_state_share(baseline_counters)
        step(
            run_id,
            "baseline-summary",
            "ok",
            "baseline status mix captured"
            + (f", {new_share}% in NEW state" if new_share is not None else ""),
        )

        store.update_run(run_id, phase="checking source availability")
        if not client.has_source(baseline_scan_id):
            raise FlowAborted(
                f"Checkmarx no longer retains the source for scan {baseline_scan_id}. "
                "Re-scan the project first, then run this comparison against the "
                "fresh scan."
            )
        step(run_id, "source-check", "ok", "source archive available")

        fa_name = fa_project_name(project.get("name") or "")
        store.update_run(run_id, phase=f"preparing {fa_name}", fa_project_name=fa_name)

        existing = _find_existing_fa_project(client, fa_name)
        if existing and reuse_existing:
            fa_project_id = existing["id"]
            step(run_id, "create-project", "reused",
                 f"existing project {fa_project_id}")
        elif existing:
            raise FlowAborted(
                f"A project named '{fa_name}' already exists. Delete it or enable "
                "reuse before running again - creating a second copy would leave "
                "two indistinguishable POC projects in the tenant."
            )
        else:
            step(run_id, "create-project", "attempting", fa_name)
            created = client.create_project(
                fa_name,
                repo_url=project.get("repoUrl"),
                main_branch=branch,
                tags=dict(FA_PROJECT_TAGS),
                criticality=project.get("criticality") or 3,
                groups=project.get("groups") or [],
            )
            fa_project_id = created["id"]
            step(run_id, "create-project", "ok", fa_project_id)
        store.update_run(run_id, fa_project_id=fa_project_id)

        store.update_run(run_id, phase="enabling Findings Analysis")
        step(run_id, "set-config", "attempting", FINDINGS_ANALYSIS_KEY)
        client.set_project_config(
            fa_project_id,
            [{"key": FINDINGS_ANALYSIS_KEY, "value": "true", "allowOverride": True}],
        )
        # Read back rather than trusting the 204. The key is not in any
        # published spec - configuration keys are dynamic - so a tenant without
        # the capability could accept the write and ignore it, and the scan
        # would then prove nothing while looking like a success.
        if not _config_enabled(client, fa_project_id):
            raise FlowAborted(
                f"'{FINDINGS_ANALYSIS_KEY}' did not stick on project {fa_project_id}. "
                "This tenant may not have Findings Analysis enabled. Stopping "
                "before running a scan that could not demonstrate anything."
            )
        step(run_id, "set-config", "ok", "verified enabled by read-back")

        # Parameter parity, read *after* the PATCH. Reading the candidate before
        # it would show findingsAnalysis false on both sides and report a match
        # for the wrong reason.
        store.update_run(run_id, phase="checking parameter parity")
        source_config = read_project_config(client, source_project_id)
        parity = compare_config(source_config, read_project_config(client, fa_project_id))
        store.update_run(run_id, parity_report=report_to_json(parity))
        # Never fatal. A mismatch does not make the numbers wrong, it makes them
        # unattributable, and that is a judgement for whoever reads the result -
        # so it is recorded loudly and the run continues.
        step(
            run_id,
            "parity-check",
            "ok" if parity.reliable else "warn",
            parity.summary
            + (
                ""
                if parity.reliable
                else " - differs on "
                + ", ".join(field.label for field in parity.mismatches)
            ),
        )

        store.update_run(run_id, phase="downloading source")
        buffer = io.BytesIO()
        size = client.download_code(baseline_scan_id, buffer)
        step(run_id, "download-code", "ok", f"{size} bytes")

        store.update_run(run_id, phase="uploading source")
        step(run_id, "upload", "attempting", "requesting pre-signed URL")
        upload_url = client.create_upload_url()
        client.put_upload(upload_url, buffer.getvalue())
        step(run_id, "upload", "ok", "archive uploaded")

        store.update_run(run_id, phase="submitting scan")
        preset = source_preset_name(client, source_project_id, config=source_config)
        payload = build_scan_payload(
            fa_project_id, upload_url, branch, project.get("repoUrl"), preset
        )
        step(
            run_id,
            "preset",
            "ok",
            f"pinned to '{preset}'" if preset
            else "inherited from tenant, matching the baseline",
        )
        step(run_id, "create-scan", "attempting", f"project {fa_project_id}")
        scan = client.create_scan(payload)
        fa_scan_id = scan["id"]
        store.update_run(run_id, fa_scan_id=fa_scan_id, phase="scan queued")
        step(run_id, "create-scan", "ok", fa_scan_id)

        status = _poll_scan(run_id, client, store, fa_scan_id, settings)
        if status == "Canceled":
            store.update_run(run_id, status=CANCELED, phase="canceled")
            return
        if status != "Completed":
            raise FlowAborted(
                f"The Findings Analysis scan finished as '{status}'. "
                "No comparison is possible from a scan that did not complete."
            )

        store.update_run(run_id, phase="comparing scans")
        # The platform compares the two scans itself and labels every finding
        # NEW / RECURRENT / FIXED, which is both more accurate than differencing
        # two severity totals and the only way to see findings that *appeared*.
        compare_counters = client.compare_summary(baseline_scan_id, fa_scan_id)
        compare_rows = client.compare_results(baseline_scan_id, fa_scan_id)
        store.update_run(
            run_id,
            compare_counters=compare_counters,
            compare_results=compare_rows,
            status=COMPLETED,
            phase="complete",
        )
        removed = len(categorize.removed_findings(compare_rows))
        step(
            run_id,
            "compare",
            "ok",
            f"{len(compare_rows)} findings across both scans, "
            f"{removed} eligible removals",
        )

    except Exception as exc:  # noqa: BLE001 - the run must record every failure
        message = str(exc)
        log.exception("Run %s failed", run_id)
        store.log_step(run_id, "run", "failed", message)
        store.update_run(run_id, status=FAILED, phase="failed", error=message)


def _config_enabled(client: CxApiClient, project_id: str) -> bool:
    return findings_analysis_enabled(client.get_project_config(project_id))


def _poll_scan(
    run_id: str, client: CxApiClient, store: Store, scan_id: str, settings: Settings
) -> str:
    started = time.monotonic()
    while True:
        scan = client.get_scan(scan_id)
        status = scan.get("status") or "Unknown"
        queue_position = scan.get("positionInQueue")
        phase = f"scan {status.lower()}"
        if status == "Queued" and queue_position is not None:
            phase = f"{phase} (position {queue_position})"
        store.update_run(run_id, phase=phase)

        if status in TERMINAL_SCAN_STATUSES:
            store.log_step(run_id, "scan", status.lower(), scan_id)
            return status

        if time.monotonic() - started > MAX_POLL_SECONDS:
            raise FlowAborted(
                f"Stopped waiting for scan {scan_id} after "
                f"{MAX_POLL_SECONDS // 60} minutes. The scan was left running - "
                "check it in Checkmarx One."
            )
        time.sleep(settings.poll_interval_seconds)
