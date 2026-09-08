"""Starting, watching, cancelling and comparing Findings Analysis runs.

`POST /runs` and `POST /runs/bulk` are the only endpoints in the application
that create anything in a tenant, and each is reachable only from its own
confirmation dialog - the project page for the former, the projects list for
the latter. There is no GET that starts a run, so a crawler, a prefetch or a
stray page reload cannot spend a scan.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, BackgroundTasks, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from analysis import categorize, portfolio
from analysis.compare import compare, new_state_share
from analysis.reonboard import plan_to_json
from config import FA_PROJECT_SUFFIX, settings
from cx import reonboard
from cx.errors import CxError
from cx.flow import FlowAborted, find_fa_twin, resolve_baseline, run_flow
from routes.deps import (
    base_context,
    get_client,
    get_store,
    require_reonboard_enabled,
    templates,
)
from routes.projects import _live_exclusion_reason
from store import COMPLETED, FAILED, PENDING, RUNNING, TERMINAL_RUN_STATUSES, Store

router = APIRouter()

#: Bulk batches are capped at this many project pipelines in flight at once -
#: the user's explicit requirement, and a guard against a large "select all"
#: batch (e.g. 36 projects) hammering the Checkmarx API with dozens of
#: simultaneous project-creation/upload/scan-start calls.
#:
#: `ThreadPoolExecutor.submit` queues everything past `max_workers` and starts
#: each queued item the moment a worker frees up, which is exactly "the 6th+
#: project starts as soon as a slot opens" with no scheduling code of our own.
#: `run_flow` is a plain blocking function (network calls, `time.sleep` while
#: polling a scan) - a thread pool, not asyncio, is what actually overlaps it.
BULK_MAX_CONCURRENT_RUNS = 5
_bulk_run_pool = ThreadPoolExecutor(
    max_workers=BULK_MAX_CONCURRENT_RUNS, thread_name_prefix="bulk-run"
)


def _run_phase_timestamps(store: Store, run: dict) -> dict[str, str | None]:
    """createdAt/downloadStartedAt/scanStartedAt/completedAt for one run.

    Built from the step journal (`store.get_step_timestamps`) that every run
    already writes, rather than new columns - so a batch's actual concurrency
    can be read directly from the Bulk Run view instead of inferred from UI
    polling snapshots (GOAL_FIX_BULK_ANALYSIS.md FIX 4).
    """
    steps = store.get_step_timestamps(run["id"])
    return {
        "created_at": run["created_at"],
        "download_started_at": steps.get("download-code"),
        "scan_started_at": steps.get("create-scan"),
        "completed_at": run["updated_at"] if run["status"] in TERMINAL_RUN_STATUSES else None,
    }


@router.post("/runs")
def start_run(
    background: BackgroundTasks,
    project_id: str = Form(...),
    minutes_per_finding: int = Form(settings.minutes_per_finding),
    confirm: str = Form(""),
) -> RedirectResponse:
    if confirm != "yes":
        raise HTTPException(
            status_code=400,
            detail="A run must be confirmed explicitly - it creates a project and "
                   "starts a scan in the tenant.",
        )
    minutes_per_finding = max(1, min(minutes_per_finding, 480))

    client = get_client()
    store = get_store()

    existing = store.find_active_run_for_project(project_id)
    if existing:
        # A second submit would create a second _FA project and a second scan.
        return RedirectResponse(f"/runs/{existing['id']}", status_code=303)

    project = client.get_project(project_id)

    # The project page hides the trigger when a twin exists, but hiding a button
    # is not a control - this is the route that spends a scan, so it checks the
    # tenant itself. Without it, a stale tab or a replayed form would create a
    # second copy of a project that has already been analysed.
    twin = find_fa_twin(client, project.get("name") or "")
    if twin:
        existing = store.find_latest_run_for_project(project_id)
        if existing:
            return RedirectResponse(f"/runs/{existing['id']}", status_code=303)
        raise HTTPException(
            status_code=400,
            detail=f"A project named '{twin.get('name')}' already exists in "
                   "Checkmarx. Delete it there, or open the run that created it, "
                   "before analysing this project again.",
        )

    run_id = store.create_run(
        source_project_id=project_id,
        source_project_name=project.get("name") or project_id,
        baseline_scan_id=None,
        baseline_branch=None,
        minutes_per_finding=minutes_per_finding,
        is_synthetic=settings.use_fixtures,
        status=RUNNING,
    )
    background.add_task(run_flow, run_id, project_id, store, client, settings)
    return RedirectResponse(f"/runs/{run_id}", status_code=303)


@router.post("/runs/bulk")
def start_bulk_run(
    project_ids: list[str] = Form(default_factory=list),
    confirm: str = Form(""),
) -> RedirectResponse:
    """Fan `run_flow` out over every selected project, up to 5 at a time.

    This used to hand each project to FastAPI's `BackgroundTasks` the same
    way `start_run` does for a single one - one `background.add_task` per
    project. That is not concurrent: `BackgroundTasks.__call__` is `for task
    in self.tasks: await task()`, so the *second* project's full pipeline
    (create project, set config, download, upload, start scan, poll to
    completion) never even began until the *first* one finished entirely. A
    3-project batch ran three full pipelines back to back, not in parallel -
    the effect a live-tenant test observed as projects stalling in lockstep
    (GOAL_FIX_BULK_ANALYSIS.md FIX 4).

    `_bulk_run_pool` fixes both problems in one move: submitting to a
    `ThreadPoolExecutor` genuinely overlaps `run_flow`'s blocking I/O and
    `time.sleep` polling across threads, and its fixed size caps how many
    pipelines are ever in flight at once - so a large "select all" batch
    doesn't hit the Checkmarx API with dozens of simultaneous requests, and
    `run_flow`'s own "never raises to the caller" behaviour still isolates
    each project's failure without any extra code here.
    """
    if confirm != "yes":
        raise HTTPException(
            status_code=400,
            detail="A bulk run must be confirmed explicitly - it creates a "
                   "project and starts a scan for every project selected.",
        )
    # Dedup, preserving order: a double-submitted checkbox list must not
    # create two runs for the same project.
    seen: set[str] = set()
    ids = [pid for pid in project_ids if not (pid in seen or seen.add(pid))]
    if not ids:
        raise HTTPException(
            status_code=400, detail="At least one project must be selected."
        )

    client = get_client()
    store = get_store()

    # Re-validated live, immediately before anything is written - the same
    # "hiding a button is not a control" discipline `start_run` applies to a
    # single project, looped here because the selection may be stale by the
    # time this request lands.
    to_run: list[dict] = []
    dropped: list[dict] = []
    for project_id in ids:
        try:
            project = client.get_project(project_id)
        except CxError:
            dropped.append(
                {"project_id": project_id, "name": project_id,
                 "reason": "Project not found in Checkmarx"}
            )
            continue

        name = project.get("name") or project_id
        reason = _live_exclusion_reason(client, project)
        if reason is None:
            try:
                resolve_baseline(client, project)
            except FlowAborted:
                reason = portfolio.NO_BASELINE
        if reason is None:
            twin = find_fa_twin(client, name)
            if twin:
                reason = f"A project named '{twin.get('name')}' already exists"
        if reason is None and store.find_active_run_for_project(project_id):
            reason = "A run for this project is already in progress"

        if reason is not None:
            dropped.append({"project_id": project_id, "name": name, "reason": reason})
        else:
            to_run.append(project)

    if not to_run:
        # Nothing to run and nothing to watch - a batch with zero runs has no
        # progress view worth landing on, so this reports the drop directly
        # rather than redirecting into an empty one.
        detail = "None of the selected projects could be run: " + "; ".join(
            f"{item['name']} ({item['reason']})" for item in dropped
        )
        raise HTTPException(status_code=400, detail=detail)

    batch_id = store.create_batch(project_count=len(to_run), dropped=dropped)
    for project in to_run:
        run_id = store.create_run(
            source_project_id=project["id"],
            source_project_name=project.get("name") or project["id"],
            baseline_scan_id=None,
            baseline_branch=None,
            minutes_per_finding=settings.minutes_per_finding,
            is_synthetic=settings.use_fixtures,
            status=RUNNING,
            batch_id=batch_id,
        )
        _bulk_run_pool.submit(run_flow, run_id, project["id"], store, client, settings)

    return RedirectResponse(f"/runs/bulk/{batch_id}", status_code=303)


@router.get("/runs/bulk/{batch_id}", response_class=HTMLResponse)
def bulk_run_detail(request: Request, batch_id: str) -> HTMLResponse:
    store = get_store()
    batch = _require_batch(store, batch_id)
    batch_runs = [
        {**run, "timestamps": _run_phase_timestamps(store, run)}
        for run in store.list_runs_for_batch(batch_id)
    ]
    context = base_context(request, tab="runs")
    context.update(
        {
            "batch": batch,
            "batch_runs": batch_runs,
            "poll_seconds": settings.poll_interval_seconds,
            "fa_suffix": FA_PROJECT_SUFFIX,
        }
    )
    return templates.TemplateResponse(request, "run_bulk.html", context)


@router.get("/runs/bulk/{batch_id}/status")
def bulk_run_status(batch_id: str) -> dict:
    """Polled by the bulk progress view. Reads SQLite fresh every call, so a
    refresh or a return visit shows current progress with no other state to
    reconstruct."""
    store = get_store()
    _require_batch(store, batch_id)
    runs = store.list_runs_for_batch(batch_id)
    return {
        "runs": [
            {
                "id": run["id"],
                "source_project_name": run["source_project_name"],
                "status": run["status"],
                "phase": run.get("phase"),
                "error": run.get("error"),
                "timestamps": _run_phase_timestamps(store, run),
            }
            for run in runs
        ],
        "completed": sum(1 for run in runs if run["status"] == COMPLETED),
        "failed": sum(1 for run in runs if run["status"] == FAILED),
        "total": len(runs),
        "done": all(run["status"] in TERMINAL_RUN_STATUSES for run in runs),
    }


@router.get("/runs", response_class=HTMLResponse)
def run_list(request: Request) -> HTMLResponse:
    """Run history, on its own tab.

    Read-only. `POST /runs` is still the only way to start one, so this route
    cannot spend a scan however it is reached.
    """
    context = base_context(request, tab="runs")
    context.update({"runs": get_store().list_runs(limit=50)})
    return templates.TemplateResponse(request, "runs.html", context)


#: The comparison page's tabs, in the order they are rendered. The first is the
#: default, and anything unrecognised falls back to it rather than erroring: a
#: mistyped or stale `?view=` should show the page, not refuse it.
COMPARISON_VIEWS: tuple[tuple[str, str], ...] = (
    ("severity", "By severity"),
    ("query", "By query"),
    ("cwe", "By CWE"),
    ("audit", "Audit trail"),
    ("reonboard", "Re-onboarding"),
)
DEFAULT_VIEW = COMPARISON_VIEWS[0][0]


@router.get("/runs/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, run_id: str, view: str = DEFAULT_VIEW) -> HTMLResponse:
    store = get_store()
    run = _require_run(store, run_id)
    if run["status"] in TERMINAL_RUN_STATUSES and run.get("compare_counters"):
        return _render_comparison(request, run, view)

    context = base_context(request, tab="runs")
    context.update(
        {
            "run": run,
            "steps": store.get_steps(run_id),
            "poll_seconds": settings.poll_interval_seconds,
            "fa_suffix": FA_PROJECT_SUFFIX,
        }
    )
    return templates.TemplateResponse(request, "run.html", context)


@router.get("/runs/{run_id}/status")
def run_status(run_id: str) -> dict:
    """Polled by the live status panel."""
    store = get_store()
    run = _require_run(store, run_id)
    return {
        "status": run["status"],
        "phase": run.get("phase"),
        "error": run.get("error"),
        "fa_scan_id": run.get("fa_scan_id"),
        "steps": store.get_steps(run_id),
        "done": run["status"] in TERMINAL_RUN_STATUSES,
    }


@router.post("/runs/{run_id}/cancel")
def cancel_run(run_id: str) -> RedirectResponse:
    store = get_store()
    run = _require_run(store, run_id)
    scan_id = run.get("fa_scan_id")
    if scan_id and run["status"] in {PENDING, RUNNING}:
        get_client().cancel_scan(scan_id)
        store.log_step(run_id, "cancel", "requested", scan_id)
    else:
        # No scan yet: the flow is still in its pre-scan steps. Marking the run
        # canceled here would lie about a scan that was never submitted.
        store.log_step(run_id, "cancel", "no-op", "no scan submitted yet")
    return RedirectResponse(f"/runs/{run_id}", status_code=303)


# --- [BETA] re-onboarding ----------------------------------------------------
# The only flow in this application that changes a project the customer already
# had. Three routes, and the split is the safety property: the GET only reads,
# the POST is the sole route that writes, and it refuses without both an
# explicit confirmation and the digest of the preview that was displayed.
#
# All three are gated on REONBOARD. The comparison page greys the tab out when
# the flag is off, but that is presentation: these checks are the control, and
# they are here because a bookmarked URL, a stale tab or a replayed form reaches
# the route without ever seeing the tab.


@router.get("/runs/{run_id}/reonboard", response_class=HTMLResponse)
def reonboard_preview(request: Request, run_id: str) -> HTMLResponse:
    """The mandatory dry run before, and the record of what was done after."""
    require_reonboard_enabled()
    store = get_store()
    run = _require_run(store, run_id)
    _require_reviewed_comparison(run)

    status = run.get("reonboard_status")
    # A failed re-onboarding is normally frozen: re-previewing a half-applied
    # disconnect and conversion would offer to fire them again at a repository
    # whose ownership is already part-moved. A manual run has neither call in
    # it - the worst it leaves behind is one outstanding rename against an
    # unclaimed name - so that one is offered again, and the fresh preview
    # reports which rename is still owed.
    settled = status in {reonboard.RUNNING, reonboard.COMPLETED} or (
        status == reonboard.FAILED and not _was_manual(run)
    )

    plan = None
    error = None
    if settled:
        # Show the plan that was approved and executed, never a fresh one.
        # Re-previewing here reads a tenant the re-onboarding itself has already
        # changed: the base project is now manual, so it no longer counts as
        # connected and its protected branches are gone. The recomputed plan
        # would refuse an action that has already succeeded, and sit under a
        # banner saying it succeeded.
        plan = run.get("reonboard_plan")
    else:
        try:
            plan = plan_to_json(reonboard.preview(get_client(), run))
            # Stored so the outcome page still has it once the tenant moves on.
            # The status is only advanced to `previewed` from a run that has not
            # already reported an outcome: a failed manual run is re-previewable
            # so it can be resumed, and stamping `previewed` over its failure
            # would erase the one record of what actually landed.
            fields = {"reonboard_plan": plan}
            if status != reonboard.FAILED:
                fields["reonboard_status"] = reonboard.PREVIEWED
            store.update_run(run_id, **fields)
        except CxError as exc:
            error = str(exc)

    context = base_context(request, tab="runs")
    context.update(
        {
            "run": run,
            "plan": plan,
            "error": error,
            "result": run.get("reonboard_result"),
            "reonboard_status": status,
            # A settled re-onboarding is history: no blockers, no warnings and
            # no confirm button, because there is nothing left to decide.
            "settled": settled,
            "poll_seconds": settings.poll_interval_seconds,
        }
    )
    return templates.TemplateResponse(request, "reonboard.html", context)


@router.post("/runs/{run_id}/reonboard")
def start_reonboard(
    background: BackgroundTasks,
    run_id: str,
    confirm: str = Form(""),
    plan_digest: str = Form(""),
) -> RedirectResponse:
    """Execute an approved plan. The one route that disconnects a project."""
    require_reonboard_enabled()
    store = get_store()
    run = _require_run(store, run_id)
    _require_reviewed_comparison(run)

    if confirm != "yes":
        raise HTTPException(
            status_code=400,
            detail="Re-onboarding must be confirmed explicitly - it disconnects "
                   "a live project from its repository.",
        )
    if not plan_digest:
        raise HTTPException(
            status_code=400,
            detail="Re-onboarding must be confirmed from a preview. No plan "
                   "digest was submitted, so there is nothing to verify against.",
        )
    if run.get("reonboard_status") in {reonboard.RUNNING, reonboard.COMPLETED}:
        # A second submit would disconnect an already-disconnected project and
        # start a second conversion of the same repository.
        return RedirectResponse(f"/runs/{run_id}/reonboard", status_code=303)

    store.update_run(run_id, reonboard_status=reonboard.RUNNING)
    background.add_task(
        reonboard.run_reonboard, run_id, store, get_client(), plan_digest, settings
    )
    return RedirectResponse(f"/runs/{run_id}/reonboard", status_code=303)


@router.get("/runs/{run_id}/reonboard/status")
def reonboard_status(run_id: str) -> dict:
    """Polled by the re-onboarding page while the conversion runs."""
    require_reonboard_enabled()
    run = _require_run(get_store(), run_id)
    status = run.get("reonboard_status")
    return {
        "status": status,
        "result": run.get("reonboard_result"),
        "done": status in {reonboard.COMPLETED, reonboard.FAILED},
    }


def _was_manual(run: dict) -> bool:
    """Whether the plan this run executed was the rename-only one.

    Read from the stored plan rather than recomputed, because the question is
    what was approved and attempted, not what the tenant would say now.
    """
    return bool((run.get("reonboard_plan") or {}).get("manual"))


def _require_reviewed_comparison(run: dict) -> None:
    """Re-onboarding is reachable only from a comparison that has been produced.

    Both conditions are the point of the gate: a run that never completed has no
    comparison to review, and one without a parity report was measured before
    the configuration check existed, so nobody can say the two projects scan
    alike.
    """
    if run.get("status") != COMPLETED:
        raise HTTPException(
            status_code=400,
            detail="Re-onboarding is only available for a completed comparison.",
        )
    if not run.get("parity_report"):
        raise HTTPException(
            status_code=400,
            detail="This run has no parameter parity check, so its comparison "
                   "has not been shown to be attributable. Re-run the "
                   "comparison before re-onboarding.",
        )


def _require_run(store, run_id: str) -> dict:
    run = store.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="No such run")
    return run


def _require_batch(store, batch_id: str) -> dict:
    batch = store.get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="No such batch")
    return batch


def _render_comparison(
    request: Request, run: dict, view: str = DEFAULT_VIEW
) -> HTMLResponse:
    compare_rows = run.get("compare_results") or []
    comparison = compare(run.get("compare_counters"), run["minutes_per_finding"])
    context = base_context(request, tab="runs")
    names = [name for name, _ in COMPARISON_VIEWS]
    # A re-onboarding tab nobody may open is not somewhere to land, so a link
    # into it while the flag is off falls back rather than showing a dead tab.
    if view == "reonboard" and not context["reonboard_enabled"]:
        view = DEFAULT_VIEW
    view = view if view in names else DEFAULT_VIEW

    context.update(
        {
            "run": run,
            "comparison": comparison,
            # None for runs recorded before the parity check existed - the
            # template renders nothing rather than an empty verdict.
            "parity": run.get("parity_report"),
            "warnings": comparison.warnings,
            "by_query": categorize.breakdown(compare_rows, key=categorize.query_name),
            "by_cwe": categorize.breakdown(compare_rows, key=categorize.cwe_label),
            "baseline_new_share": new_state_share(run.get("baseline_counters")),
            "steps": get_store().get_steps(run["id"]),
            "views": COMPARISON_VIEWS,
            "view": view,
        }
    )
    return templates.TemplateResponse(request, "comparison.html", context)
