"""Starting, watching, cancelling and comparing Findings Analysis runs.

`POST /runs` is the only endpoint in the application that creates anything in a
tenant, and it is reachable only from the confirmation dialog on the project
page. There is no GET that starts a run, so a crawler, a prefetch or a stray
page reload cannot spend a scan.
"""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from analysis import categorize
from analysis.compare import compare, new_state_share
from analysis.reonboard import plan_to_json
from config import FA_PROJECT_SUFFIX, settings
from cx import reonboard
from cx.errors import CxError
from cx.flow import find_fa_twin, run_flow
from routes.deps import (
    base_context,
    get_client,
    get_store,
    require_reonboard_enabled,
    templates,
)
from store import COMPLETED, PENDING, RUNNING, TERMINAL_RUN_STATUSES

router = APIRouter()


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
