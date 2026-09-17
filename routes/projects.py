"""Landing portfolio and per-project baseline.

Read-only against the tenant throughout. The only writes are to the local
snapshot and settings cache.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from analysis import portfolio
from analysis.compare import new_state_share, severity_counts
from analysis.parity import findings_analysis_enabled
from config import FA_PROJECT_SUFFIX, FINDINGS_ANALYSIS_KEY, settings
from cx.errors import CxError
from cx.flow import find_fa_twin, resolve_baseline
from cx.portfolio import build_rows, rows_from_json, rows_to_json
from routes.deps import base_context, get_client, get_store, templates

router = APIRouter()


def _effective_settings(store) -> tuple[dict, bool]:
    """Config defaults, overlaid with any saved overrides.

    Overlaid rather than replaced so a settings row written before a new key
    existed still works - the missing key falls back to its default instead of
    raising.
    """
    values = settings.portfolio_defaults()
    saved = store.get_portfolio_settings()
    if saved:
        values.update({k: v for k, v in saved.items() if k in values})
    return values, bool(saved)


@router.get("/", response_class=HTMLResponse)
def index(request: Request, q: str = "", sort: str = "score") -> HTMLResponse:
    store = get_store()
    tuning, customised = _effective_settings(store)

    snapshot = store.get_snapshot()
    rows = rows_from_json(snapshot["rows"] if snapshot else None)
    # Scoring happens here, not at build time: retuning a weight must re-rank
    # the stored snapshot without another tenant call.
    portfolio.score_rows(rows, tuning)

    # Before the search and before every count below, so the summary line
    # describes what is on screen. A snapshot built before the flag was
    # collected reports every project as not-enabled, so those reappear until
    # the next refresh; the `_FA_BACKUP` exclusion is name-based and applies to
    # an old snapshot immediately.
    rows = portfolio.visible_rows(rows)

    if q:
        needle = q.lower()
        rows = [row for row in rows if needle in row.name.lower()]
    if sort not in portfolio.SORT_KEYS:
        sort = "score"
    rows = portfolio.sort_rows(rows, sort)

    context = base_context(request)
    context.update(
        {
            "rows": rows,
            "query": q,
            "sort": sort,
            "sort_keys": portfolio.SORT_KEYS,
            "snapshot_built_at": snapshot["built_at"] if snapshot else None,
            "snapshot_stale": _is_stale(snapshot),
            "measured_count": sum(1 for row in rows if row.has_baseline),
            "risk_distribution": portfolio.risk_distribution(rows),
            "rebase_count": portfolio.rebase_count(rows),
            "rebase_stale_days": tuning["rebase_stale_days"],
            # The weights are shown in the sentence explaining the score, so the
            # explanation matches whatever the settings tab currently says.
            "tuning": tuning,
            "credential_warning": settings.missing_credentials(),
            "fa_suffix": FA_PROJECT_SUFFIX,
            "ineligibility_reason": portfolio.ineligibility_reason,
            "findings_analysis_key": FINDINGS_ANALYSIS_KEY,
        }
    )
    return templates.TemplateResponse(request, "index.html", context)


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request) -> HTMLResponse:
    """The scoring and risk knobs, on their own tab.

    Off the landing page on purpose: it is a page someone visits once to argue
    with the thresholds, and it was competing for attention with the ranking it
    produces.
    """
    tuning, customised = _effective_settings(get_store())
    context = base_context(request, tab="settings")
    context.update({"tuning": tuning, "tuning_customised": customised})
    return templates.TemplateResponse(request, "settings.html", context)


@router.post("/portfolio/refresh")
def refresh_portfolio() -> RedirectResponse:
    """Rebuild the snapshot. Reads only, but ~11s of tenant calls.

    A POST despite reading nothing but public data: it is the one action on the
    landing page with a real cost, and a GET would let a reload or a prefetch
    spend it repeatedly.
    """
    store = get_store()
    store.save_snapshot(rows_to_json(build_rows(get_client())))
    return RedirectResponse("/", status_code=303)


@router.post("/portfolio/settings")
def save_portfolio_settings(
    weight_high: int = Form(...),
    weight_medium: int = Form(...),
    weight_low: int = Form(...),
    weight_info: int = Form(...),
    risk_low_max_scans: int = Form(...),
    risk_low_max_branches: int = Form(...),
    risk_high_min_scans: int = Form(...),
    risk_high_min_branches: int = Form(...),
    flag_top_n: int = Form(...),
    rebase_stale_days: int = Form(...),
) -> RedirectResponse:
    values = {
        "weight_high": max(0, weight_high),
        "weight_medium": max(0, weight_medium),
        "weight_low": max(0, weight_low),
        "weight_info": max(0, weight_info),
        "risk_low_max_scans": max(0, risk_low_max_scans),
        "risk_low_max_branches": max(0, risk_low_max_branches),
        "risk_high_min_scans": max(1, risk_high_min_scans),
        "risk_high_min_branches": max(1, risk_high_min_branches),
        "flag_top_n": max(0, flag_top_n),
        "rebase_stale_days": max(1, rebase_stale_days),
    }
    get_store().save_portfolio_settings(values)
    return RedirectResponse("/settings", status_code=303)


@router.post("/portfolio/settings/reset")
def reset_portfolio_settings() -> RedirectResponse:
    get_store().clear_portfolio_settings()
    return RedirectResponse("/settings", status_code=303)


def _cx_project_url(project_id: str) -> str | None:
    """Deep link to this project in Checkmarx One, or None if it cannot be built.

    An unset base URL would produce a link to nowhere - which is worse than no
    link, because it looks clickable.
    """
    if not settings.base_url:
        return None
    return f"{settings.base_url}/projects/{project_id}/overview"


def _is_stale(snapshot: dict | None) -> bool:
    if not snapshot:
        return False
    try:
        built = datetime.fromisoformat(snapshot["built_at"])
    except ValueError:
        return True
    age = datetime.now(timezone.utc) - built
    return age.total_seconds() > settings.snapshot_stale_hours * 3600


def _live_exclusion_reason(client, project: dict) -> str | None:
    """Why this project is out of scope, read from the tenant rather than the cache.

    The list can afford to filter on a snapshot; a URL typed straight at a
    project cannot. Somebody who enabled the capability an hour ago would still
    be offered a run against it until the next refresh.

    The config call is skipped when the name already settles it - a converted
    original is hidden either way.
    """
    if portfolio.is_converted_original(project.get("name") or ""):
        return portfolio.CONVERTED_ORIGINAL
    try:
        enabled = findings_analysis_enabled(client.get_project_config(project["id"]))
    except CxError:
        # Same failure direction as the portfolio build: an unreadable config
        # leaves the project usable rather than blocking it on a timeout.
        return None
    return portfolio.ALREADY_ENABLED if enabled else None


def _unavailable(request: Request, project: dict, reason: str, detail: str) -> HTMLResponse:
    context = base_context(request)
    context.update({"project": project, "reason": reason, "detail": detail})
    return templates.TemplateResponse(request, "project_unavailable.html", context)


@router.get("/projects/{project_id}")
def project_detail(request: Request, project_id: str) -> Response:
    client = get_client()
    store = get_store()
    project = client.get_project(project_id)

    reason = _live_exclusion_reason(client, project)
    if reason == portfolio.CONVERTED_ORIGINAL:
        return _unavailable(
            request, project, reason,
            "This is the original project a re-onboarding disconnected. It keeps "
            "its full scan history and is never deleted, but its repository now "
            "belongs to another project - there is nothing left here to migrate.",
        )
    if reason == portfolio.ALREADY_ENABLED:
        return _unavailable(
            request, project, reason,
            "This project already scans with Findings Analysis turned on at "
            "project level, so there is no before-and-after to measure. Set "
            f"'{FINDINGS_ANALYSIS_KEY}' back to false in Checkmarx One if you "
            "want this tool to treat it as a candidate again.",
        )

    twin = find_fa_twin(client, project.get("name") or "")
    if twin:
        # This project has already been analysed. Offering the trigger again
        # would create a second copy and spend a second scan.
        existing = store.find_latest_run_for_project(project_id)
        if existing:
            return RedirectResponse(f"/runs/{existing['id']}", status_code=303)
        return _unavailable(
            request, project, "already analysed",
            f"A project named '{twin.get('name')}' ({twin.get('id')}) already "
            "exists in Checkmarx, but this tool holds no record of the run that "
            "created it. Open that run in whichever copy of the tool made it, or "
            "delete the project in Checkmarx One before analysing this one again.",
        )

    tuning, _ = _effective_settings(store)

    baseline = None
    branch = None
    counts = None
    error = None
    new_share = None
    baseline_age = None
    try:
        scan, branch = resolve_baseline(client, project)
        baseline = scan
        baseline_age = portfolio.baseline_age_days(scan.get("createdAt"))
        counters = client.get_scan_summary(scan["id"]).get("sastCounters")
        counts = severity_counts(counters)
        new_share = new_state_share(counters)
    except CxError as exc:
        error = str(exc)

    context = base_context(request)
    context.update(
        {
            "project": project,
            "baseline": baseline,
            "branch": branch,
            "counts": counts,
            "new_share": new_share,
            "error": error,
            "eligible_total": sum(
                (counts or {}).get(s, 0) for s in ("HIGH", "MEDIUM", "LOW", "INFO")
            ),
            "active_run": store.find_active_run_for_project(project_id),
            "findings_analysis_key": FINDINGS_ANALYSIS_KEY,
            "default_minutes": settings.minutes_per_finding,
            "baseline_age_days": baseline_age,
            "rebase_stale_days": tuning["rebase_stale_days"],
            "rebase_recommended": (
                baseline_age is not None
                and baseline_age > tuning["rebase_stale_days"]
            ),
            "cx_ui_url": _cx_project_url(project_id),
        }
    )
    return templates.TemplateResponse(request, "project.html", context)
