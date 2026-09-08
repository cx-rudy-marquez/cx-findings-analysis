"""End-to-end through the real ASGI app, in demo mode.

These are the checks that catch a broken template or a wrong context key -
things the unit tests cannot see because they never render anything.
"""

import time

import pytest
from fastapi.testclient import TestClient

from config import ROOT

WEBGOATNET = "fixture-webgoatnet"
#: A fixture project with no SAST scan at all - the one whose portfolio entry
#: declares no severities. Present deliberately: the "no baseline" path must
#: degrade into an explanation, not a stack trace.
NO_SAST = "fixture-docs-site"
NO_SAST_NAME = "acme/docs-site"


def _client(tmp_path, monkeypatch, reonboard: bool):
    monkeypatch.setenv("USE_FIXTURES", "true")
    monkeypatch.setenv("CX_DB_PATH", str(tmp_path / "routes.db"))
    # The fixture scan poller returns a terminal status after a couple of polls;
    # the default eight-second wait between them is pure dead time here and adds
    # minutes to the suite once several tests each drive a full run.
    monkeypatch.setenv("POLL_INTERVAL_SECONDS", "0")
    monkeypatch.setenv("REONBOARD", "true" if reonboard else "false")

    import config
    import routes.deps as deps

    fresh = config.Settings.from_env()
    monkeypatch.setattr(config, "settings", fresh)
    monkeypatch.setattr(deps, "settings", fresh)
    deps.get_client.cache_clear()
    deps.get_store.cache_clear()

    import app as app_module

    monkeypatch.setattr(app_module, "settings", fresh)
    with TestClient(app_module.app) as test_client:
        yield test_client

    deps.get_client.cache_clear()
    deps.get_store.cache_clear()


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A deployment with the re-onboarding beta switched on.

    The default for the suite because most of what is tested here only exists
    behind the flag. That every one of those tests 404s under `client_no_beta`
    is the assertion that the flag actually gates them.
    """
    yield from _client(tmp_path, monkeypatch, reonboard=True)


@pytest.fixture
def client_no_beta(tmp_path, monkeypatch):
    """A default deployment: REONBOARD unset, so re-onboarding is off."""
    yield from _client(tmp_path, monkeypatch, reonboard=False)


def wait_for_run(client, run_url: str, attempts: int = 60) -> dict:
    for _ in range(attempts):
        payload = client.get(f"{run_url}/status").json()
        if payload["done"]:
            return payload
        time.sleep(0.1)
    raise AssertionError(f"run did not finish: {payload}")


def wait_for_batch(client, batch_url: str, attempts: int = 60) -> dict:
    for _ in range(attempts):
        payload = client.get(f"{batch_url}/status").json()
        if payload["done"]:
            return payload
        time.sleep(0.1)
    raise AssertionError(f"batch did not finish: {payload}")


def test_healthz_reports_demo_mode(client):
    body = client.get("/healthz").json()
    assert body == {"ok": True, "mode": "demo", "missing_credentials": []}


def test_index_offers_to_build_before_any_snapshot_exists(client):
    """An unbuilt portfolio must say so, not render an empty table or stall."""
    page = client.get("/").text
    assert "has not been built yet" in page
    assert "rmarquez/WebGoatNet" not in page


def test_index_lists_the_portfolio_after_a_refresh(client):
    assert client.post("/portfolio/refresh", follow_redirects=False).status_code == 303
    page = client.get("/").text
    assert "rmarquez/WebGoatNet" in page
    assert "Sample data" in page
    assert "Counts as of" in page
    # All three risk levels are represented by the fixture portfolio.
    for level in ("risk-low", "risk-medium", "risk-high"):
        assert level in page
    # Top scorers are marked by the row tint alone - the badge that used to
    # repeat it was removed as noise.
    assert "tr class=\"flagged" in page


def test_index_filters_by_name(client):
    client.post("/portfolio/refresh")
    assert "payments-api" not in client.get("/", params={"q": "webgoat"}).text


def test_a_project_without_a_sast_baseline_is_unscored_not_zero(client):
    client.post("/portfolio/refresh")
    page = client.get("/").text
    assert "No completed scan that ran the SAST engine." in page


def test_retuning_weights_changes_the_ranking_without_refetching(client):
    client.post("/portfolio/refresh")

    def order(page: str) -> list[str]:
        import re
        return re.findall(r'/projects/(fixture-[a-z-]+)"', page)

    before = order(client.get("/").text)
    # Score on Low only: storefront has by far the most Low findings.
    client.post(
        "/portfolio/settings",
        data={
            "weight_high": 0, "weight_medium": 0, "weight_low": 1, "weight_info": 1,
            "risk_low_max_scans": 2, "risk_low_max_branches": 1,
            "risk_high_min_scans": 10, "risk_high_min_branches": 4,
            "flag_top_n": 5, "rebase_stale_days": 90,
        },
    )
    after_page = client.get("/").text
    assert order(after_page) != before
    assert after_page.index("storefront") < after_page.index("WebGoatNet")
    # The "Customised" badge moved to the settings tab along with the panel.
    assert "Customised" in client.get("/settings").text

    client.post("/portfolio/settings/reset")
    assert order(client.get("/").text) == before


def test_the_projects_list_shows_an_info_column(client):
    """Info is eligible for the capability, so the list has to show it.

    Before this existed the list scored Info at zero and never printed the
    number, while the project page it linked to counted Info as eligible - the
    two disagreed about the same project.
    """
    client.post("/portfolio/refresh")
    page = client.get("/").text
    assert ">Info</th>" in page
    assert "count-info" in page
    # Between Low and Score, not appended at the end.
    assert page.index(">Low</th>") < page.index(">Info</th>") < page.index(">Score<")


def test_the_scored_formula_on_the_list_names_every_weight(client):
    client.post("/portfolio/refresh")
    page = client.get("/").text
    assert "Info&times;1" in page or "Info×1" in page


def test_the_no_baseline_row_still_spans_the_count_columns(client):
    """The colspan has to grow with the table or the row goes ragged."""
    client.post("/portfolio/refresh")
    page = client.get("/").text
    assert "No completed scan that ran the SAST engine." in page
    assert 'colspan="6"' in page


def test_an_empty_result_spans_the_whole_table(client):
    # The empty-row branch only exists once a snapshot has been built; without
    # one the page shows the "not built yet" callout instead.
    client.post("/portfolio/refresh")
    page = client.get("/", params={"q": "zzzznomatch"}).text
    assert "No projects matched." in page
    assert 'colspan="12"' in page


def test_the_info_weight_round_trips_through_the_settings_form(client):
    client.post("/portfolio/refresh")
    assert 'name="weight_info"' in client.get("/settings").text

    def webgoatnet_score(page: str) -> str:
        import re
        row = page[page.index("WebGoatNet"):]
        return re.search(r'<td class="num score">(\d+)</td>', row).group(1)

    # Default weight 1: the 14 synthetic Info findings are worth 14 points.
    assert webgoatnet_score(client.get("/").text) == "122"

    def save(info: int):
        client.post(
            "/portfolio/settings",
            data={
                "weight_high": 3, "weight_medium": 2, "weight_low": 1,
                "weight_info": info,
                "risk_low_max_scans": 2, "risk_low_max_branches": 1,
                "risk_high_min_scans": 10, "risk_high_min_branches": 4,
                "flag_top_n": 5, "rebase_stale_days": 90,
            },
        )

    save(0)
    assert 'name="weight_info" min="0" max="100" value="0"' in client.get("/settings").text
    assert webgoatnet_score(client.get("/").text) == "108"
    # The count is still displayed even when it is worth nothing.
    assert "count-info" in client.get("/").text

    save(5)
    assert webgoatnet_score(client.get("/").text) == "178"   # 108 + 14 x 5

    client.post("/portfolio/settings/reset")
    assert webgoatnet_score(client.get("/").text) == "122"


def test_weighting_info_reorders_the_shortlist(client):
    """The flip that proves the weight reaches the ranking, not just the cell."""
    import re

    def order(page: str) -> list[str]:
        return re.findall(r'/projects/(fixture-[a-z-]+)"', page)

    client.post("/portfolio/refresh")
    with_info = order(client.get("/").text)

    client.post(
        "/portfolio/settings",
        data={
            "weight_high": 3, "weight_medium": 2, "weight_low": 1, "weight_info": 0,
            "risk_low_max_scans": 2, "risk_low_max_branches": 1,
            "risk_high_min_scans": 10, "risk_high_min_branches": 4,
            "flag_top_n": 5, "rebase_stale_days": 90,
        },
    )
    without_info = order(client.get("/").text)

    # webgoatnet 108 -> 122 overtakes legacy-uploader 113 -> 121.
    assert without_info.index("fixture-legacy-uploader") < without_info.index(
        "fixture-webgoatnet"
    )
    assert with_info.index("fixture-webgoatnet") < with_info.index(
        "fixture-legacy-uploader"
    )


def test_settings_saved_before_the_info_weight_existed_still_load(client):
    """Backward compatibility for a settings row already in someone's SQLite.

    `_effective_settings` overlays saved keys onto the defaults, so a row
    written before `weight_info` existed must fall back to the default rather
    than raising or silently scoring Info at zero.
    """
    from routes.deps import get_store
    from routes.projects import _effective_settings

    store = get_store()
    legacy = {
        "weight_high": 3, "weight_medium": 2, "weight_low": 1,
        "risk_low_max_scans": 2, "risk_low_max_branches": 1,
        "risk_high_min_scans": 10, "risk_high_min_branches": 4,
        "flag_top_n": 5, "rebase_stale_days": 90,
    }
    store.save_portfolio_settings(legacy)

    tuning, customised = _effective_settings(store)
    assert customised is True
    assert tuning["weight_info"] == 1
    assert client.get("/").status_code == 200


def test_the_info_severity_reaches_every_comparison_breakdown(client):
    """Severity, query and CWE tabs must all carry the new severity."""
    run_url = completed_run(client)

    severity = client.get(run_url, params={"view": "severity"}).text
    assert "sev-info" in severity
    assert "64.3" in severity                  # 9 of 14 Info removed

    query = client.get(run_url, params={"view": "query"}).text
    assert "Debug Enabled" in query
    assert "Information Exposure Through Comments" in query

    cwe = client.get(run_url, params={"view": "cwe"}).text
    assert "489" in cwe and "615" in cwe


def test_the_portfolio_cannot_be_built_by_a_get(client):
    assert client.get("/portfolio/refresh").status_code == 405


def test_project_page_shows_the_sast_only_baseline(client):
    page = client.get(f"/projects/{WEBGOATNET}").text
    # WebGoatNet's real SAST baseline is 63/5/33/27; the fixture layers a
    # synthetic 14 Info on top, giving 142 total and 79 eligible.
    assert ">142<" in page or "<strong>142</strong>" in page
    assert ">79<" in page
    assert "Critical is never analysed" in page


def test_a_project_without_a_sast_scan_explains_itself(client):
    page = client.get(f"/projects/{NO_SAST}")
    assert page.status_code == 200
    assert "no completed scan that ran the SAST engine" in page.text
    # And offers no way to start a run that could not produce a comparison.
    assert f"Create {NO_SAST_NAME}_FA" not in page.text


def test_a_run_must_be_confirmed(client):
    response = client.post(
        "/runs", data={"project_id": WEBGOATNET}, follow_redirects=False
    )
    assert response.status_code == 400


def test_a_run_cannot_be_started_by_a_get(client):
    """`GET /runs` lists history. It must not create one.

    This used to assert a 405, before the listing existed. The rule it guards is
    unchanged - only `POST /runs` may spend a scan - so it is now asserted
    directly rather than through the absence of the route.
    """
    from routes.deps import get_store

    assert client.get("/runs").status_code == 200
    assert get_store().list_runs() == []


def test_full_run_renders_the_comparison(client):
    response = client.post(
        "/runs",
        data={"project_id": WEBGOATNET, "minutes_per_finding": "12", "confirm": "yes"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    run_url = response.headers["location"]

    assert wait_for_run(client, run_url)["status"] == "completed"

    page = client.get(run_url).text
    assert "43.0" in page                      # 34 of 79 eligible
    assert "Sample data — not measured" in page
    assert "not eligible for Findings Analysis" in page
    assert "6.8" in page                       # 34 findings x 12 min = 6.8 hours
    assert "15.5" in page                      # NEW share of the original baseline

    # The breakdowns moved into tabs; the data behind them is unchanged.
    assert "Stored XSS" in client.get(run_url, params={"view": "query"}).text
    assert "CWE-209" in client.get(run_url, params={"view": "cwe"}).text


def test_unknown_run_is_a_404(client):
    assert client.get("/runs/deadbeef").status_code == 404


def test_an_in_flight_run_is_not_duplicated(client, tmp_path):
    """The confirmation dialog must not be submittable twice into two scans."""
    from routes.deps import get_store
    from store import RUNNING

    store = get_store()
    run_id = store.create_run(
        source_project_id=WEBGOATNET,
        source_project_name="rmarquez/WebGoatNet",
        baseline_scan_id=None,
        baseline_branch=None,
        minutes_per_finding=10,
        status=RUNNING,
    )
    response = client.post(
        "/runs",
        data={"project_id": WEBGOATNET, "confirm": "yes"},
        follow_redirects=False,
    )
    assert response.headers["location"] == f"/runs/{run_id}"


# --- Bulk Analyze -------------------------------------------------------------


def test_bulk_run_must_be_confirmed(client):
    response = client.post(
        "/runs/bulk", data={"project_ids": [WEBGOATNET]}, follow_redirects=False
    )
    assert response.status_code == 400


def test_bulk_run_rejects_an_empty_selection(client):
    response = client.post(
        "/runs/bulk", data={"confirm": "yes"}, follow_redirects=False
    )
    assert response.status_code == 400


def test_bulk_run_starts_every_selected_project_in_parallel(client):
    response = client.post(
        "/runs/bulk",
        data={"project_ids": [WEBGOATNET, "fixture-payments-api"], "confirm": "yes"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    batch_url = response.headers["location"]

    status = wait_for_batch(client, batch_url)
    assert status["total"] == 2
    assert status["completed"] == 2
    assert status["failed"] == 0

    page = client.get(batch_url).text
    assert "rmarquez/WebGoatNet" in page
    assert "acme/payments-api" in page
    assert "were not started" not in page


def test_bulk_run_drops_ineligible_projects_and_proceeds_with_the_rest(client):
    """One collision must not block the rest of a batch.

    `NO_SAST` has no baseline scan, so it fails the live pre-flight check and
    is dropped; `WEBGOATNET` is untouched and still runs.
    """
    response = client.post(
        "/runs/bulk",
        data={"project_ids": [WEBGOATNET, NO_SAST], "confirm": "yes"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    batch_url = response.headers["location"]
    batch_id = batch_url.rsplit("/", 1)[-1]

    from routes.deps import get_store

    batch = get_store().get_batch(batch_id)
    assert batch["project_count"] == 1
    assert [item["project_id"] for item in batch["dropped"]] == [NO_SAST]

    status = wait_for_batch(client, batch_url)
    assert status["total"] == 1
    assert status["completed"] == 1

    page = client.get(batch_url).text
    assert "were not started" in page
    assert NO_SAST_NAME in page
    assert "No completed SAST scan" in page


def test_bulk_run_with_every_project_ineligible_does_not_create_a_batch(client):
    response = client.post(
        "/runs/bulk", data={"project_ids": [NO_SAST], "confirm": "yes"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "No completed SAST scan" in response.text


def test_a_failure_in_one_bulk_project_does_not_affect_others(client, monkeypatch):
    """Bulk needs no failure-isolation code of its own - `run_flow` already
    never raises to its caller, and each project gets its own background task
    and its own DB row. This proves that holds across two calls, not one."""
    import routes.runs as runs_module
    from store import FAILED

    real_run_flow = runs_module.run_flow

    def flaky_run_flow(run_id, project_id, store, client_, settings_):
        if project_id == "fixture-payments-api":
            store.update_run(run_id, status=FAILED, error="synthetic failure")
            return
        real_run_flow(run_id, project_id, store, client_, settings_)

    monkeypatch.setattr(runs_module, "run_flow", flaky_run_flow)

    response = client.post(
        "/runs/bulk",
        data={"project_ids": [WEBGOATNET, "fixture-payments-api"], "confirm": "yes"},
        follow_redirects=False,
    )
    batch_url = response.headers["location"]
    status = wait_for_batch(client, batch_url)
    assert status["completed"] == 1
    assert status["failed"] == 1
    failed = [r for r in status["runs"] if r["status"] == "failed"][0]
    assert failed["error"] == "synthetic failure"


def test_a_real_pipeline_failure_leaves_its_partial_fa_project_in_place(client, monkeypatch):
    """Fails inside the real run_flow (at create-scan, after the _FA project,
    config, and archive upload already happened) rather than bypassing the
    flow like the test above does. Verifies the batch isolates the failure
    AND that the partially-created _FA project is left in place, not rolled
    back or cleaned up - the GAP flagged in GOAL_FIX_BULK_ANALYSIS.md."""
    from cx.fixtures import FixtureClient
    from routes.deps import get_client

    real_create_scan = FixtureClient.create_scan
    failing_fa_id = "fixture-acme/payments-api_FA"

    def flaky_create_scan(self, payload):
        if payload["project"]["id"] == failing_fa_id:
            raise RuntimeError("synthetic scan-creation failure")
        return real_create_scan(self, payload)

    monkeypatch.setattr(FixtureClient, "create_scan", flaky_create_scan)

    response = client.post(
        "/runs/bulk",
        data={
            "project_ids": [WEBGOATNET, "fixture-payments-api", "fixture-storefront"],
            "confirm": "yes",
        },
        follow_redirects=False,
    )
    batch_url = response.headers["location"]
    status = wait_for_batch(client, batch_url)

    assert status["total"] == 3
    assert status["completed"] == 2
    assert status["failed"] == 1
    failed = [r for r in status["runs"] if r["status"] == "failed"][0]
    assert "synthetic scan-creation failure" in failed["error"]

    # The batch detail page renders cleanly with the mixed outcome, not a crash.
    page = client.get(batch_url).text
    assert "1 failed" in page

    # The partially-created _FA project was left in place, not cleaned up.
    assert get_client().get_project(failing_fa_id)["id"] == failing_fa_id


def test_bulk_runs_overlap_but_never_exceed_5_in_flight(client, monkeypatch):
    """Regression for GOAL_FIX_BULK_ANALYSIS.md FIX 4: `start_bulk_run` used
    to hand each project to FastAPI's `BackgroundTasks`, whose `__call__` is
    `for task in self.tasks: await task()` - a for-loop that awaits each task
    to completion before starting the next, so nothing in a "parallel" batch
    ever actually overlapped. This instruments the real `run_flow` (not a
    stand-in) to record how many projects are executing at once, across a
    batch of 8 - comfortably past the 5-in-flight cap - and asserts the peak
    never exceeds it while also proving it is not silently back to fully
    serial (peak of 1)."""
    import threading

    import routes.runs as runs_module

    real_run_flow = runs_module.run_flow
    lock = threading.Lock()
    state = {"current": 0, "peak": 0}

    def instrumented_run_flow(run_id, project_id, store, client_, settings_):
        with lock:
            state["current"] += 1
            state["peak"] = max(state["peak"], state["current"])
        try:
            # Held briefly so overlapping calls actually overlap in wall time
            # rather than racing through in whichever order the pool happens
            # to schedule them.
            time.sleep(0.05)
            real_run_flow(run_id, project_id, store, client_, settings_)
        finally:
            with lock:
                state["current"] -= 1

    monkeypatch.setattr(runs_module, "run_flow", instrumented_run_flow)

    project_ids = [
        WEBGOATNET,
        "fixture-payments-api",
        "fixture-storefront",
        "fixture-auth-service",
        "fixture-internal-tools",
        "fixture-legacy-billing",
        "fixture-mobile-api",
        "fixture-legacy-uploader",
    ]
    response = client.post(
        "/runs/bulk",
        data={"project_ids": project_ids, "confirm": "yes"},
        follow_redirects=False,
    )
    batch_url = response.headers["location"]
    status = wait_for_batch(client, batch_url, attempts=200)

    assert status["total"] == len(project_ids)
    assert status["completed"] == len(project_ids)
    assert 2 <= state["peak"] <= 5


def test_completed_bulk_runs_appear_in_recent_runs_tagged_with_their_batch(client):
    response = client.post(
        "/runs/bulk", data={"project_ids": [WEBGOATNET], "confirm": "yes"},
        follow_redirects=False,
    )
    batch_url = response.headers["location"]
    wait_for_batch(client, batch_url)

    page = client.get("/runs").text
    assert "rmarquez/WebGoatNet" in page
    assert f'href="{batch_url}"' in page


def test_unknown_batch_is_a_404(client):
    assert client.get("/runs/bulk/deadbeef").status_code == 404
    assert client.get("/runs/bulk/deadbeef/status").status_code == 404


def test_the_projects_list_offers_a_bulk_checkbox_per_eligible_row(client):
    client.post("/portfolio/refresh")
    page = client.get("/").text
    assert 'id="select-all"' in page
    assert 'id="bulk-bar"' in page
    assert 'id="bulk-confirm"' in page
    # An eligible row gets a live checkbox the user can act on.
    assert f'data-project-id="{WEBGOATNET}"' in page
    # An ineligible row (no baseline) gets a disabled one with its reason.
    row = page[page.index(NO_SAST_NAME) - 400 : page.index(NO_SAST_NAME)]
    assert 'class="bulk-select" disabled' in row
    assert "No completed SAST scan to use as a baseline" in row


def test_the_bulk_confirmation_checkbox_gates_the_bulk_submit_button(client):
    client.post("/portfolio/refresh")
    page = client.get("/").text
    assert '<button type="submit" id="bulk-confirm-submit" disabled>' in page
    assert 'id="bulk-confirm-confirm-cb"' in page


def test_the_single_project_modal_is_unchanged_by_the_shared_modal_refactor(client):
    """The refactor into a shared, parameterized component must not touch the
    single-project page's behavior: no checkbox, Create enabled immediately."""
    page = client.get(f"/projects/{WEBGOATNET}").text
    assert "confirm-checkbox" not in page
    assert '<button type="submit" id="confirm-submit">' in page
    assert "Create rmarquez/WebGoatNet_FA and scan" in page


def test_the_bulk_bar_hides_at_zero_selection_in_css_not_just_js(client):
    """The JS already sets `.hidden = count === 0` (index.html); the actual
    defect was CSS: `.bulk-action-bar { display: flex }` silently overrode the
    browser's own `[hidden]{display:none}` rule. Guards that override rule
    since there is no browser/Playwright harness in this suite to check the
    rendered style directly."""
    css = (ROOT / "static" / "app.css").read_text()
    assert ".bulk-action-bar[hidden] { display: none; }" in css


def test_the_single_project_modal_uses_grammatical_singular_copy(client):
    """N=1 must read as standard English, not the plural-only copy the shared
    modal was written for (`.bulk-count` design note in _confirm_modal.html).
    The count and its noun render as separate elements (so bulk's JS can
    patch each independently), so this checks the rendered `.bulk-noun` spans
    rather than a plain-English substring."""
    import re

    page = client.get(f"/projects/{WEBGOATNET}").text
    project_nouns = re.findall(
        r'data-singular="project" data-plural="projects">([^<]+)<', page
    )
    scan_nouns = re.findall(
        r'data-singular="scan" data-plural="scans">([^<]+)<', page
    )
    assert project_nouns == ["project"] * len(project_nouns)
    assert scan_nouns == ["scan"] * len(scan_nouns)
    assert len(project_nouns) >= 2  # aggregate line + collapsible summary
    assert len(scan_nouns) >= 1


# --- Phase 3: tabs, settings tab, run list, re-base indicator ----------------


def test_every_page_carries_the_tab_bar(client):
    for path in ("/", "/runs", "/settings"):
        page = client.get(path).text
        assert 'aria-label="Main"' in page, path
        assert 'href="/settings"' in page, path


def test_the_active_tab_is_marked_on_each_page(client):
    assert 'class="tab tab-active"' in client.get("/").text
    assert '<a href="/runs" class="tab tab-active"' in client.get("/runs").text
    assert "tab tab-icon tab-active" in client.get("/settings").text


def test_a_project_page_belongs_to_the_projects_tab(client):
    """A path the tab does not share must still light the right tab."""
    page = client.get(f"/projects/{WEBGOATNET}").text
    assert '<a href="/" class="tab tab-active"' in page


def test_the_settings_panel_left_the_projects_page(client):
    client.post("/portfolio/refresh")
    page = client.get("/").text
    assert 'action="/portfolio/settings"' not in page
    assert 'action="/portfolio/settings"' in client.get("/settings").text


def test_the_run_list_left_the_projects_page(client):
    client.post("/portfolio/refresh")
    assert "Recent runs</h2>" not in client.get("/").text
    assert "Recent runs</h2>" in client.get("/runs").text


def test_an_empty_run_list_explains_itself(client):
    assert "No runs yet." in client.get("/runs").text


def test_saving_settings_returns_to_the_settings_tab(client):
    response = client.post(
        "/portfolio/settings",
        data={
            "weight_high": 3, "weight_medium": 2, "weight_low": 1, "weight_info": 1,
            "risk_low_max_scans": 2, "risk_low_max_branches": 1,
            "risk_high_min_scans": 10, "risk_high_min_branches": 4,
            "flag_top_n": 5, "rebase_stale_days": 45,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/settings"
    assert 'value="45"' in client.get("/settings").text

    reset = client.post("/portfolio/settings/reset", follow_redirects=False)
    assert reset.headers["location"] == "/settings"


def test_a_stale_baseline_is_flagged_on_the_projects_list(client):
    client.post("/portfolio/refresh")
    page = client.get("/").text
    assert "badge-rebase" in page
    assert "recommended for re-base" in page
    # And a project scanned recently is not flagged.
    assert "stale-baseline" in page


def test_the_rebase_threshold_is_tunable(client):
    """Raising the threshold past every fixture's age clears the flags."""
    client.post("/portfolio/refresh")
    assert "badge-rebase" in client.get("/").text
    client.post(
        "/portfolio/settings",
        data={
            "weight_high": 3, "weight_medium": 2, "weight_low": 1, "weight_info": 1,
            "risk_low_max_scans": 2, "risk_low_max_branches": 1,
            "risk_high_min_scans": 10, "risk_high_min_branches": 4,
            "flag_top_n": 5, "rebase_stale_days": 3650,
        },
    )
    assert "badge-rebase" not in client.get("/").text


def test_a_stale_project_says_so_on_its_own_page(client):
    page = client.get("/projects/fixture-legacy-billing").text
    assert "flagged for re-basing" in page


def test_the_comparison_reports_parameter_parity(client):
    response = client.post(
        "/runs",
        data={"project_id": WEBGOATNET, "confirm": "yes"},
        follow_redirects=False,
    )
    run_url = response.headers["location"]
    assert wait_for_run(client, run_url)["status"] == "completed"

    from routes.deps import get_store
    run = get_store().get_run(run_url.rsplit("/", 1)[-1])

    page = client.get(run_url).text
    # One badge on the headline: the settings behind it are provenance and do
    # not compete with the numbers for space.
    assert "Parameters match baseline" in page
    assert "needs review" not in page
    assert "<td>Fast scan mode</td>" not in page

    # The evidence is a click away, in the audit trail.
    audit = client.get(run_url, params={"view": "audit"}).text
    assert "Scan parameters" in audit
    for label in ("Fast scan mode", "Folder/file filter", "Incremental",
                  "LLM-based scanning", "Preset", "Recommended exclusions",
                  "Findings Analysis"):
        assert f"<td>{label}</td>" in audit
    assert run["baseline_scan_id"] in audit


def test_a_parameter_mismatch_marks_the_comparison_unreliable(client):
    """A confound must be surfaced, not silently absorbed into the headline.

    `fixture-auth-service` overrides fast scan mode and a folder filter. Neither
    is carried onto a fresh copy and neither is overridden by the scan payload,
    so the two projects genuinely scan differently.
    """
    response = client.post(
        "/runs",
        data={"project_id": "fixture-auth-service", "confirm": "yes"},
        follow_redirects=False,
    )
    run_url = response.headers["location"]
    assert wait_for_run(client, run_url)["status"] == "completed"

    # The warning stays on the headline - it is a verdict on every number there.
    page = client.get(run_url).text
    assert "This comparison needs review" in page
    assert "Parameters match baseline" not in page

    audit = client.get(run_url, params={"view": "audit"}).text
    assert "Fast scan mode" in audit
    assert "Folder/file filter" in audit
    # Every parameter is listed, so the check is not that the expected
    # difference is absent - it is that it is not reported as a fault.
    assert "<td>Findings Analysis</td>" in audit
    assert "expected to differ" in audit
    assert audit.count("parity-flag-off") == 2     # the two real mismatches


# --- Phase 3c: [BETA] re-onboarding -----------------------------------------


def completed_run(client) -> str:
    """A finished comparison, which is the only thing re-onboarding hangs off."""
    response = client.post(
        "/runs",
        data={"project_id": WEBGOATNET, "confirm": "yes"},
        follow_redirects=False,
    )
    run_url = response.headers["location"]
    assert wait_for_run(client, run_url)["status"] == "completed"
    return run_url


def test_the_comparison_offers_a_re_onboarding_preview(client):
    page = client.get(completed_run(client), params={"view": "reonboard"}).text
    assert "Preview re-onboarding" in page
    assert "Beta" in page
    assert "Nothing is deleted" in page


def test_the_preview_is_reachable_and_writes_nothing(client):
    from routes.deps import get_client

    page = client.get(f"{completed_run(client)}/reonboard")
    assert page.status_code == 200
    assert "What would happen" in page.text
    assert get_client()._disconnected == set()


def test_the_preview_names_both_calls_and_both_project_ids(client):
    page = client.get(f"{completed_run(client)}/reonboard").text
    assert "/disconnect" in page
    assert "/api/repos-manager/project-conversion" in page
    assert "fixture-webgoatnet" in page          # the base
    assert "WebGoatNet_FA" in page               # the candidate


def test_the_preview_shows_the_filtered_scanner_list(client):
    """The fixture baseline reports containers/microengines; neither may appear."""
    page = client.get(f"{completed_run(client)}/reonboard").text
    assert "sast, sca, kics" in page
    assert "containers" not in page
    assert "microengines" not in page


def test_re_onboarding_cannot_be_started_by_a_get(client):
    run_url = completed_run(client)
    from routes.deps import get_client

    client.get(f"{run_url}/reonboard")
    assert get_client()._disconnected == set()


def test_re_onboarding_must_be_confirmed(client):
    run_url = completed_run(client)
    response = client.post(f"{run_url}/reonboard", data={"plan_digest": "x"})
    assert response.status_code == 400
    assert "confirmed explicitly" in response.json()["detail"]


def test_re_onboarding_requires_the_digest_of_a_reviewed_plan(client):
    run_url = completed_run(client)
    response = client.post(f"{run_url}/reonboard", data={"confirm": "yes"})
    assert response.status_code == 400
    assert "digest" in response.json()["detail"]


def test_a_stale_digest_changes_nothing_in_the_tenant(client):
    from routes.deps import get_client

    run_url = completed_run(client)
    client.post(
        f"{run_url}/reonboard",
        data={"confirm": "yes", "plan_digest": "0000000000000000"},
    )
    page = client.get(f"{run_url}/reonboard").text
    assert "no longer matches" in page
    assert get_client()._disconnected == set()


def test_re_onboarding_is_unreachable_without_a_comparison(client):
    """The 3c gate: only from a completed run that carries a parity check."""
    from routes.deps import get_store
    from store import RUNNING

    run_id = get_store().create_run(
        source_project_id=WEBGOATNET, source_project_name="rmarquez/WebGoatNet",
        baseline_scan_id=None, baseline_branch=None, minutes_per_finding=10,
        status=RUNNING,
    )
    assert client.get(f"/runs/{run_id}/reonboard").status_code == 400
    response = client.post(
        f"/runs/{run_id}/reonboard", data={"confirm": "yes", "plan_digest": "x"}
    )
    assert response.status_code == 400


def test_a_confirmed_re_onboarding_disconnects_the_base_and_converts_the_copy(client):
    import re

    from routes.deps import get_client

    run_url = completed_run(client)
    # The digest the preview actually rendered into its confirm form - the same
    # value a person clicking the button would submit.
    preview = client.get(f"{run_url}/reonboard").text
    digest = re.search(r'name="plan_digest" value="([a-f0-9]+)"', preview).group(1)

    response = client.post(
        f"{run_url}/reonboard",
        data={"confirm": "yes", "plan_digest": digest},
        follow_redirects=False,
    )
    assert response.status_code == 303

    for _ in range(60):
        payload = client.get(f"{run_url}/reonboard/status").json()
        if payload["done"]:
            break
        time.sleep(0.1)
    assert payload["status"] == "completed", payload

    cx = get_client()
    assert cx._disconnected == {WEBGOATNET}
    assert cx._converted                      # the copy was converted
    converted = list(cx._converted.values())[0]
    assert converted["cxProjectId"] == "fixture-rmarquez/WebGoatNet_FA"

    # The base still exists - renamed, disconnected, never deleted - and the
    # copy has taken over the name it released.
    assert cx.get_project(WEBGOATNET)["name"] == "rmarquez/WebGoatNet_FA_BACKUP"
    assert cx.get_project("fixture-rmarquez/WebGoatNet_FA")["name"] == (
        "rmarquez/WebGoatNet"
    )

    page = client.get(f"{run_url}/reonboard").text
    assert "Re-onboarding complete" in page
    assert "manual project" in page
    assert "WebGoatNet_FA_BACKUP" in page


def test_the_last_connected_project_is_refused_in_the_ui(client):
    """auth-service is the only project on its integration in the fixture."""
    response = client.post(
        "/runs",
        data={"project_id": "fixture-auth-service", "confirm": "yes"},
        follow_redirects=False,
    )
    run_url = response.headers["location"]
    assert wait_for_run(client, run_url)["status"] == "completed"

    page = client.get(f"{run_url}/reonboard").text
    assert "cannot proceed" in page
    assert "only project connected" in page
    # And no confirm button is offered for a plan that cannot run.
    assert 'name="confirm"' not in page


def test_a_completed_re_onboarding_does_not_re_preview_itself(client, monkeypatch):
    """Regression: the outcome page contradicted itself on a live tenant.

    Re-previewing after execution reads a tenant the re-onboarding has already
    changed - the base is now a manual project, so it no longer counts as
    connected and its protected branches are gone. The page rendered
    "Re-onboarding complete" directly above a freshly computed
    "This re-onboarding cannot proceed".

    Asserted as "the tenant is not read again" rather than through fixture data,
    because what went wrong is the re-read itself; which particular refusal it
    produces depends on the tenant.
    """
    import re

    from cx import reonboard as reonboard_module

    run_url = completed_run(client)
    preview = client.get(f"{run_url}/reonboard").text
    digest = re.search(r'name="plan_digest" value="([a-f0-9]+)"', preview).group(1)
    client.post(f"{run_url}/reonboard", data={"confirm": "yes", "plan_digest": digest})

    for _ in range(60):
        payload = client.get(f"{run_url}/reonboard/status").json()
        if payload["done"]:
            break
        time.sleep(0.1)
    assert payload["status"] == "completed"

    calls = []
    real_preview = reonboard_module.preview
    def counting_preview(*args, **kwargs):
        calls.append(1)
        return real_preview(*args, **kwargs)
    monkeypatch.setattr(reonboard_module, "preview", counting_preview)

    page = client.get(f"{run_url}/reonboard").text
    assert calls == [], "a settled re-onboarding must not re-read the tenant"

    assert "Re-onboarding complete" in page
    assert "cannot proceed" not in page
    # Nothing left to decide, so no confirm button.
    assert 'name="confirm"' not in page
    # The plan that was executed is still shown, as a record of what was done.
    assert "What was done" in page
    assert "/api/repos-manager/project-conversion" in page


# --- Phase 3.1: projects that are no longer candidates ------------------------

BACKUP = "fixture-checkout_FA_BACKUP"
BACKUP_NAME = "acme/checkout_FA_BACKUP"
FA_ENABLED = "fixture-search-api"
FA_ENABLED_NAME = "acme/search-api"
#: A base project whose `<name>_FA` copy already exists in the fixture tenant.
ANALYSED = "fixture-notifications"
ANALYSED_NAME = "acme/notifications"


def test_a_converted_original_is_not_listed(client):
    client.post("/portfolio/refresh")
    assert BACKUP_NAME not in client.get("/").text


def test_a_project_already_running_the_capability_is_not_listed(client):
    client.post("/portfolio/refresh")
    assert FA_ENABLED_NAME not in client.get("/").text


def test_the_summary_counts_describe_only_what_is_listed(client):
    """"N of M projects" must not count projects the table refuses to show."""
    import routes.deps as deps

    tenant_total = len(deps.get_client().get_projects())
    client.post("/portfolio/refresh")
    page = client.get("/").text

    listed = page.count('<td class="project-name">')
    assert listed < tenant_total
    # The summary bar's denominator is the visible set, not the tenant.
    assert f"of {listed} projects have a SAST baseline" in page
    assert f"of {tenant_total} projects have a SAST baseline" not in page


def test_an_excluded_project_cannot_be_found_by_searching_for_it(client):
    client.post("/portfolio/refresh")
    page = client.get("/", params={"q": "checkout"}).text
    assert BACKUP_NAME not in page


def test_a_converted_original_is_blocked_at_its_own_url(client):
    page = client.get(f"/projects/{BACKUP}")
    assert page.status_code == 200
    assert "already converted" in page.text
    assert "Test Findings Analysis" not in page.text


def test_a_project_already_running_the_capability_is_blocked_at_its_url(client):
    page = client.get(f"/projects/{FA_ENABLED}")
    assert page.status_code == 200
    assert "Findings Analysis already enabled" in page.text
    assert "Test Findings Analysis" not in page.text


def test_a_project_with_an_existing_copy_opens_its_run(client):
    response = client.post(
        "/runs",
        data={"project_id": ANALYSED, "minutes_per_finding": "10", "confirm": "yes"},
        follow_redirects=False,
    )
    # The fixture tenant already holds acme/notifications_FA, so the run itself
    # is refused - that is the guard under test on the write route.
    assert response.status_code == 400
    assert "acme/notifications_FA" in response.json()["detail"]


def test_a_project_with_a_copy_but_no_run_explains_itself(client):
    page = client.get(f"/projects/{ANALYSED}", follow_redirects=False)
    assert page.status_code == 200
    assert "acme/notifications_FA" in page.text
    assert "Test Findings Analysis" not in page.text


def test_a_project_with_a_copy_redirects_to_the_run_that_made_it(client):
    import routes.deps as deps

    store = deps.get_store()
    run_id = store.create_run(
        source_project_id=ANALYSED,
        source_project_name=ANALYSED_NAME,
        baseline_scan_id=None,
        baseline_branch=None,
        minutes_per_finding=10,
        status="completed",
    )
    response = client.get(f"/projects/{ANALYSED}", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"/runs/{run_id}"


def test_a_completed_run_is_preferred_over_a_more_recent_failure(client):
    import routes.deps as deps

    store = deps.get_store()
    completed = store.create_run(
        source_project_id=ANALYSED, source_project_name=ANALYSED_NAME,
        baseline_scan_id=None, baseline_branch=None,
        minutes_per_finding=10, status="completed",
    )
    store.create_run(
        source_project_id=ANALYSED, source_project_name=ANALYSED_NAME,
        baseline_scan_id=None, baseline_branch=None,
        minutes_per_finding=10, status="failed",
    )
    response = client.get(f"/projects/{ANALYSED}", follow_redirects=False)
    assert response.headers["location"] == f"/runs/{completed}"


def test_a_project_whose_every_run_failed_still_leads_to_one(client):
    import routes.deps as deps

    failed = deps.get_store().create_run(
        source_project_id=ANALYSED, source_project_name=ANALYSED_NAME,
        baseline_scan_id=None, baseline_branch=None,
        minutes_per_finding=10, status="failed",
    )
    response = client.get(f"/projects/{ANALYSED}", follow_redirects=False)
    assert response.headers["location"] == f"/runs/{failed}"


def test_a_re_onboarded_project_is_offered_no_further_actions(client):
    import routes.deps as deps

    response = client.post(
        "/runs",
        data={"project_id": WEBGOATNET, "minutes_per_finding": "10", "confirm": "yes"},
        follow_redirects=False,
    )
    run_url = response.headers["location"]
    wait_for_run(client, run_url)

    page = client.get(run_url, params={"view": "reonboard"}).text
    assert "Preview re-onboarding" in page
    assert "Run another comparison" in client.get(run_url).text

    deps.get_store().update_run(run_url.rsplit("/", 1)[-1], reonboard_status="completed")
    page = client.get(run_url, params={"view": "reonboard"}).text
    assert "Preview re-onboarding" not in page
    assert "Run another comparison" not in client.get(run_url).text
    assert "See exactly what was done" in page


def test_an_analysed_project_is_marked_in_the_list(client):
    """The base of an existing _FA pair says so, without opening it."""
    client.post("/portfolio/refresh")
    page = client.get("/").text
    assert "badge-analysed" in page
    row = [line for line in page.splitlines() if ANALYSED_NAME in line]
    assert row, "the analysed project should still be listed"


def test_an_unanalysed_project_carries_no_analysed_badge(client):
    client.post("/portfolio/refresh")
    page = client.get("/", params={"q": "storefront"}).text
    assert "badge-analysed" not in page


# --- manual projects take the rename-only re-onboarding path ------------------

MANUAL = "fixture-legacy-uploader"
MANUAL_NAME = "acme/legacy-uploader"
WEBHOOKED = "fixture-webhook-only"


def completed_run_for(client, project_id: str) -> str:
    response = client.post(
        "/runs",
        data={"project_id": project_id, "confirm": "yes"},
        follow_redirects=False,
    )
    run_url = response.headers["location"]
    assert wait_for_run(client, run_url)["status"] == "completed"
    return run_url


def test_a_manual_project_previews_the_rename_only_path(client):
    page = client.get(f"{completed_run_for(client, MANUAL)}/reonboard").text

    assert "connected to no repository" in page
    assert "/api/scans/rescan" in page
    # The two calls that move a repository must be shown as skipped, not offered.
    assert "Manual project" in page


def test_the_manual_preview_offers_no_conversion_body(client):
    """There is no conversion, so there is no request body to disclose."""
    page = client.get(f"{completed_run_for(client, MANUAL)}/reonboard").text

    assert "The exact request body" not in page
    assert "Protected branches" not in page
    assert "Organisation" not in page


def test_the_manual_confirm_button_says_rename_not_disconnect(client):
    page = client.get(f"{completed_run_for(client, MANUAL)}/reonboard").text

    assert f"Rename {MANUAL_NAME}_FA to {MANUAL_NAME}" in page
    assert "Disconnect" not in page


def test_a_stale_repo_url_does_not_take_a_project_off_the_manual_path(client):
    """The fixture carries one, exactly as `VulnPascal` does on the tenant."""
    from routes.deps import get_client

    project = get_client().get_project(MANUAL)
    assert project["repoUrl"]
    assert not project.get("repoId")

    page = client.get(f"{completed_run_for(client, MANUAL)}/reonboard").text
    assert "connected to no repository" in page


def test_a_webhook_driven_project_is_still_refused(client):
    """No repository record, but its scans are cloned. Must not be renamed."""
    page = client.get(f"{completed_run_for(client, WEBHOOKED)}/reonboard").text

    assert "cannot proceed" in page
    assert "connected to no repository" not in page


def test_a_confirmed_manual_re_onboarding_renames_and_rescans(client):
    import re

    from routes.deps import get_client

    run_url = completed_run_for(client, MANUAL)
    preview = client.get(f"{run_url}/reonboard").text
    digest = re.search(r'name="plan_digest" value="([a-f0-9]+)"', preview).group(1)
    client.post(f"{run_url}/reonboard", data={"confirm": "yes", "plan_digest": digest})

    for _ in range(60):
        payload = client.get(f"{run_url}/reonboard/status").json()
        if payload["done"]:
            break
        time.sleep(0.1)
    assert payload["status"] == "completed"

    fixture = get_client()
    names = {p["id"]: p["name"] for p in fixture.get_projects()}
    assert names[MANUAL] == f"{MANUAL_NAME}_FA_BACKUP"
    assert names[f"fixture-{MANUAL_NAME}_FA"] == MANUAL_NAME
    # Nothing was disconnected and nothing was converted.
    assert fixture._disconnected == set()
    assert fixture._conversions == {}
    assert fixture._rescans == [f"fixture-{MANUAL_NAME}_FA"]

    page = client.get(f"{run_url}/reonboard").text
    assert "Re-onboarding complete" in page
    assert "Neither project is connected to a repository" in page


def test_a_failed_manual_re_onboarding_can_be_resumed(client, monkeypatch):
    """A failed SCM run is frozen; this one is not, and the plan says why.

    Two renames leave nothing pointing anywhere unexpected - the live name is
    simply unclaimed - so re-offering the confirmation is safe in a way that
    re-offering a half-applied conversion would not be.
    """
    import re

    from cx.errors import CxError
    from routes.deps import get_client

    run_url = completed_run_for(client, MANUAL)
    fixture = get_client()
    fa_id = f"fixture-{MANUAL_NAME}_FA"

    real_rename = fixture.rename_project

    def fail_the_second(project_id, name):
        if project_id == fa_id:
            raise CxError("409 name already in use")
        return real_rename(project_id, name)

    monkeypatch.setattr(fixture, "rename_project", fail_the_second)

    preview = client.get(f"{run_url}/reonboard").text
    digest = re.search(r'name="plan_digest" value="([a-f0-9]+)"', preview).group(1)
    client.post(f"{run_url}/reonboard", data={"confirm": "yes", "plan_digest": digest})
    for _ in range(60):
        if client.get(f"{run_url}/reonboard/status").json()["done"]:
            break
        time.sleep(0.1)
    assert client.get(f"{run_url}/reonboard/status").json()["status"] == "failed"

    # The base gave up its name; the live name is unclaimed.
    names = {p["id"]: p["name"] for p in fixture.get_projects()}
    assert names[MANUAL] == f"{MANUAL_NAME}_FA_BACKUP"
    assert names[fa_id] == f"{MANUAL_NAME}_FA"

    # The failure page offers the confirmation again, with the same digest.
    monkeypatch.setattr(fixture, "rename_project", real_rename)
    page = client.get(f"{run_url}/reonboard").text
    assert "Re-onboarding failed" in page
    assert "resume" in page
    resumed = re.search(r'name="plan_digest" value="([a-f0-9]+)"', page).group(1)
    assert resumed == digest

    client.post(f"{run_url}/reonboard", data={"confirm": "yes", "plan_digest": resumed})
    for _ in range(60):
        if client.get(f"{run_url}/reonboard/status").json()["done"]:
            break
        time.sleep(0.1)
    assert client.get(f"{run_url}/reonboard/status").json()["status"] == "completed"
    assert {p["id"]: p["name"] for p in fixture.get_projects()}[fa_id] == MANUAL_NAME


def test_a_failed_scm_re_onboarding_is_still_frozen(client, monkeypatch):
    """The distinction the resume rests on: a conversion must not be re-offered."""
    import re

    from cx.errors import CxError
    from routes.deps import get_client

    run_url = completed_run(client)
    fixture = get_client()
    monkeypatch.setattr(
        fixture, "convert_project",
        lambda payload: (_ for _ in ()).throw(CxError("conversion refused")),
    )

    preview = client.get(f"{run_url}/reonboard").text
    digest = re.search(r'name="plan_digest" value="([a-f0-9]+)"', preview).group(1)
    client.post(f"{run_url}/reonboard", data={"confirm": "yes", "plan_digest": digest})
    for _ in range(60):
        if client.get(f"{run_url}/reonboard/status").json()["done"]:
            break
        time.sleep(0.1)

    page = client.get(f"{run_url}/reonboard").text
    assert "Re-onboarding failed" in page
    assert 'name="plan_digest"' not in page
    assert "Nothing was retried automatically" in page


# --- GOAL_UI_PHASE1: tabs, the parameters panel, and the re-onboarding flag ---


def test_the_default_tab_is_severity(client):
    page = client.get(completed_run(client)).text
    assert "By severity" in page
    assert 'class="tab tab-active"' in page
    assert "not eligible for Findings Analysis" in page      # the severity table
    assert "Which query types were removed" not in page


def test_each_tab_shows_only_its_own_section(client):
    """The point of the change: one section on screen, not five stacked."""
    run_url = completed_run(client)
    severity = "not eligible for Findings Analysis"
    query = "Which query types were removed"
    cwe = "CWE-209"
    audit = "Checkmarx One records the capability"

    on_query = client.get(run_url, params={"view": "query"}).text
    assert query in on_query and severity not in on_query and audit not in on_query

    on_cwe = client.get(run_url, params={"view": "cwe"}).text
    assert cwe in on_cwe and severity not in on_cwe and query not in on_cwe

    on_audit = client.get(run_url, params={"view": "audit"}).text
    assert audit in on_audit and severity not in on_audit and cwe not in on_audit


def test_a_tab_is_a_shareable_url(client):
    """No JavaScript involved: the tab is a link and the URL is the state."""
    run_url = completed_run(client)
    page = client.get(run_url).text
    assert f'href="{run_url}?view=cwe#views"' in page
    # And following it lands on that tab, marked active.
    assert 'aria-current="page"' in client.get(run_url, params={"view": "cwe"}).text


def test_an_unknown_tab_falls_back_rather_than_erroring(client):
    """A stale or mistyped link should show the page, not refuse it."""
    response = client.get(completed_run(client), params={"view": "nonsense"})
    assert response.status_code == 200
    assert "not eligible for Findings Analysis" in response.text


def test_an_empty_breakdown_keeps_its_tab_and_explains_itself(client):
    """The tab bar must not change shape between runs.

    A run recorded before per-finding detail was captured has no query or CWE
    rows. Dropping the tabs would leave two different page layouts; the tab
    stays and says why it is empty.
    """
    import routes.deps as deps

    run_url = completed_run(client)
    deps.get_store().update_run(run_url.rsplit("/", 1)[-1], compare_results=[])

    page = client.get(run_url, params={"view": "query"}).text
    assert "no per-finding detail" in page
    assert "By query" in page                                # the tab is still there


def test_the_old_parity_banner_is_gone(client):
    page = client.get(completed_run(client)).text
    assert 'class="parity-ok' not in page
    assert "Parameter parity:" not in page


def test_the_parameters_table_names_both_projects_and_both_values(client):
    """The badge claims the scans matched; the audit trail shows the evidence."""
    page = client.get(completed_run(client), params={"view": "audit"}).text
    assert "Scan parameters" in page
    assert "rmarquez/WebGoatNet" in page                      # base column head
    assert "rmarquez/WebGoatNet_FA" in page                   # copy column head
    # Findings Analysis differs by design, and both sides are shown saying so.
    assert "<td><code>false</code></td>" in page
    assert "<td><code>true</code></td>" in page
    assert "expected to differ" in page


def test_the_audit_trail_carries_the_scan_identifiers(client):
    import routes.deps as deps

    run_url = completed_run(client)
    run = deps.get_store().get_run(run_url.rsplit("/", 1)[-1])
    page = client.get(run_url, params={"view": "audit"}).text
    for value in (run["baseline_scan_id"], run["fa_scan_id"], run["fa_project_id"]):
        assert value in page
    assert run["baseline_branch"] in page


def test_a_run_without_a_parity_report_renders_no_panel(client):
    """Runs recorded before the check existed: no panel beats an empty one."""
    import routes.deps as deps

    run_url = completed_run(client)
    deps.get_store().update_run(run_url.rsplit("/", 1)[-1], parity_report=None)
    assert client.get(run_url).status_code == 200
    assert "Scan parameters" not in client.get(
        run_url, params={"view": "audit"}
    ).text


# -- the REONBOARD flag --------------------------------------------------------


def test_the_reonboard_tab_is_disabled_when_the_flag_is_off(client_no_beta):
    page = client_no_beta.get(completed_run(client_no_beta)).text
    assert 'class="tab tab-disabled"' in page
    assert "Beta" in page
    # Greyed out, and silent about why - a tooltip naming the env var would put
    # the deployment's configuration in front of someone who cannot change it.
    assert "title=" not in page.split("tab-disabled", 1)[1].split(">", 1)[0]
    # Disabled means no link to it anywhere on the page.
    assert "?view=reonboard" not in page
    assert "Preview re-onboarding" not in page


def test_the_reonboard_routes_refuse_when_the_flag_is_off(client_no_beta):
    """Greying out a tab is presentation. These are the control.

    A bookmarked URL or a replayed form reaches the route without ever seeing
    the tab, and the route is what disconnects a live project.
    """
    run_url = completed_run(client_no_beta)
    assert client_no_beta.get(f"{run_url}/reonboard").status_code == 404
    assert client_no_beta.get(f"{run_url}/reonboard/status").status_code == 404
    assert client_no_beta.post(
        f"{run_url}/reonboard", data={"confirm": "yes", "plan_digest": "x"}
    ).status_code == 404


def test_linking_to_the_disabled_tab_falls_back_to_severity(client_no_beta):
    """No dead tab to land on, so the link resolves somewhere real."""
    response = client_no_beta.get(
        completed_run(client_no_beta), params={"view": "reonboard"}
    )
    assert response.status_code == 200
    assert "not eligible for Findings Analysis" in response.text
    assert "Preview re-onboarding" not in response.text


def test_the_flag_changes_nothing_else_on_the_page(client_no_beta):
    """A disabled beta must not cost the operator the measurement."""
    run_url = completed_run(client_no_beta)
    page = client_no_beta.get(run_url).text
    assert "Parameters match baseline" in page
    assert "43.0" in page
    assert "Scan parameters" in client_no_beta.get(
        run_url, params={"view": "audit"}
    ).text


# --- the page leads with the numbers, not with a banner -----------------------

VIEWS = ("severity", "query", "cwe", "audit", "reonboard")


def test_the_benefit_banner_is_gone(client):
    """It repeated on every view and pushed the tabs below the fold."""
    run_url = completed_run(client)
    for view in VIEWS:
        page = client.get(run_url, params={"view": view}).text
        assert 'class="benefit"' not in page
        assert "What re-onboarding gets you" not in page
        assert "this saving is hypothetical" not in page


def test_the_headline_frames_the_decision_not_the_experiment(client):
    page = client.get(completed_run(client)).text
    assert "What you gain by re-onboarding" in page


def test_the_hero_is_followed_straight_by_the_tabs(client):
    """Nothing between the figures and the tab bar any more."""
    page = client.get(completed_run(client)).text
    assert page.index("findings left to triage") < page.index('class="tabs subtabs')


def test_the_ongoing_rate_qualifies_the_severity_table(client):
    """It explains those counts, so it belongs with them and nowhere else."""
    run_url = completed_run(client)
    page = client.get(run_url, params={"view": "severity"}).text
    assert "15.5" in page                       # NEW share of the original baseline
    assert "not the whole backlog again" in page
    assert "not the whole backlog again" not in client.get(
        run_url, params={"view": "cwe"}
    ).text


def test_the_preview_action_lives_in_the_reonboard_tab(client):
    """With the pitch gone the button sits with the mechanics it describes."""
    run_url = completed_run(client)
    assert "Preview re-onboarding" not in client.get(run_url).text
    assert "Preview re-onboarding" in client.get(
        run_url, params={"view": "reonboard"}
    ).text


def test_no_view_tells_the_reader_how_to_enable_re_onboarding(client, client_no_beta):
    """How the deployment is configured is not this reader's business.

    They cannot act on it, and naming the variable invites asking someone to
    switch on a flow that disconnects a live project.
    """
    for c in (client, client_no_beta):
        run_url = completed_run(c)
        for view in VIEWS:
            assert "REONBOARD" not in c.get(run_url, params={"view": view}).text


def test_a_re_onboarded_run_says_so_in_its_tab(client):
    import routes.deps as deps

    run_url = completed_run(client)
    deps.get_store().update_run(run_url.rsplit("/", 1)[-1], reonboard_status="completed")
    page = client.get(run_url, params={"view": "reonboard"}).text
    assert "Already re-onboarded" in page
    assert "See exactly what was done" in page
    assert "Preview re-onboarding" not in page


def test_the_reonboard_tab_carries_the_mechanics_and_one_action(client):
    page = client.get(completed_run(client), params={"view": "reonboard"}).text
    assert "How re-onboarding works" in page
    assert "_FA_BACKUP" in page                       # the actual steps
    assert page.count("Preview re-onboarding") == 1


def test_the_tab_does_not_promise_calls_the_flow_no_longer_makes(client):
    """The step list is hand-written, so nothing made it follow the code.

    It went stale the moment the post-conversion scanner PATCH and rescan were
    dropped in favour of the conversion scanning the branch itself, and the one
    tab whose job is saying what will happen was saying the wrong thing.
    """
    page = client.get(completed_run(client), params={"view": "reonboard"}).text
    assert "licensed for is switched on" not in page
    assert "Best effort" not in page
    assert "that same call scans the branch" in page


# --- switching tabs keeps the reader's place ----------------------------------


def test_every_tab_link_anchors_the_tab_bar(client):
    """A tab is a full navigation, so without this the browser jumps to the top."""
    page = client.get(completed_run(client)).text
    assert 'class="tabs subtabs no-print" id="views"' in page
    for view in VIEWS:
        assert f"?view={view}#views" in page


def test_the_anchored_nav_is_not_flush_against_the_viewport(client):
    css = client.get("/static/app.css").text
    subtabs = css.split(".subtabs {", 1)[1].split("}", 1)[0]
    assert "scroll-margin-top" in subtabs


def test_the_parameters_no_longer_compete_with_the_numbers(client):
    """The panel was the complaint: it pushed the result down the page."""
    page = client.get(completed_run(client)).text
    for label in ("Fast scan mode", "Recommended exclusions", "LLM-based scanning"):
        assert label not in page
    assert "Baseline scan" not in page
    # Still one line saying the comparison is sound.
    assert "Parameters match baseline" in page


# --- progress feedback on slow actions ----------------------------------------


def test_every_page_carries_the_progress_script(client):
    """It lives in the layout, so a page cannot forget to include it."""
    for path in ("/", "/runs", "/settings"):
        assert "page-progress" in client.get(path).text


def test_a_page_with_its_own_poller_still_gets_it(client):
    """`{% block scripts %}` is overridden by the polling pages.

    The progress script sits outside that block for exactly this reason - a
    page that defines its own script must not silently lose it.
    """
    response = client.post(
        "/runs", data={"project_id": WEBGOATNET, "confirm": "yes"},
        follow_redirects=False,
    )
    page = client.get(response.headers["location"]).text
    assert "page-progress" in page


def test_the_slow_actions_say_how_long_they_take(client):
    """A spinner says "happening"; these say "and it will be a while"."""
    client.post("/portfolio/refresh")
    assert "around ten seconds" in client.get("/").text

    page = client.get(completed_run(client), params={"view": "reonboard"}).text
    assert "busy-note" in page
    assert "can take a few seconds" in page


def test_the_busy_notes_are_hidden_until_the_action_starts(client):
    """Printed up front they are noise; after the click they answer "is it stuck?"."""
    css = client.get("/static/app.css").text
    assert ".busy-note { display: none; }" in css
    assert ".busy-note.is-visible { display: block; }" in css


def test_the_preview_link_names_its_note_rather_than_relying_on_position(client):
    page = client.get(completed_run(client), params={"view": "reonboard"}).text
    assert 'data-busy-note="reonboard-wait"' in page
    assert 'id="reonboard-wait"' in page


def test_the_spinner_respects_reduced_motion(client):
    """The animation is the message, so it is replaced rather than cancelled."""
    css = client.get("/static/app.css").text
    reduced = css.split("prefers-reduced-motion", 1)[1]
    assert ".spinner" in reduced
    assert "pulse" in reduced


def test_the_page_still_works_without_javascript(client):
    """Progressive enhancement: nothing is wired through a click handler.

    Every action is a real form or a real link, so the spinner is decoration on
    top of a page that already worked.
    """
    page = client.get("/").text
    assert '<form method="post" action="/portfolio/refresh"' in page
    assert "onclick" not in page.split("<script>")[0]
