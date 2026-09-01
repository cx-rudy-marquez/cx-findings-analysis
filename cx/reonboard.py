"""[BETA] Moving a repository from the base project to its `_FA` copy.

This is the second module in the project that writes to a tenant, and the only
one that changes state a tenant did not ask this tool to create. `cx/flow.py`
creates its own `_FA` project and scans it; this touches a project the customer
already had, and detaches it from its repository.

Two calls, in this order, and the order is forced:

1. `POST /api/repos-manager/projects/{base}/disconnect` - the base becomes a
   manual project. Its scan history is preserved and its webhook is removed.
2. `POST /api/repos-manager/project-conversion` - the `_FA` copy is connected to
   the repository the base just released, and polled to completion.

The base project is **never deleted**. There is no delete call anywhere in this
project, and this module does not add one.

Nothing here fires without an operator confirming a dry-run preview that names
both project ids and shows the exact conversion payload, and the digest of that
preview is checked again at execution time. `analysis/reonboard.py` builds the
plan; this module only reads the tenant to feed it, then executes what was
approved.

Failure is not retried. A conversion that failed after the disconnect landed has
left the tenant in a state a human needs to look at, and quietly trying again
would either double-submit or bury that fact.

A project connected to no repository takes a different path entirely - two
renames and a rescan, no disconnect and no conversion, because there is nothing
to disconnect from and nothing to connect to. That path *is* resumable: a
half-applied pair of renames leaves a named, recognisable state and no
repository pointing anywhere unexpected. See `_run_manual_reonboard`, and
`analysis/reonboard.py:is_manual_project` for what earns it.
"""

from __future__ import annotations

import logging
import time

from analysis.reonboard import (
    ReonboardPlan,
    build_plan,
    is_manual_project,
    is_proxy_base,
    plan_to_json,
)
from config import (
    FA_BACKUP_SUFFIX,
    FA_PROJECT_SUFFIX,
    Settings,
    settings as default_settings,
)
from cx.client import CxApiClient
from cx.errors import CxError
from store import Store

log = logging.getLogger(__name__)

#: Give up watching a conversion after this long. The process is not cancelled -
#: it may still finish - but the dashboard stops holding a worker for it.
MAX_CONVERSION_SECONDS = 15 * 60

#: `migrationStatus` values that mean the process has stopped moving.
TERMINAL_CONVERSION_STATUSES = frozenset({"OK", "PARTIAL", "FAILURE"})

#: Re-onboarding lifecycle, stored on the run's `reonboard_status`.
PREVIEWED = "previewed"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"


class ReonboardAborted(CxError):
    """A precondition failed. Nothing further may be written to the tenant."""


def _integration_for(
    client: CxApiClient, scms: list[dict], project_name: str
) -> tuple[dict | None, list[str]]:
    """The integration a project is connected through, and its project list.

    Found by **membership**, not by URL, and across *every* integration rather
    than stopping at the first one whose type looks right. A tenant routinely
    has several integrations of one type - on a live tenant, four Checkmarx-
    proxied GitLab entries alongside the cloud one - and their `repoBaseUrl`
    values cannot tell them apart. Asking each integration which projects it
    owns is the only reliable answer, and it yields the connected-project count
    the safety check needs anyway.

    When more than one integration claims the project, a directly-addressed one
    wins over a Checkmarx-proxied one: if a cloud integration genuinely lists
    the project, its own hostname is the better address to convert to.
    """
    matches: list[tuple[dict, list[str]]] = []
    for scm in scms:
        try:
            names = client.list_scm_projects(scm.get("id"))
        except CxError:
            # One unreadable integration must not hide a match in another.
            continue
        if project_name in names:
            matches.append((scm, names))

    if not matches:
        return None, []
    for scm, names in matches:
        if not is_proxy_base(scm):
            return scm, names
    return matches[0]


def handler_repo_url(client: CxApiClient, scan_id: str | None) -> str:
    """The repository URL recorded in a scan's own git handler.

    The authoritative answer to "what does Checkmarx clone for this project".
    `GET /api/projects/{id}` reports an empty `repoUrl` for every project
    connected through a Code Repository integration, and the integration
    listings proved incomplete on a live tenant - this field was the only source
    that produced the real address.
    """
    if not scan_id:
        return ""
    try:
        metadata = client.get_scan(scan_id).get("metadata") or {}
    except CxError:
        return ""
    handler = metadata.get("Handler") or metadata.get("handler") or {}
    for key in ("GitHandler", "gitHandler"):
        url = (handler.get(key) or {}).get("repo_url")
        if url:
            return str(url)
    return ""


def _org_peers(client: CxApiClient, base_project: dict, repo_url: str) -> list[str]:
    """Other projects connected to the same host and organisation.

    This is what decides whether a disconnect strips the credential the
    conversion borrows, and it deliberately does not use
    `scms/{id}/projects`: on a live tenant that endpoint returned an empty list
    for an integration with seventeen projects behind it, which would have
    blocked a perfectly safe re-onboarding - or, worse, mis-stated the risk.

    Costs one scan-metadata read per same-origin project. Only the preview pays
    it, and being wrong here is the expensive outcome.
    """
    prefix = "/".join(repo_url.split("/")[:4])
    if not prefix or repo_url.count("/") < 3:
        return []
    origin = (base_project.get("origin") or "").strip().lower()
    peers: list[str] = []
    try:
        projects = client.get_projects()
    except CxError:
        return []
    for project in projects:
        if project.get("id") == base_project.get("id"):
            continue
        if (project.get("origin") or "").strip().lower() != origin:
            continue
        try:
            scan = client.get_last_sast_scan(project["id"])
        except CxError:
            continue
        url = handler_repo_url(client, (scan or {}).get("id"))
        if url and url.startswith(prefix + "/"):
            peers.append(project.get("name") or project["id"])
    return peers


def preview(client: CxApiClient, run: dict) -> ReonboardPlan:
    """Build the dry-run plan. Reads only - nothing here writes to the tenant.

    Deliberately tolerant: every read that fails degrades into a blocker on the
    plan rather than an exception, because the preview's job is to explain why a
    re-onboarding cannot proceed just as much as to describe one that can.
    """
    base_id = run.get("source_project_id") or ""
    candidate_id = run.get("fa_project_id") or ""
    if not candidate_id:
        raise ReonboardAborted(
            "This run never created a Findings Analysis project, so there is "
            "nothing to connect the repository to."
        )

    base_project = client.get_project(base_id)

    # Read live, like the base project's, rather than taken from the run row.
    # The stored name is what the copy was called when it was created, and a
    # re-onboarding that failed between its two renames has moved it since -
    # planning against the stale name would report the live name as taken by a
    # stranger, when the stranger is this project.
    try:
        candidate_name = (
            (client.get_project(candidate_id) or {}).get("name")
            or run.get("fa_project_name")
            or candidate_id
        )
    except CxError:
        candidate_name = run.get("fa_project_name") or candidate_id

    baseline_scan = {}
    baseline_scan_id = run.get("baseline_scan_id")
    if baseline_scan_id:
        try:
            baseline_scan = client.get_scan(baseline_scan_id)
        except CxError:
            # The engine list and sourceType are advisory; their absence shows
            # up as a narrower plan, not as a failure to produce one.
            baseline_scan = {}

    scms: list[dict] = []
    try:
        scms = client.list_scms()
    except CxError:
        scms = []

    integration, listed = _integration_for(
        client, scms, base_project.get("name") or ""
    )
    repo_url = handler_repo_url(client, baseline_scan.get("id"))

    base_name = base_project.get("name") or ""
    # Only read when the project already looks manual on every cheaper signal.
    # For the 30 connected projects on the reference tenant this call never
    # happens; for the rest it is one page of scan rows.
    recent_scans: list[dict] = []
    history_unreadable = False
    if not (base_project.get("repoId") or base_project.get("scmRepoId")):
        try:
            recent_scans = client.get_recent_scans(base_id)
        except CxError:
            # An unreadable history is not evidence of anything, least of all
            # that nothing was ever cloned. Refusing the rename path is the safe
            # way to be wrong: the project stays as stuck as it is today.
            history_unreadable = True
            log.warning(
                "Could not read scan history for %s, so it is not treated as "
                "manual", base_id
            )
    manual = not history_unreadable and is_manual_project(
        base_project,
        integration=integration,
        handler_repo_url=repo_url,
        recent_scans=recent_scans,
    )

    # Everything below this point exists to satisfy `project-conversion`, and a
    # manual project is never converted. `_org_peers` in particular walks every
    # project in the tenant reading scan metadata, purely to count the projects
    # that could lend the conversion a credential - so skipping it is the
    # difference between a cheap manual preview and an expensive pointless one.
    connected: list[str] = [base_name]
    protected: list[dict] = []
    licensed: tuple[str, ...] = ()
    if not manual:
        # The integration listing is a hint, not the truth. The peers derived
        # from scan handlers are, so the two are unioned and the base is always
        # counted.
        connected = list(dict.fromkeys(
            [base_name] + list(listed) + _org_peers(client, base_project, repo_url)
        ))
        try:
            protected = client.get_protected_branches(base_name)
        except CxError:
            protected = []
        # Disclosed in the preview, not enforced by it: the scanners the
        # follow-up step will try to enable once the conversion has finished.
        try:
            licensed = client.licensed_engines()
        except Exception:  # noqa: BLE001 - disclosure only, never load-bearing
            # This list is shown in the preview and nothing else reads it. A plan
            # that could not be produced because a cosmetic field was unreadable
            # would be a worse outcome than a plan that omits it.
            licensed = ()

    # Both renames need somewhere to land, so the plan checks the names it
    # intends to use are free before anything is written. Needed on both paths -
    # the manual one renames too.
    try:
        existing_names = [p.get("name") or "" for p in client.get_projects()]
    except CxError:
        existing_names = []

    return build_plan(
        base_project=base_project,
        candidate_project_id=candidate_id,
        candidate_project_name=candidate_name,
        baseline_scan=baseline_scan,
        baseline_branch=run.get("baseline_branch"),
        protected_branches=protected,
        scms=scms,
        connected_project_names=connected,
        integration=integration,
        handler_repo_url=repo_url,
        existing_project_names=existing_names,
        licensed_scanners=licensed,
        manual=manual,
    )


def run_reonboard(
    run_id: str,
    store: Store,
    client: CxApiClient,
    expected_digest: str,
    settings: Settings | None = None,
) -> None:
    """Execute an approved plan, journalling each step. Never raises.

    Like `cx/flow.py:run_flow`, this runs as a background task: an exception
    escaping into the event loop would leave the re-onboarding stuck at
    `running` with no explanation of what it did or did not do to the tenant.
    """
    settings = settings or default_settings
    step = store.log_step
    # What has actually landed in the tenant, for the failure message. Getting
    # this wrong is worse than the failure itself: someone has to know exactly
    # how far a half-applied re-onboarding got.
    done: list[str] = []
    # Decides which recovery advice the failure message carries. A manual run
    # never disconnects anything, so the SCM tail would be actively misleading.
    manual = False

    try:
        run = store.get_run(run_id)
        if not run:
            raise ReonboardAborted(f"Run {run_id} no longer exists.")

        # The plan is rebuilt from the tenant rather than replayed from storage.
        # A stored plan describes a tenant as it was; if anything has moved
        # since - the repo reconnected elsewhere, a branch added - the operator
        # approved something that is no longer true.
        plan = preview(client, run)
        if plan.digest() != expected_digest:
            raise ReonboardAborted(
                "The tenant has changed since this preview was generated, so "
                "the plan you approved no longer matches what would happen. "
                "Nothing has been changed. Review the new preview and confirm "
                "again."
            )
        if not plan.executable:
            raise ReonboardAborted(plan.blockers[0].message)

        manual = plan.manual
        if manual:
            # A different flow entirely: no repository moves, so none of the
            # ordering hazards below apply and none of their calls are made.
            _run_manual_reonboard(run_id, store, client, plan, done)
            return

        store.update_run(
            run_id,
            reonboard_status=RUNNING,
            reonboard_plan=plan_to_json(plan),
            reonboard_result={"phase": "disconnecting base project"},
        )

        step(run_id, "reonboard-disconnect", "attempting",
             f"{plan.base_project_name} ({plan.base_project_id})")
        client.disconnect_project(plan.base_project_id)
        done.append(
            f"'{plan.base_project_name}' was disconnected from its repository "
            "and is now a manual project"
        )
        step(run_id, "reonboard-disconnect", "ok",
             f"{plan.base_project_name} is now a manual project; history "
             "preserved, webhook removed, project not deleted")

        # The base gives up its name only after it has given up the repository,
        # and the copy takes that name only once it is free. Both renames touch
        # nothing but the name: same ids, same scans, same configuration.
        store.update_run(
            run_id, reonboard_result={"phase": "renaming base project"}
        )
        step(run_id, "reonboard-rename-base", "attempting",
             f"{plan.base_project_name} -> {plan.base_backup_name}")
        client.rename_project(plan.base_project_id, plan.base_backup_name)
        done.append(
            f"the base project was renamed to '{plan.base_backup_name}' "
            f"(id {plan.base_project_id}, history intact)"
        )
        step(run_id, "reonboard-rename-base", "ok", plan.base_backup_name)

        store.update_run(
            run_id, reonboard_result={"phase": "renaming candidate project"}
        )
        step(run_id, "reonboard-rename-candidate", "attempting",
             f"{plan.candidate_project_name} -> {plan.candidate_final_name}")
        client.rename_project(plan.candidate_project_id, plan.candidate_final_name)
        done.append(
            f"the Findings Analysis copy was renamed to "
            f"'{plan.candidate_final_name}' (id {plan.candidate_project_id})"
        )
        step(run_id, "reonboard-rename-candidate", "ok", plan.candidate_final_name)

        store.update_run(
            run_id, reonboard_result={"phase": "converting candidate project"}
        )
        step(run_id, "reonboard-convert", "attempting",
             f"{plan.candidate_final_name} -> {plan.repo_url}")
        response = client.convert_project(plan.conversion_payload())
        process_id = response.get("processId")
        if not process_id:
            raise ReonboardAborted(
                "The conversion was accepted but returned no processId, so its "
                "outcome cannot be confirmed. Check the project in Checkmarx "
                "One before doing anything else."
            )
        step(run_id, "reonboard-convert", "ok", f"process {process_id}")
        store.update_run(
            run_id,
            reonboard_result={
                "phase": "polling conversion",
                "process_id": process_id,
            },
        )

        status = _poll_conversion(run_id, client, store, process_id, settings)
        migration_status = status.get("migrationStatus")
        failed_projects = status.get("failedProjectList") or []

        if migration_status == "OK" and not failed_projects:
            store.update_run(
                run_id,
                reonboard_status=COMPLETED,
                reonboard_result={
                    "phase": "complete",
                    "process_id": process_id,
                    "status": status,
                    "base_project_id": plan.base_project_id,
                    "base_project_name": plan.base_backup_name,
                    "base_original_name": plan.base_project_name,
                    "candidate_project_id": plan.candidate_project_id,
                    "candidate_project_name": plan.candidate_final_name,
                    "candidate_original_name": plan.candidate_project_name,
                    "repo_url": plan.repo_url,
                },
            )
            step(run_id, "reonboard", "ok",
                 f"{plan.candidate_final_name} is connected to {plan.repo_url}, "
                 f"and scanning {plan.baseline_branch or 'its default branch'} "
                 "as part of the conversion")
            return

        raise ReonboardAborted(
            f"The conversion finished as '{migration_status}'. "
            + (status.get("summary") or "")
            + (f" Failed: {failed_projects}" if failed_projects else "")
        )

    except Exception as exc:  # noqa: BLE001 - every failure must be recorded
        message = str(exc)
        log.exception("Re-onboarding for run %s failed", run_id)
        # The single most important thing to say. A re-onboarding that fails
        # part-way leaves the tenant in a state someone has to resolve by hand,
        # and exactly which steps landed decides what they have to do.
        if done and manual:
            applied = "".join(f"\n  - {item}" for item in done)
            message = (
                f"{message}\n\nThis failed part-way. Already applied:{applied}"
                "\n\nNothing was deleted. No repository is involved, so nothing "
                "is disconnected and no pushes are going anywhere unexpected - "
                "the only thing outstanding is the second rename, and the live "
                "name is currently unclaimed. Re-run this re-onboarding to "
                "resume: it reads both names first and picks up from the rename "
                "that did not land."
            )
        elif done:
            applied = "".join(f"\n  - {item}" for item in done)
            message = (
                f"{message}\n\nThis failed part-way. Already applied:{applied}"
                "\n\nNothing was deleted and nothing was retried automatically. "
                "The repository is currently connected to no Checkmarx project, "
                "so reconnect it in Checkmarx One - to the copy if you want the "
                "re-onboarding, or to the original if you want to undo it. Both "
                "projects still exist with their full scan history."
            )
        store.log_step(run_id, "reonboard", "failed", message)
        store.update_run(
            run_id,
            reonboard_status=FAILED,
            reonboard_result={
                "phase": "failed",
                "error": message,
                "base_disconnected": bool(done),
                "applied_steps": list(done),
            },
        )


#: Pre-flight verdicts for a manual re-onboarding.
FRESH = "fresh"
BASE_RENAMED = "base-renamed"
ALREADY_APPLIED = "already-applied"


def _current_name(client: CxApiClient, project_id: str) -> str:
    return str((client.get_project(project_id) or {}).get("name") or "")


def _manual_state(client: CxApiClient, plan: ReonboardPlan) -> str:
    """Which of the two renames are still outstanding, read from the tenant.

    Decided on the **suffixes**, not on the plan's own name fields. The plan is
    built from whatever the tenant currently reports, and `backup_name_for` is
    idempotent, so a base that has already been renamed reports a
    `base_project_name` and a `base_backup_name` that are the same string - the
    plan cannot tell a fresh run from a resumed one. The suffixes can, and they
    need no memory of what anything used to be called.

    Everything that is not one of the three known states aborts before a single
    write. A pair of names that contradict each other did not get that way
    through this flow, and renaming blind against it is how a project ends up
    with a name nobody chose.
    """
    base = _current_name(client, plan.base_project_id)
    candidate = _current_name(client, plan.candidate_project_id)
    base_renamed = base.endswith(FA_BACKUP_SUFFIX)
    candidate_renamed = not candidate.endswith(FA_PROJECT_SUFFIX)

    if not base_renamed and not candidate_renamed:
        return FRESH
    if base_renamed and not candidate_renamed:
        if candidate == plan.candidate_project_name:
            return BASE_RENAMED
    elif base_renamed and candidate == plan.candidate_final_name:
        return ALREADY_APPLIED

    raise ReonboardAborted(
        "The two projects are not in a state this re-onboarding recognises, so "
        f"nothing was renamed. It expected the copy to be '{plan.candidate_project_name}' "
        f"with the rename outstanding, or '{plan.candidate_final_name}' with it "
        f"already applied; the tenant reports '{base}' and '{candidate}'. "
        "Resolve the names in Checkmarx One and preview this again."
    )


def _rename_and_verify(client: CxApiClient, project_id: str, name: str) -> None:
    """Rename, then read the name back before anything else is written.

    `PATCH /api/projects/{id}` answers 204 with no body, so the only way to know
    it landed is to ask. The goal requires it explicitly, and the reason is the
    next call: firing the second rename on the strength of an unverified first
    is how both projects end up holding the wrong names.
    """
    client.rename_project(project_id, name)
    actual = _current_name(client, project_id)
    if actual != name:
        raise ReonboardAborted(
            f"Renaming project {project_id} to '{name}' reported success, but it "
            f"still reads as '{actual}'. Nothing further was attempted."
        )


def _run_manual_reonboard(
    run_id: str,
    store: Store,
    client: CxApiClient,
    plan: ReonboardPlan,
    done: list[str],
) -> None:
    """The reduced path for a project connected to no repository.

    Two renames swap the live name onto the `_FA` copy, then one rescan. No
    disconnect, no conversion, no scanner settings - there is no repository for
    any of them to act on, and each is journalled as skipped with the reason so
    the trail reads the same way an SCM re-onboarding's does.

    Raises on a rename failure, which the caller records as a failed run. That
    is deliberate: unlike the rescan, an unfinished rename leaves the live name
    unclaimed, and the goal calls that blocking and retryable rather than a
    warning.
    """
    step = store.log_step

    state = _manual_state(client, plan)
    step(run_id, "reonboard-preflight", "ok", {
        FRESH: "both projects hold their original names",
        BASE_RENAMED: (
            f"'{plan.base_backup_name}' is already renamed; resuming from the "
            "second rename"
        ),
        ALREADY_APPLIED: "both renames already landed; only the rescan is left",
    }[state])

    step(run_id, "reonboard-disconnect", "skipped",
         "manual project: connected to no repository, so there is no webhook or "
         "connection to remove")

    store.update_run(
        run_id,
        reonboard_status=RUNNING,
        reonboard_plan=plan_to_json(plan),
        reonboard_result={"phase": "renaming base project"},
    )

    if state == FRESH:
        step(run_id, "reonboard-rename-base", "attempting",
             f"{plan.base_project_name} -> {plan.base_backup_name}")
        _rename_and_verify(client, plan.base_project_id, plan.base_backup_name)
        done.append(
            f"the base project was renamed to '{plan.base_backup_name}' "
            f"(id {plan.base_project_id}, history intact)"
        )
        step(run_id, "reonboard-rename-base", "ok", plan.base_backup_name)
    else:
        step(run_id, "reonboard-rename-base", "skipped",
             f"already renamed to {plan.base_backup_name} by an earlier attempt")

    store.update_run(
        run_id, reonboard_result={"phase": "renaming candidate project"}
    )
    if state == ALREADY_APPLIED:
        step(run_id, "reonboard-rename-candidate", "skipped",
             f"already renamed to {plan.candidate_final_name} by an earlier attempt")
    else:
        step(run_id, "reonboard-rename-candidate", "attempting",
             f"{plan.candidate_project_name} -> {plan.candidate_final_name}")
        _rename_and_verify(
            client, plan.candidate_project_id, plan.candidate_final_name
        )
        done.append(
            f"the Findings Analysis copy was renamed to "
            f"'{plan.candidate_final_name}' (id {plan.candidate_project_id})"
        )
        step(run_id, "reonboard-rename-candidate", "ok", plan.candidate_final_name)

    step(run_id, "reonboard-convert", "skipped",
         "manual project: there is no repository to connect the copy to")

    store.update_run(
        run_id,
        reonboard_status=COMPLETED,
        reonboard_result={
            "phase": "complete",
            "manual": True,
            "base_project_id": plan.base_project_id,
            "base_project_name": plan.base_backup_name,
            "base_original_name": plan.base_project_name,
            "candidate_project_id": plan.candidate_project_id,
            "candidate_project_name": plan.candidate_final_name,
            "candidate_original_name": plan.candidate_project_name,
            "repo_url": "",
        },
    )
    step(run_id, "reonboard", "ok",
         f"{plan.candidate_final_name} now holds the live name; "
         f"{plan.base_backup_name} keeps its history")

    # Past this point the re-onboarding is recorded as complete, exactly as on
    # the SCM path. Nothing here may reopen that.
    try:
        rescan = _rescan_manual(run_id, store, client, plan)
        result = (store.get_run(run_id) or {}).get("reonboard_result") or {}
        store.update_run(run_id, reonboard_result={**result, "rescan": rescan})
    except Exception as exc:  # noqa: BLE001 - must not reopen a done run
        log.exception("Post-rename rescan for run %s failed", run_id)
        store.log_step(run_id, "rescan", "warn", str(exc))


def _rescan_manual(
    run_id: str, store: Store, client: CxApiClient, plan: ReonboardPlan
) -> dict:
    """Re-run the copy's existing source under its new name. Best effort.

    `POST /api/scans/rescan` re-runs the origin scan's retained source - a scan
    of `type: "rescan"` whose handler names the scan it came from - so nothing is
    downloaded or uploaded. Confirmed against a manual project on the reference
    tenant, which carries exactly such a scan.

    The scanner-settings step has no equivalent here and is journalled as
    skipped: a manual project has no `repoId`, so there is no repository
    settings document to change, and the scan runs with whatever the Findings
    Analysis comparison configured.
    """
    step = store.log_step
    outcome: dict = {"warnings": [], "manual": True}

    step(run_id, "rescan-settings", "skipped",
         "manual project: no repoId, so the scanners stay as the comparison run "
         "configured them")

    try:
        step(run_id, "rescan-trigger", "attempting", plan.candidate_project_id)
        response = client.rescan_project(plan.candidate_project_id)
        outcome["rescan_response"] = response
        scan_id = (response or {}).get("id") or (response or {}).get("scanId")
        outcome["scan_id"] = scan_id
        step(run_id, "rescan-trigger", "ok",
             f"scan {scan_id}" if scan_id else "queued")
    except CxError as exc:
        detail = f"no fresh scan was queued: {exc}"
        outcome["warnings"].append(detail)
        step(run_id, "rescan-trigger", "warn", detail)
        log.warning("Post-rename rescan for run %s: %s", run_id, detail)

    return outcome


def _poll_conversion(
    run_id: str,
    client: CxApiClient,
    store: Store,
    process_id: str,
    settings: Settings,
) -> dict:
    started = time.monotonic()
    while True:
        status = client.get_conversion_status(process_id)
        migration_status = status.get("migrationStatus") or "UNKNOWN"
        store.update_run(
            run_id,
            reonboard_result={
                "phase": f"conversion {migration_status.lower()}",
                "process_id": process_id,
                "status": status,
            },
        )
        if migration_status in TERMINAL_CONVERSION_STATUSES:
            store.log_step(
                run_id, "reonboard-status", migration_status.lower(),
                status.get("summary") or process_id,
            )
            return status

        if time.monotonic() - started > MAX_CONVERSION_SECONDS:
            raise ReonboardAborted(
                f"Stopped waiting for conversion {process_id} after "
                f"{MAX_CONVERSION_SECONDS // 60} minutes. It was left running - "
                "check it in Checkmarx One."
            )
        time.sleep(settings.poll_interval_seconds)
