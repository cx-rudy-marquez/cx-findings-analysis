"""Executing the rename-only re-onboarding, driven by a fake client.

Three properties matter more than the rest and are asserted directly: the SCM
calls are never made, each rename is verified before the next one fires, and a
half-applied pair of renames can be resumed without repeating the one that
landed.
"""

import pytest

from config import Settings
from cx import reonboard
from cx.errors import CxError
from store import COMPLETED, Store

#: Zero poll interval, matching tests/test_reonboard_flow.py. Nothing here
#: polls, but a stray sleep in a shared code path must not cost eight seconds.
SETTINGS = Settings(poll_interval_seconds=0)

BASE_NAME = "VISLab"
FA_NAME = "VISLab_FA"
BACKUP_NAME = "VISLab_FA_BACKUP"


class ManualClient:
    """A project connected to no repository, and the tenant around it.

    Renames mutate the recorded names, so a test can read back exactly what the
    tenant would report - which is the whole point of the read-back the flow
    performs between the two writes.
    """

    def __init__(self, **overrides):
        self.calls = []
        self.names = dict(overrides.get(
            "names", {"base-1": BASE_NAME, "fa-1": FA_NAME}
        ))
        self.rename_errors = dict(overrides.get("rename_errors", {}))
        #: Renames that report success but do not actually take effect.
        self.silent_renames = set(overrides.get("silent_renames", ()))
        self.rescan_error = overrides.get("rescan_error")
        #: `sourceType` of the project's recent scans. Uploads and rescans mean
        #: Checkmarx has never cloned this project's source.
        self.source_types = list(
            overrides.get("source_types", ["rescan", "zip"])
        )
        self.renames = []
        self.rescans = []

    # -- reads

    def get_project(self, project_id):
        self.calls.append(f"get_project:{project_id}")
        return {"id": project_id, "name": self.names[project_id], "repoUrl": ""}

    def get_projects(self):
        return [{"id": pid, "name": name} for pid, name in self.names.items()]

    def get_scan(self, scan_id):
        # An uploaded archive: no git handler, which is what marks the project
        # as untied to source control.
        return {"id": scan_id, "engines": ["sast"],
                "metadata": {"Handler": {"UploadHandler": {"branch": "master"}}}}

    def get_recent_scans(self, project_id, limit=20):
        self.calls.append("get_recent_scans")
        return [{"id": f"s-{i}", "sourceType": t}
                for i, t in enumerate(self.source_types)]

    def list_scms(self):
        self.calls.append("list_scms")
        return [{"id": 7, "type": "github", "repoBaseUrl": "https://github.com"}]

    def list_scm_projects(self, scm_id):
        self.calls.append(f"list_scm_projects:{scm_id}")
        return ["somebody/else"]

    # Recorded rather than refused: the boundary tests below deliberately fall
    # onto the SCM path, which reads all three. That the manual path does *not*
    # read them is asserted against `calls`, not by exploding here.

    def get_protected_branches(self, project_name):
        self.calls.append("get_protected_branches")
        return []

    def licensed_engines(self):
        self.calls.append("licensed_engines")
        return ("SAST",)

    def get_last_sast_scan(self, project_id, branch=None):
        self.calls.append("get_last_sast_scan")
        return None

    # -- writes

    def rename_project(self, project_id, name):
        self.calls.append("rename_project")
        error = self.rename_errors.get(project_id)
        if error:
            raise CxError(error)
        self.renames.append((project_id, name))
        if project_id not in self.silent_renames:
            self.names[project_id] = name

    def rescan_project(self, project_id):
        self.calls.append("rescan_project")
        if self.rescan_error:
            raise CxError(self.rescan_error)
        self.rescans.append(project_id)
        return {"id": "scan-manual-1"}

    # -- calls that must never happen on this path

    def disconnect_project(self, project_id):  # pragma: no cover - must not run
        raise AssertionError("a manual project has no connection to disconnect")

    def convert_project(self, payload):  # pragma: no cover - must not run
        raise AssertionError("a manual project has no repository to convert to")

    def get_repo_settings(self, repo_id):  # pragma: no cover - must not run
        raise AssertionError("a manual project has no repository settings")

    def update_repo_settings(self, repo_id, project_id, payload):  # pragma: no cover
        raise AssertionError("a manual project has no repository settings")

    def delete_project(self, project_id):  # pragma: no cover - must never run
        raise AssertionError("re-onboarding must never delete a project")


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("CX_DB_PATH", str(tmp_path / "manual.db"))
    return Store(Settings.from_env())


def make_run(store):
    run_id = store.create_run(
        source_project_id="base-1",
        source_project_name=BASE_NAME,
        baseline_scan_id="baseline-1",
        baseline_branch="master",
        minutes_per_finding=10,
        status=COMPLETED,
    )
    store.update_run(
        run_id,
        fa_project_id="fa-1",
        fa_project_name=FA_NAME,
        parity_report={"reliable": True, "total": 7},
    )
    return run_id


def run_it(client, store, run_id=None):
    run_id = run_id or make_run(store)
    digest = reonboard.preview(client, store.get_run(run_id)).digest()
    reonboard.run_reonboard(run_id, store, client, digest, SETTINGS)
    return run_id


def steps_of(store, run_id):
    return {s["step"]: s for s in store.get_steps(run_id)}


# -- the happy path ------------------------------------------------------------


def test_a_manual_project_takes_the_rename_path(store):
    client = ManualClient()
    plan = reonboard.preview(client, store.get_run(make_run(store)))

    assert plan.manual
    assert plan.executable


def test_no_scm_call_is_ever_made(store):
    """Every one of them raises in the fake, so a stray call fails loudly."""
    client = ManualClient()
    run_id = run_it(client, store)

    assert store.get_run(run_id)["reonboard_status"] == reonboard.COMPLETED
    assert "disconnect_project" not in client.calls
    assert "convert_project" not in client.calls


def test_both_renames_fire_in_order(store):
    client = ManualClient()
    run_it(client, store)

    assert client.renames == [("base-1", BACKUP_NAME), ("fa-1", BASE_NAME)]


def test_each_rename_is_read_back_before_the_next_one_fires(store):
    """The goal's ordered, checked writes. `PATCH` answers 204 with no body.

    Firing the second rename on the strength of an unverified first is how both
    projects end up holding the wrong names.
    """
    client = ManualClient()
    run_it(client, store)

    renames = [i for i, call in enumerate(client.calls) if call == "rename_project"]
    first, second = renames
    between = client.calls[first + 1:second]
    assert "get_project:base-1" in between


def test_a_rename_that_does_not_take_effect_is_caught(store):
    """A 2xx is not evidence. The name is."""
    client = ManualClient(silent_renames={"base-1"})
    run_id = run_it(client, store)

    run = store.get_run(run_id)
    assert run["reonboard_status"] == reonboard.FAILED
    assert "still reads as" in run["reonboard_result"]["error"]
    # The second rename must not have been attempted on a false premise.
    assert client.renames == [("base-1", BACKUP_NAME)]


def test_the_rescan_runs_on_the_promoted_copy(store):
    client = ManualClient()
    run_id = run_it(client, store)

    assert client.rescans == ["fa-1"]
    result = store.get_run(run_id)["reonboard_result"]
    assert result["rescan"]["scan_id"] == "scan-manual-1"
    assert result["rescan"]["manual"] is True


def test_the_result_records_both_names(store):
    client = ManualClient()
    run_id = run_it(client, store)

    result = store.get_run(run_id)["reonboard_result"]
    assert result["manual"] is True
    assert result["candidate_project_name"] == BASE_NAME
    assert result["candidate_original_name"] == FA_NAME
    assert result["base_project_name"] == BACKUP_NAME
    assert result["base_original_name"] == BASE_NAME


# -- the audit trail -----------------------------------------------------------


def test_every_skipped_step_is_logged_with_its_reason(store):
    """Audit-trail parity with the SCM path: a silent skip reads as a failure."""
    client = ManualClient()
    run_id = run_it(client, store)
    steps = steps_of(store, run_id)

    for name in ("reonboard-disconnect", "reonboard-convert", "rescan-settings"):
        assert steps[name]["outcome"] == "skipped"
        assert "manual project" in steps[name]["detail"]


def test_the_preflight_records_which_state_it_found(store):
    client = ManualClient()
    run_id = run_it(client, store)

    assert steps_of(store, run_id)["reonboard-preflight"]["detail"] == (
        "both projects hold their original names"
    )


def test_the_renames_and_the_outcome_are_journalled(store):
    client = ManualClient()
    run_id = run_it(client, store)
    steps = steps_of(store, run_id)

    assert steps["reonboard-rename-base"]["outcome"] == "ok"
    assert steps["reonboard-rename-candidate"]["outcome"] == "ok"
    assert steps["rescan-trigger"]["outcome"] == "ok"
    assert steps["reonboard"]["outcome"] == "ok"


# -- partial failure and resuming ---------------------------------------------


def test_a_failed_second_rename_is_blocking_and_names_what_landed(store):
    client = ManualClient(rename_errors={"fa-1": "409 name already in use"})
    run_id = run_it(client, store)

    run = store.get_run(run_id)
    assert run["reonboard_status"] == reonboard.FAILED
    error = run["reonboard_result"]["error"]
    assert "409 name already in use" in error
    assert BACKUP_NAME in error
    assert "resume" in error
    # And it must not claim a repository is stranded, because none is involved.
    assert "connected to no Checkmarx project" not in error


def test_a_failed_first_rename_leaves_nothing_applied(store):
    client = ManualClient(rename_errors={"base-1": "403 forbidden"})
    run_id = run_it(client, store)

    run = store.get_run(run_id)
    assert run["reonboard_status"] == reonboard.FAILED
    assert run["reonboard_result"]["applied_steps"] == []
    assert client.renames == []


def test_a_resumed_run_performs_only_the_outstanding_rename(store):
    """The intermediate state, detected and picked up from - not repeated."""
    client = ManualClient(names={"base-1": BACKUP_NAME, "fa-1": FA_NAME})
    run_id = run_it(client, store)

    assert client.renames == [("fa-1", BASE_NAME)]
    steps = steps_of(store, run_id)
    assert steps["reonboard-rename-base"]["outcome"] == "skipped"
    assert steps["reonboard-rename-candidate"]["outcome"] == "ok"
    assert store.get_run(run_id)["reonboard_status"] == reonboard.COMPLETED


def test_the_approved_digest_still_matches_after_a_partial_failure(store):
    """What makes a resume a resume rather than a fresh decision."""
    fresh = ManualClient()
    approved = reonboard.preview(fresh, store.get_run(make_run(store))).digest()

    resumed = ManualClient(names={"base-1": BACKUP_NAME, "fa-1": FA_NAME})
    assert reonboard.preview(
        resumed, store.get_run(make_run(store))
    ).digest() == approved


def test_a_fully_applied_run_renames_nothing_and_still_succeeds(store):
    """Idempotency: re-running after everything landed must not rename again."""
    client = ManualClient(names={"base-1": BACKUP_NAME, "fa-1": BASE_NAME})
    run_id = run_it(client, store)

    assert client.renames == []
    steps = steps_of(store, run_id)
    assert steps["reonboard-rename-base"]["outcome"] == "skipped"
    assert steps["reonboard-rename-candidate"]["outcome"] == "skipped"
    assert store.get_run(run_id)["reonboard_status"] == reonboard.COMPLETED
    assert client.rescans == ["fa-1"]


def test_the_state_is_read_from_the_suffixes_not_from_the_plan(store):
    """The plan cannot tell a fresh run from a resumed one, and this is why.

    It is built from whatever the tenant currently reports, and
    `backup_name_for` is idempotent - so on a resume `base_project_name` and
    `base_backup_name` are the same string. Only the suffix distinguishes them.
    """
    fresh = ManualClient()
    resumed = ManualClient(names={"base-1": BACKUP_NAME, "fa-1": FA_NAME})
    done = ManualClient(names={"base-1": BACKUP_NAME, "fa-1": BASE_NAME})

    for client, expected in (
        (fresh, reonboard.FRESH),
        (resumed, reonboard.BASE_RENAMED),
        (done, reonboard.ALREADY_APPLIED),
    ):
        plan = reonboard.preview(client, store.get_run(make_run(store)))
        assert reonboard._manual_state(client, plan) == expected


def test_a_contradictory_pair_of_names_aborts_before_any_write(store):
    """Someone renamed a project by hand. Guessing from here is how names get lost.

    The base has handed over its name, but the copy is called something this
    flow never would have chosen - so which rename is outstanding, and to what,
    is not answerable.
    """
    client = ManualClient()
    plan = reonboard.preview(client, store.get_run(make_run(store)))
    client.names = {"base-1": BACKUP_NAME, "fa-1": "renamed-by-hand"}

    with pytest.raises(reonboard.ReonboardAborted) as caught:
        reonboard._manual_state(client, plan)
    assert "not in a state this re-onboarding recognises" in str(caught.value)
    assert client.renames == []


# -- the rescan is best effort -------------------------------------------------


def test_a_failed_rescan_leaves_the_re_onboarding_successful(store):
    """The renames are what re-onboarding means here. The scan is housekeeping."""
    client = ManualClient(rescan_error="scan already in progress")
    run_id = run_it(client, store)

    run = store.get_run(run_id)
    assert run["reonboard_status"] == reonboard.COMPLETED
    assert any(
        "scan already in progress" in w
        for w in run["reonboard_result"]["rescan"]["warnings"]
    )
    assert steps_of(store, run_id)["rescan-trigger"]["outcome"] == "warn"


def test_an_unexpected_error_in_the_rescan_does_not_reopen_the_run(store):
    """The status is written before the rescan, so nothing here may undo it."""
    class Exploding(ManualClient):
        def rescan_project(self, project_id):
            raise RuntimeError("something nobody predicted")

    client = Exploding()
    run_id = run_it(client, store)

    run = store.get_run(run_id)
    assert run["reonboard_status"] == reonboard.COMPLETED
    assert steps_of(store, run_id)["rescan"]["outcome"] == "warn"


# -- the boundary --------------------------------------------------------------


def test_a_project_whose_baseline_was_cloned_never_reaches_this_path(store):
    """`scheduler`: no repository record, but driven by a webhook all the same.

    It must keep hitting today's blocking error. Renaming it would leave its
    webhook scanning the backup copy for ever.
    """
    class Webhooked(ManualClient):
        def get_scan(self, scan_id):
            return {"id": scan_id, "engines": ["sast"], "metadata": {"Handler": {
                "GitHandler": {"repo_url": "https://github.com/acme/thing"}
            }}}

    plan = reonboard.preview(Webhooked(), store.get_run(make_run(store)))

    assert not plan.manual
    assert not plan.executable
    assert "last-connected-project" in [b.code for b in plan.blockers]


def test_a_cloned_scan_further_back_also_keeps_it_off_this_path(store):
    """`delphilint`: uploaded baseline, cloned history. The baseline lies."""
    client = ManualClient(source_types=["zip", "rescan", "github"])
    plan = reonboard.preview(client, store.get_run(make_run(store)))

    assert not plan.manual


def test_an_unreadable_scan_history_is_not_read_as_manual(store):
    """Absence of evidence is not evidence. Staying stuck is the safe failure."""
    class Unreadable(ManualClient):
        def get_recent_scans(self, project_id, limit=20):
            raise CxError("500 could not list scans")

    plan = reonboard.preview(Unreadable(), store.get_run(make_run(store)))

    assert not plan.manual


def test_the_scan_history_is_not_read_for_a_connected_project(store):
    """One page of scans per preview is cheap, but not free and not needed."""
    class Connected(ManualClient):
        def get_project(self, project_id):
            record = super().get_project(project_id)
            if project_id == "base-1":
                record.update({"repoId": 72770, "origin": "GitLab"})
            return record

    client = Connected()
    reonboard.preview(client, store.get_run(make_run(store)))

    assert "get_recent_scans" not in client.calls


def test_a_connected_project_never_reaches_this_path(store):
    class Connected(ManualClient):
        def get_project(self, project_id):
            record = super().get_project(project_id)
            if project_id == "base-1":
                record.update({"repoId": 72770, "origin": "GitLab"})
            return record

    plan = reonboard.preview(Connected(), store.get_run(make_run(store)))

    assert not plan.manual


def test_the_manual_preview_skips_the_conversion_only_reads(store):
    """`_org_peers` walks the whole tenant to count credential-sharing peers.

    There is no conversion to lend a credential to, so paying for that walk -
    and for the protected-branch and licence reads - would be work for nothing.
    `get_protected_branches` raises in the fake, so this is enforced, not hoped.
    """
    client = ManualClient()
    reonboard.preview(client, store.get_run(make_run(store)))

    assert "get_protected_branches" not in client.calls
