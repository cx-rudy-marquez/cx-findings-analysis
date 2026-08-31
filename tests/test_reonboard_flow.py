"""Executing a re-onboarding, driven by a fake client.

Two properties matter more than anything else here and are asserted directly:
the base project is never deleted, and a failure after the disconnect says so
in plain words instead of leaving someone to discover it.
"""

import pytest

from config import Settings
from cx import reonboard
from cx.errors import CxError
from store import COMPLETED, Store

#: Zero poll interval: the fake conversion is terminal immediately, and the
#: repoId retry must not spend eight seconds a go proving a project has none.
SETTINGS = Settings(poll_interval_seconds=0)

#: `repoId` and `scmRepoId` are the repository-manager record, and every
#: connected project on the reference tenant carries both. They are what tells
#: this project apart from one that is genuinely manual, which takes the
#: rename-only path in `tests/test_reonboard_manual.py` instead.
BASE = {
    "id": "base-1",
    "name": "acme/checkout",
    "repoUrl": "https://github.com/acme/checkout.git",
    "repoId": 52042,
    "scmRepoId": "checkout",
    "origin": "GitHub",
}


class FakeClient:
    """Records every call in order, so the test can assert on the sequence."""

    def __init__(self, **overrides):
        self.calls = []
        self.deleted = []
        self.disconnected = []
        self.conversions = []
        self.renames = []
        self.connected = overrides.get(
            "connected", ["acme/checkout", "acme/other"]
        )
        self.convert_error = overrides.get("convert_error")
        self.disconnect_error = overrides.get("disconnect_error")
        self.statuses = list(
            overrides.get("statuses", [{"migrationStatus": "OK",
                                        "summary": "Finished converting projects",
                                        "failedProjectList": []}])
        )
        self.no_process_id = overrides.get("no_process_id", False)
        self.scms = overrides.get(
            "scms", [{"id": 7, "type": "github", "repoBaseUrl": "https://github.com"}]
        )
        #: {scm_id: [project names]}, when a test needs several integrations.
        self.memberships = overrides.get("memberships")
        # -- post-conversion rescan
        self.engines = overrides.get("engines", ["SAST", "KICS", "SCA"])
        self.repo_id = overrides.get("repo_id", 72768)
        self.repo_settings = overrides.get("repo_settings", {
            "kicsScannerEnabled": {"value": False, "isEditable": True},
            "scaScannerEnabled": {"value": False, "isEditable": True},
            "sastIncrementalScan": {"value": True, "isEditable": True},
            "scaAutoPrEnabled": {"value": True, "isEditable": True},
        })
        self.settings_error = overrides.get("settings_error")
        self.rescan_error = overrides.get("rescan_error")
        self.settings_patches = []
        self.rescans = []
        #: Current names, mutated by `rename_project` so the tenant this fake
        #: stands for answers with what things are called *now*.
        self.names = {"base-1": BASE["name"], "fa-1": "acme/checkout_FA"}

    def get_project(self, project_id):
        # Names come out of `self.names`, which the renames mutate, so a project
        # asked about after a rename reports what it is actually called now.
        if project_id == "fa-1":
            # The converted project reports a repoId, exactly as the platform
            # does once a project is connected - and reports none when the test
            # is exercising the gap before the platform has assigned one.
            record = {"id": "fa-1", "name": self.names["fa-1"]}
            if self.repo_id:
                record["repoId"] = self.repo_id
            return record
        return {**BASE, "name": self.names["base-1"]}

    def licensed_engines(self):
        self.calls.append("licensed_engines")
        return tuple(self.engines)

    def get_repo_settings(self, repo_id):
        self.calls.append("get_repo_settings")
        if self.settings_error:
            raise CxError(self.settings_error)
        return {k: dict(v) for k, v in self.repo_settings.items()}

    def update_repo_settings(self, repo_id, project_id, payload):
        self.calls.append("update_repo_settings")
        if self.settings_error:
            raise CxError(self.settings_error)
        self.settings_patches.append((repo_id, project_id, payload))
        return {"applied": dict(payload)}

    def rescan_project(self, project_id):
        self.calls.append("rescan_project")
        if self.rescan_error:
            raise CxError(self.rescan_error)
        self.rescans.append(project_id)
        return {"id": "scan-99"}

    def get_projects(self):
        return [
            {**BASE, "name": self.names["base-1"]},
            {"id": "fa-1", "name": self.names["fa-1"]},
        ]

    def rename_project(self, project_id, name):
        self.calls.append("rename_project")
        self.renames.append((project_id, name))
        self.names[project_id] = name

    def get_scan(self, scan_id):
        return {"id": scan_id, "sourceType": "github",
                "engines": ["sast", "sca", "containers"]}

    def list_scms(self):
        self.calls.append("list_scms")
        return list(self.scms)

    def list_scm_projects(self, scm_id):
        self.calls.append(f"list_scm_projects:{scm_id}")
        if self.memberships is not None:
            return list(self.memberships.get(scm_id, []))
        return list(self.connected)

    def get_protected_branches(self, project_name):
        self.calls.append("get_protected_branches")
        return [{"pattern": "main", "isDefaultBranch": True}]

    def disconnect_project(self, project_id):
        self.calls.append("disconnect_project")
        if self.disconnect_error:
            raise CxError(self.disconnect_error)
        self.disconnected.append(project_id)

    def convert_project(self, payload):
        self.calls.append("convert_project")
        if self.convert_error:
            raise CxError(self.convert_error)
        self.conversions.append(payload)
        return {} if self.no_process_id else {"processId": "proc-1"}

    def get_conversion_status(self, process_id):
        self.calls.append("get_conversion_status")
        return self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]

    # Deliberately present so a stray call is caught rather than silently
    # unsupported: nothing in this project may ever delete a project.
    def delete_project(self, project_id):  # pragma: no cover - must never run
        self.deleted.append(project_id)
        raise AssertionError("re-onboarding must never delete a project")


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("CX_DB_PATH", str(tmp_path / "reonboard.db"))
    return Store(Settings.from_env())


def make_run(store):
    run_id = store.create_run(
        source_project_id="base-1",
        source_project_name="acme/checkout",
        baseline_scan_id="baseline-1",
        baseline_branch="main",
        minutes_per_finding=10,
        status=COMPLETED,
    )
    store.update_run(
        run_id,
        fa_project_id="fa-1",
        fa_project_name="acme/checkout_FA",
        parity_report={"reliable": True, "total": 7},
    )
    return run_id


def approved(client, store, run_id):
    """The digest an operator would have been shown by the preview."""
    return reonboard.preview(client, store.get_run(run_id)).digest()


def test_the_preview_writes_nothing_to_the_tenant(store):
    client = FakeClient()
    plan = reonboard.preview(client, store.get_run(make_run(store)))

    assert plan.executable
    assert client.disconnected == []
    assert client.conversions == []
    assert "disconnect_project" not in client.calls
    assert "convert_project" not in client.calls


def test_the_preview_strips_the_git_suffix_from_the_repo_url(store):
    plan = reonboard.preview(FakeClient(), store.get_run(make_run(store)))
    assert plan.repo_url == "https://github.com/acme/checkout"


def test_a_run_with_no_fa_project_cannot_be_re_onboarded(store):
    run_id = store.create_run(
        source_project_id="base-1", source_project_name="acme/checkout",
        baseline_scan_id=None, baseline_branch=None, minutes_per_finding=10,
    )
    with pytest.raises(reonboard.ReonboardAborted):
        reonboard.preview(FakeClient(), store.get_run(run_id))


def test_disconnect_runs_before_conversion(store):
    """Forced order: the repo cannot be attached to two projects at once."""
    client = FakeClient()
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    assert store.get_run(run_id)["reonboard_status"] == reonboard.COMPLETED
    assert client.calls.index("disconnect_project") < client.calls.index(
        "convert_project"
    )


def test_the_base_project_is_disconnected_and_never_deleted(store):
    client = FakeClient()
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    assert client.disconnected == ["base-1"]
    assert client.deleted == []


def test_the_candidate_is_the_project_that_gets_converted(store):
    client = FakeClient()
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    payload = client.conversions[0]
    assert payload["projects"][0]["cxProjectId"] == "fa-1"
    assert payload["projects"][0]["scmRepositoryUrl"] == (
        "https://github.com/acme/checkout"
    )
    assert "token" not in payload


def test_the_conversion_is_polled_to_a_terminal_status(store):
    client = FakeClient(statuses=[
        {"migrationStatus": "IN_PROGRESS", "failedProjectList": []},
        {"migrationStatus": "OK", "summary": "done", "failedProjectList": []},
    ])
    run_id = make_run(store)
    reonboard.run_reonboard(
        run_id, store, client,
        approved(client, store, run_id),
        Settings(poll_interval_seconds=0),
    )

    assert client.calls.count("get_conversion_status") >= 2
    assert store.get_run(run_id)["reonboard_status"] == reonboard.COMPLETED


def test_a_stale_approval_is_refused_before_anything_is_written(store):
    """Approval binds to one exact plan; the tenant may have moved since."""
    client = FakeClient()
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, "not-the-right-digest")

    run = store.get_run(run_id)
    assert run["reonboard_status"] == reonboard.FAILED
    assert client.disconnected == []
    assert "no longer matches" in run["reonboard_result"]["error"]
    assert run["reonboard_result"]["base_disconnected"] is False


def test_the_last_connected_project_is_refused_before_anything_is_written(store):
    client = FakeClient(connected=["acme/checkout"])
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    run = store.get_run(run_id)
    assert run["reonboard_status"] == reonboard.FAILED
    assert client.disconnected == []
    assert "only project connected" in run["reonboard_result"]["error"]


def test_a_failed_conversion_reports_exactly_what_landed(store):
    """The single most important message this module produces.

    By the time the conversion fires, three changes have already been applied.
    Someone resolving this by hand needs all three named, not just the first.
    """
    client = FakeClient(convert_error="organisation not found")
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    run = store.get_run(run_id)
    result = run["reonboard_result"]
    assert run["reonboard_status"] == reonboard.FAILED
    assert result["base_disconnected"] is True
    error = result["error"]
    assert "organisation not found" in error
    assert "failed part-way" in error
    # Every applied step is named, in order.
    assert "was disconnected" in error
    assert "acme/checkout_FA_BACKUP" in error
    assert "acme/checkout'" in error          # the copy's new name
    assert len(result["applied_steps"]) == 3
    assert "reconnect it in checkmarx one" in error.lower()
    assert "Both projects still exist" in error
    assert client.deleted == []


def test_a_failed_disconnect_stops_before_the_conversion(store):
    client = FakeClient(disconnect_error="403 forbidden")
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    run = store.get_run(run_id)
    assert run["reonboard_status"] == reonboard.FAILED
    assert client.conversions == []
    assert run["reonboard_result"]["base_disconnected"] is False


def test_nothing_is_retried_automatically(store):
    client = FakeClient(convert_error="boom")
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    assert client.calls.count("disconnect_project") == 1
    assert client.calls.count("convert_project") == 1


def test_a_conversion_without_a_process_id_is_a_failure(store):
    """Accepted but unconfirmable is not success."""
    client = FakeClient(no_process_id=True)
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    run = store.get_run(run_id)
    assert run["reonboard_status"] == reonboard.FAILED
    assert "no processId" in run["reonboard_result"]["error"]


def test_a_partial_conversion_is_not_reported_as_success(store):
    client = FakeClient(statuses=[{
        "migrationStatus": "PARTIAL",
        "summary": "1 of 2 converted",
        "failedProjectList": [{"project": "fa-1", "reason": "branch missing"}],
    }])
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    run = store.get_run(run_id)
    assert run["reonboard_status"] == reonboard.FAILED
    assert "PARTIAL" in run["reonboard_result"]["error"]


def test_every_step_is_journalled(store):
    client = FakeClient()
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    steps = {s["step"] for s in store.get_steps(run_id)}
    assert {"reonboard-disconnect", "reonboard-convert", "reonboard"} <= steps


def test_the_disconnect_step_records_that_nothing_was_deleted(store):
    client = FakeClient()
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    detail = next(
        s["detail"] for s in store.get_steps(run_id)
        if s["step"] == "reonboard-disconnect" and s["outcome"] == "ok"
    )
    assert "not deleted" in detail
    assert "history preserved" in detail


# -- integration discovery ----------------------------------------------------


PROXIED_SCM = {
    "id": 3301, "type": "gitlab",
    "repoBaseUrl": "https://deu.ast.checkmarx.net/link/42086f33",
}
CLOUD_SCM = {"id": 2, "type": "gitlab", "repoBaseUrl": "https://gitlab.com"}


def test_every_integration_is_searched_not_just_the_first_of_its_type(store):
    """The bug a live tenant exposed: four GitLab integrations, one owner."""
    client = FakeClient(
        scms=[CLOUD_SCM, {"id": 9, "type": "gitlab", "repoBaseUrl": "https://x.invalid"},
              PROXIED_SCM],
        memberships={2: [], 9: [], 3301: ["acme/checkout", "acme/other"]},
    )
    plan = reonboard.preview(client, store.get_run(make_run(store)))

    assert plan.scm_id == "3301"
    assert plan.repo_url == f"{PROXIED_SCM['repoBaseUrl']}/acme/checkout"
    assert plan.executable
    # Every integration was asked, not just the first matching type.
    assert "list_scm_projects:2" in client.calls
    assert "list_scm_projects:3301" in client.calls


def test_a_directly_addressed_integration_wins_over_a_proxied_one(store):
    """If a cloud integration really lists it, its hostname is the better one."""
    client = FakeClient(
        scms=[PROXIED_SCM, CLOUD_SCM],
        memberships={3301: ["acme/checkout"], 2: ["acme/checkout", "acme/other"]},
    )
    plan = reonboard.preview(client, store.get_run(make_run(store)))

    assert plan.scm_id == "2"
    assert plan.repo_url == "https://gitlab.com/acme/checkout"


def test_an_unreadable_integration_does_not_hide_a_match_in_another(store):
    class Flaky(FakeClient):
        def list_scm_projects(self, scm_id):
            self.calls.append(f"list_scm_projects:{scm_id}")
            if scm_id == 2:
                raise CxError("500 from repos-manager")
            return ["acme/checkout", "acme/other"]

    client = Flaky(scms=[CLOUD_SCM, PROXIED_SCM])
    plan = reonboard.preview(client, store.get_run(make_run(store)))
    assert plan.scm_id == "3301"
    assert plan.executable


def test_a_project_no_integration_lists_still_resolves_from_its_scan(store):
    """The live case: empty listing, empty repoUrl, real repository.

    `scms/{id}/projects` returned nothing for the integration that actually
    owned the project. The scan's git handler is what settles it.
    """
    client = FakeClient(scms=[CLOUD_SCM], memberships={2: []})
    plan = reonboard.preview(client, store.get_run(make_run(store)))

    assert plan.repo_url == "https://github.com/acme/checkout"
    # Alone in its organisation as far as anything can tell, so still refused -
    # but for the credential reason, not for the listing's silence.
    assert [b.code for b in plan.blockers] == ["last-connected-project"]


def test_org_peers_make_a_re_onboarding_executable(store):
    """Another project on the same host and org keeps the credential alive."""
    class WithPeer(FakeClient):
        def get_project(self, project_id):
            record = super().get_project(project_id)
            return {**record, "origin": "GitHub"} if project_id == "base-1" else record

        def get_projects(self):
            return [
                {"id": "base-1", "name": self.names["base-1"], "origin": "GitHub"},
                {"id": "peer-1", "name": "acme/other", "origin": "GitHub"},
            ]

        def get_last_sast_scan(self, project_id, branch=None):
            return {"id": f"scan-{project_id}"}

        def get_scan(self, scan_id):
            url = "https://github.com/acme/other" if "peer" in scan_id \
                else "https://github.com/acme/checkout"
            return {"id": scan_id, "sourceType": "github",
                    "engines": ["sast", "sca"],
                    "metadata": {"Handler": {"GitHandler": {"repo_url": url}}}}

    client = WithPeer(scms=[CLOUD_SCM], memberships={2: []})
    plan = reonboard.preview(client, store.get_run(make_run(store)))

    assert plan.executable
    assert plan.connected_project_count == 2


# -- the two renames ----------------------------------------------------------


def test_the_renames_run_between_the_disconnect_and_the_conversion(store):
    """Forced order: the base must vacate the name before the copy takes it."""
    client = FakeClient()
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    assert store.get_run(run_id)["reonboard_status"] == reonboard.COMPLETED
    order = [c for c in client.calls
             if c in {"disconnect_project", "rename_project", "convert_project"}]
    assert order == [
        "disconnect_project", "rename_project", "rename_project", "convert_project",
    ]


def test_the_base_is_renamed_to_a_backup_and_the_copy_takes_its_name(store):
    client = FakeClient()
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    assert client.renames == [
        ("base-1", "acme/checkout_FA_BACKUP"),
        ("fa-1", "acme/checkout"),
    ]
    # Renaming is not deleting, and never becomes it.
    assert client.deleted == []


def test_the_result_records_both_old_and_new_names(store):
    client = FakeClient()
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    result = store.get_run(run_id)["reonboard_result"]
    assert result["base_original_name"] == "acme/checkout"
    assert result["base_project_name"] == "acme/checkout_FA_BACKUP"
    assert result["candidate_original_name"] == "acme/checkout_FA"
    assert result["candidate_project_name"] == "acme/checkout"


def test_a_failed_base_rename_stops_before_the_copy_is_touched(store):
    class NoRename(FakeClient):
        def rename_project(self, project_id, name):
            self.calls.append("rename_project")
            raise CxError("409 name already in use")

    client = NoRename()
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    run = store.get_run(run_id)
    assert run["reonboard_status"] == reonboard.FAILED
    assert client.conversions == []
    assert client.calls.count("rename_project") == 1
    # Only the disconnect had landed, and the message says so.
    assert run["reonboard_result"]["applied_steps"] == [
        "'acme/checkout' was disconnected from its repository and is now a "
        "manual project"
    ]


def test_every_rename_is_journalled(store):
    client = FakeClient()
    run_id = make_run(store)
    reonboard.run_reonboard(run_id, store, client, approved(client, store, run_id))

    steps = {s["step"] for s in store.get_steps(run_id)}
    assert {"reonboard-rename-base", "reonboard-rename-candidate"} <= steps


# --- the post-conversion rescan ----------------------------------------------
# Best-effort by construction. Every test here exists to prove one thing: this
# step cannot turn a re-onboarding that moved a repository into a failed one.


def run_to_completion(client, store):
    run_id = make_run(store)
    reonboard.run_reonboard(
        run_id, store, client, approved(client, store, run_id), SETTINGS
    )
    return run_id


def test_the_rescan_runs_after_the_conversion_and_in_order(store):
    client = FakeClient()
    run_id = run_to_completion(client, store)

    order = [c for c in client.calls if c in
             ("convert_project", "get_repo_settings", "update_repo_settings",
              "rescan_project")]
    assert order == [
        "convert_project", "get_repo_settings", "update_repo_settings",
        "rescan_project",
    ]
    assert store.get_run(run_id)["reonboard_status"] == reonboard.COMPLETED


def test_only_licensed_scanners_are_patched_onto_the_live_project(store):
    client = FakeClient(engines=["SAST", "KICS"])
    run_to_completion(client, store)

    repo_id, project_id, payload = client.settings_patches[0]
    assert repo_id == 72768
    assert project_id == "fa-1"
    assert payload["kicsScannerEnabled"] is True
    assert "scaScannerEnabled" not in payload
    assert payload["sastIncrementalScan"] is False
    assert payload["scaAutoPrEnabled"] is False


def test_the_scan_is_queued_against_the_converted_project(store):
    client = FakeClient()
    run_id = run_to_completion(client, store)
    assert client.rescans == ["fa-1"]
    assert store.get_run(run_id)["reonboard_result"]["rescan"]["scan_id"] == "scan-99"


def test_both_calls_are_recorded_in_the_audit_trail(store):
    client = FakeClient()
    run_id = run_to_completion(client, store)

    steps = {s["step"]: s for s in store.get_steps(run_id)}
    assert steps["rescan-settings"]["outcome"] == "ok"
    assert steps["rescan-trigger"]["outcome"] == "ok"

    rescan = store.get_run(run_id)["reonboard_result"]["rescan"]
    assert rescan["licensed_engines"] == ["SAST", "KICS", "SCA"]
    assert rescan["repo_id"] == 72768
    assert rescan["settings_request"]["kicsScannerEnabled"] is True
    assert rescan["settings_response"] == {"applied": rescan["settings_request"]}
    assert rescan["rescan_response"] == {"id": "scan-99"}


def test_a_failed_settings_update_still_queues_the_scan(store):
    """A full scan on the old settings beats no scan, and the trail says so."""
    client = FakeClient(settings_error="repo 72768 is locked")
    run_id = run_to_completion(client, store)

    assert client.rescans == ["fa-1"]
    run = store.get_run(run_id)
    assert run["reonboard_status"] == reonboard.COMPLETED
    warnings = run["reonboard_result"]["rescan"]["warnings"]
    assert any("locked" in w for w in warnings)


def test_a_failed_rescan_leaves_the_re_onboarding_completed(store):
    client = FakeClient(rescan_error="a scan is already running")
    run_id = run_to_completion(client, store)

    run = store.get_run(run_id)
    assert run["reonboard_status"] == reonboard.COMPLETED
    assert run["reonboard_result"]["candidate_project_name"] == "acme/checkout"
    assert any(
        "already running" in w for w in run["reonboard_result"]["rescan"]["warnings"]
    )
    steps = {s["step"]: s for s in store.get_steps(run_id)}
    assert steps["rescan-trigger"]["outcome"] == "warn"


def test_a_missing_repo_id_skips_the_settings_but_still_scans(store):
    client = FakeClient(repo_id=None)
    run_id = run_to_completion(client, store)

    assert "update_repo_settings" not in client.calls
    assert client.rescans == ["fa-1"]
    run = store.get_run(run_id)
    assert run["reonboard_status"] == reonboard.COMPLETED
    assert any(
        "repoId" in w for w in run["reonboard_result"]["rescan"]["warnings"]
    )


def test_an_unexpected_error_in_the_follow_up_does_not_fail_the_run(store):
    """The outer handler must not reopen a run whose status is already written."""
    class Exploding(FakeClient):
        def licensed_engines(self):
            raise RuntimeError("something nobody predicted")

    client = Exploding()
    run_id = run_to_completion(client, store)
    assert store.get_run(run_id)["reonboard_status"] == reonboard.COMPLETED


def test_the_rescan_never_touches_the_base_project(store):
    """The base is disconnected and renamed. It is not scanned, and not deleted."""
    client = FakeClient()
    run_to_completion(client, store)
    assert client.rescans == ["fa-1"]
    assert client.deleted == []
