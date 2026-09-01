"""Planning a re-onboarding.

This is the only flow that touches a project the customer already had, so the
tests lean hardest on the refusals. A plan that is wrong in a permissive
direction disconnects a live repository on bad information; a plan that is
wrong in a restrictive direction only annoys someone.
"""

import pytest

from analysis.reonboard import (
    browse_base_url,
    build_plan,
    convertible_engines,
    is_manual_project,
    normalise_repo_url,
    org_identity,
    plan_to_json,
    protected_branch_patterns,
    resolve_repo_url,
    scm_type_for,
)

GITHUB = {"id": 1, "type": "github", "repoBaseUrl": "https://github.com"}
SELF_HOSTED = {"id": 2, "type": "gitlab", "repoBaseUrl": "https://gitlab.example.internal"}
#: How a live tenant reports a self-hosted integration: a Checkmarx link
#: address, not the customer's SCM hostname.
PROXIED = {
    "id": 3301, "type": "gitlab",
    "repoBaseUrl": "https://deu.ast.checkmarx.net/link/42086f33-b559-4c65-a01f",
}
SCMS = [GITHUB, SELF_HOSTED, PROXIED]


def plan(**overrides):
    """A plan that is executable, so each test can break exactly one thing."""
    kwargs = {
        "base_project": {
            "id": "base-1",
            "name": "acme/checkout",
            "repoUrl": "https://github.com/acme/checkout",
        },
        "candidate_project_id": "fa-1",
        "candidate_project_name": "acme/checkout_FA",
        "baseline_scan": {"sourceType": "github", "engines": ["sast", "sca"]},
        "baseline_branch": "main",
        "protected_branches": [{"pattern": "main", "isDefaultBranch": True}],
        "scms": SCMS,
        "connected_project_names": ["acme/checkout", "acme/other"],
        "integration": GITHUB,
    }
    kwargs.update(overrides)
    return build_plan(**kwargs)


def codes(built):
    return [blocker.code for blocker in built.blockers]


# -- repo URL and organisation ------------------------------------------------


def test_the_git_suffix_is_stripped():
    """The conversion API documents the URL without it; tenants store both."""
    assert normalise_repo_url("https://github.com/acme/checkout.git") == (
        "https://github.com/acme/checkout"
    )
    assert normalise_repo_url("https://github.com/acme/checkout/") == (
        "https://github.com/acme/checkout"
    )


def test_repo_url_case_is_preserved():
    """`scmRepositoryUrl` is documented case sensitive - normalising breaks it."""
    assert normalise_repo_url("https://github.com/Acme/CheckOut") == (
        "https://github.com/Acme/CheckOut"
    )


def test_the_organisation_is_the_first_path_segment():
    assert org_identity("https://github.com/acme/checkout") == "acme"
    assert org_identity("https://gitlab.com/acme/group/repo.git") == "acme"
    assert org_identity("https://bitbucket.org/workspace/repo") == "workspace"
    assert org_identity("") == ""


# -- SCM type -----------------------------------------------------------------


def test_the_scans_own_source_type_wins():
    """The platform recorded it when it pulled the code. That is a fact."""
    assert scm_type_for("https://anything.invalid/x/y", "bitbucket", SCMS) == (
        "bitbucket"
    )


def test_a_self_hosted_instance_is_matched_on_its_integration_base_url():
    """Only the tenant's integration list can identify a private hostname."""
    assert scm_type_for(
        "https://gitlab.example.internal/team/repo", None, SCMS
    ) == "gitlab"


def test_the_integration_the_project_belongs_to_wins():
    """It is the thing the conversion will actually talk to."""
    assert scm_type_for(
        "https://github.com/acme/checkout", "github", SCMS, integration=PROXIED
    ) == "gitlab"


def test_the_project_origin_is_used_when_nothing_better_exists():
    assert scm_type_for("", None, None, origin="GitLab") == "gitlab"


def test_a_known_host_is_the_last_resort():
    assert scm_type_for("https://github.com/acme/checkout", None, None) == "github"


def test_an_unrecognisable_host_yields_no_type():
    assert scm_type_for("https://git.unknown.invalid/a/b", None, None) == ""


# -- engines ------------------------------------------------------------------


def test_engines_the_conversion_api_rejects_are_dropped():
    """A real scan reports containers/aisc/microengines; sending one is a 400."""
    assert convertible_engines(
        ["sast", "kics", "containers", "aisc", "microengines", "sca"]
    ) == ("sast", "sca", "kics")


def test_engine_order_is_stable_so_the_digest_is():
    assert convertible_engines(["sca", "sast"]) == convertible_engines(
        ["sast", "sca"]
    )


def test_a_scan_with_no_usable_engines_falls_back_to_sast():
    assert convertible_engines(["containers"]) == ("sast",)
    assert convertible_engines(None) == ("sast",)


# -- protected branches -------------------------------------------------------


def test_protected_branch_patterns_are_carried_across():
    patterns = protected_branch_patterns(
        [{"pattern": "main"}, {"pattern": "release/*"}, {"pattern": "main"}], "main"
    )
    assert patterns == ("main", "release/*")


def test_an_unprotected_project_falls_back_to_its_baseline_branch():
    """`protectedBranches` is required and an empty list fails the conversion."""
    assert protected_branch_patterns([], "develop") == ("develop",)


def test_with_neither_there_is_nothing_to_protect():
    assert protected_branch_patterns([], None) == ()


# -- blockers -----------------------------------------------------------------


def test_a_complete_plan_is_executable():
    built = plan()
    assert built.executable
    assert built.blockers == ()


def test_the_last_connected_project_blocks_the_whole_flow():
    """The hazard the ordering creates.

    Disconnect runs first and the conversion carries no token - it borrows the
    credential from another connected project. If this is the only one, that
    credential vanishes between the two calls and the base is left disconnected
    with nothing able to convert.
    """
    built = plan(connected_project_names=["acme/checkout"])
    assert not built.executable
    assert codes(built) == ["last-connected-project"]
    assert "only project connected" in built.blockers[0].message


def test_a_project_alone_in_its_organisation_is_refused():
    """Absence from a listing is no longer evidence of anything.

    A live tenant returned an empty project list for an integration with
    seventeen projects behind it, so the count - not the listing - is what
    decides. One project means one credential, and disconnecting it strips it.
    """
    built = plan(connected_project_names=["acme/checkout"])
    assert codes(built) == ["last-connected-project"]


def test_a_project_with_no_repository_is_refused():
    built = plan(base_project={"id": "base-1", "name": "manual", "repoUrl": ""})
    assert not built.executable
    assert "no-repo-url" in codes(built)


def test_an_unidentifiable_scm_is_refused_rather_than_guessed():
    built = plan(
        base_project={
            "id": "base-1", "name": "acme/checkout",
            "repoUrl": "https://git.unknown.invalid/acme/checkout",
        },
        baseline_scan={"engines": ["sast"]},
        scms=[],
        integration=None,     # a manual project belongs to no integration yet
    )
    assert "unknown-scm" in codes(built)


def test_no_protectable_branch_is_refused():
    built = plan(protected_branches=[], baseline_branch=None)
    assert "no-branches" in codes(built)


def test_every_blocker_carries_an_explanation():
    """The preview has to say *why*; a bare refusal explains nothing."""
    built = plan(connected_project_names=[])
    assert built.blockers
    for blocker in built.blockers:
        assert len(blocker.message) > 40


# -- payload ------------------------------------------------------------------


def test_the_payload_never_carries_a_token():
    """This flow accepts no credential, by construction."""
    assert "token" not in plan().conversion_payload()


def test_the_payload_matches_the_documented_shape():
    payload = plan().conversion_payload()
    assert payload["scmType"] == "github"
    assert payload["orgIdentity"] == "acme"
    assert payload["types"] == ["sast", "sca"]
    assert payload["webhookEnabled"] is True
    assert payload["autoScanCxProjectAfterConversion"] is True
    assert payload["projects"] == [
        {
            "cxProjectId": "fa-1",
            "scmRepositoryUrl": "https://github.com/acme/checkout",
            "protectedBranches": ["main"],
            "types": ["sast", "sca"],
            "webhookEnabled": True,
            "branchToScanUponCreation": "main",
        }
    ]


def test_no_branch_to_scan_is_sent_when_auto_scan_is_off():
    """`branchToScanUponCreation` is only meaningful with autoScan enabled."""
    payload = plan(auto_scan=False).conversion_payload()
    assert payload["autoScanCxProjectAfterConversion"] is False
    assert "branchToScanUponCreation" not in payload["projects"][0]


def test_branch_to_scan_is_sent_when_auto_scan_is_on():
    """The conversion API needs to know what to scan once autoScan is on."""
    payload = plan().conversion_payload()
    assert payload["projects"][0]["branchToScanUponCreation"] == "main"


def test_the_candidate_is_converted_and_the_base_is_only_disconnected():
    """The direction of the swap, pinned. Reversing it would be catastrophic."""
    built = plan()
    disconnect, rename_base, rename_candidate, convert = built.steps()
    assert built.base_project_id in disconnect["path"]
    assert rename_base["path"] == f"/api/projects/{built.base_project_id}"
    assert rename_candidate["path"] == (
        f"/api/projects/{built.candidate_project_id}"
    )
    assert convert["path"].endswith("/project-conversion")
    assert built.conversion_payload()["projects"][0]["cxProjectId"] == "fa-1"


def test_the_rename_targets_are_derived_from_the_two_project_names():
    built = plan()
    assert built.base_backup_name == "acme/checkout_FA_BACKUP"
    assert built.candidate_final_name == "acme/checkout"


def test_the_backup_suffix_is_not_applied_twice():
    """A retry must not produce x_FA_BACKUP_FA_BACKUP."""
    built = plan(base_project={
        "id": "base-1", "name": "acme/checkout_FA_BACKUP",
        "repoUrl": "https://github.com/acme/checkout",
    }, connected_project_names=["acme/checkout_FA_BACKUP", "acme/other"])
    assert built.base_backup_name == "acme/checkout_FA_BACKUP"


def test_only_a_trailing_fa_suffix_is_stripped_from_the_copy():
    """`FOO_FACTORY` must survive intact."""
    from analysis.reonboard import promoted_name_for
    assert promoted_name_for("acme/FOO_FACTORY", "_FA") == "acme/FOO_FACTORY"
    assert promoted_name_for("acme/checkout_FA", "_FA") == "acme/checkout"


def test_a_name_already_in_use_blocks_the_rename():
    built = plan(existing_project_names=[
        "acme/checkout", "acme/checkout_FA", "acme/checkout_FA_BACKUP",
    ])
    assert not built.executable
    assert "backup-name-taken" in codes(built)


def test_a_copy_without_the_fa_suffix_cannot_take_over(): 
    built = plan(candidate_project_name="something-else")
    assert not built.executable
    assert "candidate-not-suffixed" in codes(built)


def test_the_digest_covers_the_rename_targets():
    """Approval binds to the names too, not just the conversion payload."""
    assert plan(candidate_project_name="acme/other_FA").digest() != plan().digest()


def test_no_step_deletes_anything():
    built = plan()
    rendered = " ".join(step["path"] + step["effect"] for step in built.steps())
    assert "delete" not in rendered.lower() or "not deleted" in rendered.lower()
    assert "DELETE" not in [step["method"] for step in built.steps()]


# -- digest -------------------------------------------------------------------


def test_the_digest_is_stable_for_an_unchanged_plan():
    assert plan().digest() == plan().digest()


@pytest.mark.parametrize(
    "change",
    [
        {"protected_branches": [{"pattern": "develop"}]},
        {"candidate_project_id": "fa-2"},
        {"baseline_scan": {"sourceType": "github", "engines": ["sast"]}},
        {"base_project": {"id": "base-2", "name": "acme/checkout",
                          "repoUrl": "https://github.com/acme/checkout"}},
    ],
)
def test_the_digest_changes_when_the_plan_does(change):
    """What makes confirmation meaningful: approval binds to one exact plan."""
    assert plan(**change).digest() != plan().digest()


# -- warnings and serialisation ----------------------------------------------


def test_falling_back_to_the_baseline_branch_is_called_out():
    built = plan(protected_branches=[])
    assert any("no protected branches" in w for w in built.warnings)
    assert built.executable


def test_a_github_app_integration_is_called_out():
    built = plan(
        baseline_scan={"sourceType": "githubApp", "engines": ["sast"]},
        integration=None,
    )
    assert any("GitHub App" in w for w in built.warnings)


def test_the_plan_serialises_everything_the_template_renders():
    payload = plan_to_json(plan())
    for key in (
        "steps", "payload", "digest", "executable", "blockers", "warnings",
        "repo_url", "scm_type", "org_identity", "protected_branches", "engines",
        "connected_project_count",
    ):
        assert key in payload
    assert payload["digest"] == plan().digest()


# -- repository URL resolution ------------------------------------------------
# A live tenant reports `repoUrl: ""` for every project connected through a Code
# Repository Integration; the identity is in `imported_proj_name` instead.


def test_a_manual_project_carries_its_repository_url_directly():
    project = {"repoUrl": "https://github.com/acme/checkout.git"}
    assert resolve_repo_url(project, None) == "https://github.com/acme/checkout"


def test_a_connected_project_is_rebuilt_from_its_imported_name():
    project = {"repoUrl": "", "imported_proj_name": "acme/checkout",
               "origin": "GitHub"}
    assert resolve_repo_url(project, GITHUB) == "https://github.com/acme/checkout"


def test_the_bitbucket_api_host_is_translated_to_its_browse_host():
    """`repoBaseUrl` for Bitbucket Cloud is the API host, not the browse host."""
    bitbucket = {"id": 4, "type": "bitbucket",
                 "repoBaseUrl": "https://api.bitbucket.org"}
    assert browse_base_url(bitbucket) == "https://bitbucket.org"
    project = {"repoUrl": "", "imported_proj_name": "workspace/repo"}
    assert resolve_repo_url(project, bitbucket) == (
        "https://bitbucket.org/workspace/repo"
    )


def test_a_checkmarx_link_address_is_still_a_usable_repository_address():
    """It is what the platform clones through - the scan git handler shows it."""
    assert browse_base_url(PROXIED) == PROXIED["repoBaseUrl"]
    project = {"name": "cx/WebGoatNet", "repoUrl": ""}
    assert resolve_repo_url(project, PROXIED) == (
        f"{PROXIED['repoBaseUrl']}/cx/WebGoatNet"
    )


def test_a_proxied_project_converts_and_says_so_rather_than_being_refused():
    """An empty repoUrl is how the integration stores things, not a failure."""
    built = plan(
        base_project={
            "id": "base-1", "name": "cx/WebGoatNet", "repoUrl": "",
            "origin": "GitLab",
        },
        integration=PROXIED,
        connected_project_names=["cx/WebGoatNet", "cx/juice-shop"],
    )
    assert built.executable
    assert built.blockers == ()
    assert built.org_identity == "cx"
    assert any("Checkmarx link address" in w for w in built.warnings)


def test_the_repository_path_comes_from_the_project_name():
    """The same string `scms/{id}/projects` matched on."""
    built = plan(
        base_project={"id": "base-1", "name": "rmarquez/WebGoat8", "repoUrl": ""},
        integration={"id": 2, "type": "gitlab", "repoBaseUrl": "https://gitlab.com"},
        connected_project_names=["rmarquez/WebGoat8", "other/repo"],
    )
    assert built.repo_url == "https://gitlab.com/rmarquez/WebGoat8"
    assert built.org_identity == "rmarquez"


def test_only_a_project_no_integration_lists_is_refused():
    """Step 4: the failure is legitimate only after every integration is tried."""
    built = plan(
        base_project={"id": "base-1", "name": "manual-project", "repoUrl": ""},
        integration=None,
        connected_project_names=[],
    )
    assert not built.executable
    assert "no-repo-url" in codes(built)
    assert "No integration lists" in built.blockers[0].message


def test_a_connected_project_produces_a_complete_plan():
    """The whole point: repoUrl empty, but the plan still builds correctly."""
    built = plan(
        base_project={
            "id": "base-1", "name": "acme/checkout", "repoUrl": "",
            "imported_proj_name": "acme/checkout", "origin": "GitHub",
        },
        integration=GITHUB,
    )
    assert built.executable
    assert built.repo_url == "https://github.com/acme/checkout"
    assert built.org_identity == "acme"
    assert built.scm_type == "github"
    assert built.scm_id == "1"


# --- licensed-scanner disclosure ----------------------------------------------
# `licensed_scanners` is informational only - shown in the preview as "Licensed
# for", not tied to any step this flow performs - so it must never affect
# whether a plan is executable or what its digest is.


def test_the_digest_does_not_depend_on_the_licence_disclosure():
    """A licence change must not refuse a re-onboarding that is otherwise identical."""
    assert plan(licensed_scanners=("KICS",)).digest() == (
        plan(licensed_scanners=("SCA", "Containers")).digest()
    )
    assert plan(licensed_scanners=()).digest() == plan().digest()


# --- manual projects: the rename-only path ------------------------------------
# Every shape below was read off the reference tenant during planning. The cost
# of getting this predicate wrong is asymmetric: classifying a connected project
# as manual renames it out from under a repository that keeps pushing to it,
# while the reverse only leaves a manual project as stuck as it is today.


UPLOADED = [{"sourceType": "zip"}, {"sourceType": "rescan"}]
CLONED = [{"sourceType": "zip"}, {"sourceType": "github"}]


def manual(project, integration=None, handler_repo_url="", recent_scans=UPLOADED):
    return is_manual_project(
        project,
        integration=integration,
        handler_repo_url=handler_repo_url,
        recent_scans=recent_scans,
    )


def test_a_project_with_no_repository_record_is_manual():
    """`VISLab`: no repoId, no scmRepoId, no origin, uploaded source."""
    assert manual({"id": "p", "name": "VISLab", "repoUrl": ""})


def test_a_repo_id_means_connected():
    """`rmarquez/WebGoat8`. The repoId *is* the repository-manager record."""
    assert not manual({"name": "rmarquez/WebGoat8", "repoId": 72770})
    assert not manual({"name": "x", "scmRepoId": "19349395"})


def test_a_stale_repo_url_does_not_make_a_project_connected():
    """A URL in the project record is not a connection, and never was."""
    assert manual({
        "name": "orchestrator",
        "repoUrl": "https://github.com/acme/orchestrator.git",
    })


def test_an_empty_repo_url_does_not_make_a_project_manual():
    """`rudy-marquez/juice-shop`: connected, and reports no repoUrl at all.

    Together with the test above, this is why the predicate never reads
    `repoUrl`: it is wrong in both directions on the same tenant.
    """
    assert not manual({"name": "rudy-marquez/juice-shop", "repoUrl": "",
                       "repoId": 57514, "scmRepoId": "juice-shop"})


def test_an_scm_origin_means_connected_even_without_a_repo_id():
    for origin in ("GitHub", "GitLab", "Bitbucket", "GitHub App", "Azure DevOps"):
        assert not manual({"name": "x", "origin": origin})


def test_the_tools_own_origin_is_not_an_scm_origin():
    """An `_FA` copy carries this tool's origin and is manual all the same."""
    assert manual({"name": "VISLab_FA", "origin": "findings-analysis-dashboard"})


def test_a_project_an_integration_lists_is_not_manual():
    assert not manual({"name": "x"}, integration=GITHUB)


def test_a_project_whose_scans_are_cloned_is_not_manual():
    """`scheduler`: no repoId, but its scans arrive from a GitHub PR webhook.

    This is the case the goal insists must keep failing loudly. Renaming it
    would leave its webhook scanning the `_FA_BACKUP` copy for ever.
    """
    assert not manual(
        {"name": "scheduler", "repoUrl": "https://github.com/marquezrudy/Scheduler"},
        handler_repo_url="https://github.com/marquezrudy/Scheduler",
    )


def test_a_git_url_scan_is_not_manual_even_with_no_repo_url_field():
    """`R-project`: scanned from a URL the project record never mentions."""
    assert not manual(
        {"name": "R-project", "repoUrl": ""},
        handler_repo_url="https://github.com/Rdatatable/data.table.git",
    )


def test_a_cloned_scan_anywhere_in_the_history_disqualifies_it():
    """`delphilint`, `VulnPascal`, `kubernetes-goat` and four more on the tenant.

    An uploaded or rescanned baseline sitting on top of cloned scans. Judging on
    the baseline alone called every one of them manual, which would have renamed
    a project something out there still addresses by name.
    """
    assert not manual({"name": "delphilint"}, recent_scans=CLONED)


def test_a_history_of_uploads_and_rescans_is_manual():
    """`VISLab`: the live instance of the case this path exists for."""
    assert manual({"name": "VISLab"}, recent_scans=[
        {"sourceType": "rescan"}, {"sourceType": "zip"},
    ])


def test_an_unknown_source_type_is_not_read_as_cloned():
    assert manual({"name": "x"}, recent_scans=[{"sourceType": "sbom"}, {}])


# -- the manual plan ----------------------------------------------------------


def manual_plan(**overrides):
    """A manual project's plan: no repository facts of any kind."""
    kwargs = {
        "base_project": {"id": "base-1", "name": "VISLab", "repoUrl": ""},
        "candidate_project_id": "fa-1",
        "candidate_project_name": "VISLab_FA",
        "baseline_scan": {},
        "baseline_branch": None,
        "protected_branches": None,
        "scms": [],
        "connected_project_names": ["VISLab"],
        "integration": None,
        "manual": True,
    }
    kwargs.update(overrides)
    return build_plan(**kwargs)


def test_a_manual_plan_is_executable_with_none_of_the_conversion_facts():
    """The five refusals are all `project-conversion` preconditions.

    Without this the manual path could not exist: a project with no repository
    trips every one of them, which is exactly why it is stuck today.
    """
    built = manual_plan()
    assert built.executable
    assert codes(built) == []
    assert built.manual


def test_the_same_project_without_the_manual_flag_is_still_refused():
    """Proves the waiver is the flag, not the absence of facts.

    An unsupported SCM provider fails the same checks for a different reason,
    and must keep failing them.
    """
    built = manual_plan(manual=False)
    assert not built.executable
    assert "no-repo-url" in codes(built)


def test_a_manual_plan_sends_no_conversion_body():
    assert manual_plan().conversion_payload() == {}


def test_a_manual_plan_still_refuses_a_backup_name_collision():
    """Both renames are real writes, so the name checks are not waived."""
    taken = ["VISLab_FA_BACKUP", "somebody-else"]
    assert "backup-name-taken" in codes(manual_plan(existing_project_names=taken))


def test_the_base_holding_the_final_name_is_not_a_collision():
    """It is the point of the exercise: the base is about to give that name up."""
    assert codes(manual_plan(existing_project_names=["VISLab", "VISLab_FA"])) == []


def test_a_manual_plan_still_refuses_a_copy_it_did_not_create():
    built = manual_plan(candidate_project_name="something-else")
    assert "candidate-not-suffixed" in codes(built)


def test_the_manual_steps_are_two_renames_a_rescan_and_two_skips():
    steps = manual_plan().steps()
    assert [s["method"] for s in steps] == [
        "PATCH", "PATCH", "POST", "skipped", "skipped"
    ]
    assert [s["order"] for s in steps[:3]] == [1, 2, 3]
    assert steps[0]["path"] == "/api/projects/base-1"
    assert steps[1]["path"] == "/api/projects/fa-1"
    assert steps[2]["path"] == "/api/scans/rescan"


def test_every_skipped_call_says_why_it_was_skipped():
    """Audit-trail parity: a skip nobody explained reads like a silent failure."""
    skipped = [s for s in manual_plan().steps() if s["method"] == "skipped"]
    assert [s["path"] for s in skipped] == [
        "/api/repos-manager/projects/base-1/disconnect",
        "/api/repos-manager/project-conversion",
    ]
    assert all("Manual project" in s["effect"] for s in skipped)


def test_a_manual_plan_carries_no_conversion_commentary():
    """Every stock warning is about the conversion, and there is not one.

    A protected-branch note on a project with no repository is commentary on a
    call that will never be made, and the preview already explains the path it
    is taking in its own words.
    """
    assert manual_plan().warnings == ()
    assert manual_plan().protected_branches == ()


# -- resuming a half-applied manual re-onboarding ------------------------------


def half_applied(**overrides):
    """The state a run that failed between the two renames leaves behind."""
    return manual_plan(
        base_project={"id": "base-1", "name": "VISLab_FA_BACKUP", "repoUrl": ""},
        **overrides,
    )


def test_the_digest_survives_the_base_having_already_been_renamed():
    """What makes a resume a resume rather than a fresh approval.

    The digest binds ids and target names, and neither moves when the first
    rename lands - so the operator's original confirmation still matches.
    """
    assert half_applied().digest() == manual_plan().digest()


def test_the_backup_name_is_not_applied_twice():
    assert half_applied().base_backup_name == "VISLab_FA_BACKUP"


def test_the_intermediate_state_is_still_executable():
    built = half_applied()
    assert built.executable
    assert not built.already_applied


def test_a_name_grabbed_during_the_gap_refuses_the_resume():
    """The live name is unclaimed between the two renames. Something took it."""
    built = half_applied(existing_project_names=["VISLab", "VISLab_FA_BACKUP"])
    assert "final-name-taken" in codes(built)


def test_a_fully_applied_pair_is_recognised_rather_than_refused():
    """Both renames landed. The copy has no suffix left - which is the point.

    Left alone, `candidate-not-suffixed` would fire and tell someone the copy
    cannot take a name it is already holding.
    """
    built = half_applied(candidate_project_name="VISLab")
    assert built.executable
    assert built.already_applied
    assert codes(built) == []
    assert any("already been applied" in w for w in built.warnings)


def test_a_copy_with_no_suffix_is_still_refused_when_nothing_was_renamed():
    """The suppression is narrow: it needs the base to hold the backup name."""
    built = manual_plan(candidate_project_name="VISLab")
    assert "candidate-not-suffixed" in codes(built)


def test_the_manual_flags_round_trip_through_the_stored_plan():
    stored = plan_to_json(manual_plan())
    assert stored["manual"] is True
    assert stored["already_applied"] is False
    assert stored["payload"] == {}
