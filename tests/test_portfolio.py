"""Ranking projects as Findings Analysis candidates.

The score and the risk label are the two numbers a reviewer acts on, and both
are tuning-dependent, so the boundaries are pinned exactly.
"""

import pytest

from analysis import portfolio
from analysis.portfolio import ProjectRow
from config import settings

TUNING = settings.portfolio_defaults()


def row(name="p", counts=None, scans=0, branches=0, **kw):
    return ProjectRow(id=name, name=name, counts=counts, scans=scans, branches=branches, **kw)


def counts(critical=0, high=0, medium=0, low=0, info=0):
    return {
        "CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low, "INFO": info
    }


# -- opportunity score --------------------------------------------------------


def test_score_is_the_weighted_sum_of_eligible_severities():
    assert portfolio.opportunity_score(counts(high=5, medium=33, low=27), TUNING) == (
        5 * 3 + 33 * 2 + 27 * 1
    )


def test_critical_never_contributes_to_the_score():
    """Findings Analysis is not permitted to touch Critical results."""
    without = portfolio.opportunity_score(counts(high=2), TUNING)
    with_critical = portfolio.opportunity_score(counts(critical=999, high=2), TUNING)
    assert without == with_critical == 6


def test_info_contributes_at_its_configured_weight():
    """Info is eligible, so it scores. This reverses an earlier decision.

    The platform removes Info findings like any other, so a backlog that is
    mostly Info is still a backlog. Scoring it at zero ranked such a project as
    having nothing to gain.
    """
    assert portfolio.opportunity_score(counts(info=500), TUNING) == 500


def test_info_can_still_be_tuned_out():
    """Weight 1 is a default, not a verdict - a team that does not triage Info
    turns it off in settings rather than needing a code change."""
    muted = {**TUNING, "weight_info": 0}
    assert portfolio.opportunity_score(counts(info=500), muted) == 0
    assert portfolio.opportunity_score(counts(high=2, info=500), muted) == 6


def test_info_is_weighted_but_critical_is_still_not():
    """The two absences from the old formula were never the same thing.

    Guards the copy-paste that adds Critical alongside Info: Critical must stay
    unscored no matter how large it is.
    """
    scored = portfolio.opportunity_score(counts(critical=999, info=7), TUNING)
    assert scored == 7


def test_a_project_without_a_baseline_scores_none_not_zero():
    """Unmeasured and measured-but-clean are different, and must stay different."""
    assert portfolio.opportunity_score(None, TUNING) is None
    assert portfolio.opportunity_score(counts(), TUNING) == 0


def test_weights_come_from_settings_not_from_code():
    tuned = {**TUNING, "weight_high": 10, "weight_medium": 0, "weight_low": 0}
    assert portfolio.opportunity_score(counts(high=4, medium=99, low=99), tuned) == 40


# -- migration risk -----------------------------------------------------------


@pytest.mark.parametrize(
    "scans,branches,expected",
    [
        (0, 0, portfolio.LOW_RISK),
        (2, 1, portfolio.LOW_RISK),      # exactly at the Low ceiling
        (3, 1, portfolio.MEDIUM_RISK),   # one over on scans
        (2, 2, portfolio.MEDIUM_RISK),   # one over on branches
        (9, 3, portfolio.MEDIUM_RISK),   # just under both High floors
        (10, 1, portfolio.HIGH_RISK),    # exactly at the High scan floor
        (1, 4, portfolio.HIGH_RISK),     # exactly at the High branch floor
        (58, 2, portfolio.HIGH_RISK),    # the tenant's heaviest project
        (31, 11, portfolio.HIGH_RISK),
    ],
)
def test_risk_boundaries(scans, branches, expected):
    assert portfolio.migration_risk(scans, branches, TUNING).level == expected


def test_high_risk_needs_only_one_signal_but_low_risk_needs_both():
    # 40 scans on a single branch is still expensive to discard.
    assert portfolio.migration_risk(40, 1, TUNING).level == portfolio.HIGH_RISK
    # ...and so is a little history spread across many branches.
    assert portfolio.migration_risk(3, 9, TUNING).level == portfolio.HIGH_RISK


def test_the_reason_states_the_numbers_behind_the_label():
    """The label must never be a black box - GOAL_PHASE2 requires the figures."""
    reason = portfolio.migration_risk(42, 5, TUNING).reason
    assert reason == "High risk: re-onboarding would discard 42 scans across 5 branches."


def test_the_reason_reads_correctly_in_the_singular():
    assert "1 scan across 1 branch." in portfolio.migration_risk(1, 1, TUNING).reason


# -- ranking ------------------------------------------------------------------


def test_top_n_are_flagged_by_score():
    rows = [
        row("low", counts(low=1)),
        row("high", counts(high=40)),
        row("mid", counts(medium=20)),
    ]
    portfolio.score_rows(rows, {**TUNING, "flag_top_n": 2})
    assert {r.name for r in rows if r.flagged} == {"high", "mid"}


def test_a_zero_scoring_project_is_never_flagged():
    """Flagging the top N must not promote a project with nothing to remove."""
    rows = [row("clean", counts(critical=99)), row("none", None)]
    portfolio.score_rows(rows, {**TUNING, "flag_top_n": 5})
    assert not any(r.flagged for r in rows)


def test_unmeasured_projects_sort_last_not_first():
    rows = [row("unmeasured", None), row("measured", counts(high=1))]
    portfolio.score_rows(rows, TUNING)
    assert [r.name for r in portfolio.sort_rows(rows, "score")] == [
        "measured",
        "unmeasured",
    ]


def test_risk_sort_puts_the_most_expensive_first():
    rows = [
        row("safe", counts(high=1), scans=1, branches=1),
        row("costly", counts(high=1), scans=99, branches=9),
    ]
    portfolio.score_rows(rows, TUNING)
    assert [r.name for r in portfolio.sort_rows(rows, "risk")] == ["costly", "safe"]


def test_risk_distribution_counts_every_row():
    rows = [
        row("a", counts(high=1), scans=1, branches=1),
        row("b", counts(high=1), scans=5, branches=2),
        row("c", counts(high=1), scans=50, branches=1),
    ]
    portfolio.score_rows(rows, TUNING)
    assert portfolio.risk_distribution(rows) == {"Low": 1, "Medium": 1, "High": 1}


# --- Phase 3: baseline age and the re-base recommendation --------------------

from datetime import datetime, timedelta, timezone  # noqa: E402

from analysis.portfolio import baseline_age_days, rebase_count  # noqa: E402
from cx.portfolio import rows_from_json, rows_to_json  # noqa: E402

#: A fixed instant. Every age below is measured from it and `score_rows` is
#: told so, because a staleness assertion against the wall clock passes on
#: the day it is written and fails the next.
NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def test_baseline_age_is_counted_in_whole_days():
    assert baseline_age_days("2026-08-20T12:00:00Z", now=NOW) == 10


def test_a_naive_timestamp_is_read_as_utc():
    """The API returns Z-suffixed times; a stored snapshot may not."""
    assert baseline_age_days("2026-08-20T12:00:00", now=NOW) == 10


def test_an_unreadable_baseline_date_is_unknown_not_stale():
    """The one answer that must never be invented."""
    for value in (None, "", "not a date", "2026-13-45"):
        assert baseline_age_days(value, now=NOW) is None


def test_a_future_baseline_date_is_age_zero_not_negative():
    assert baseline_age_days("2027-01-01T00:00:00Z", now=NOW) == 0


def test_the_threshold_is_exclusive_at_the_boundary():
    """Exactly at the threshold is not yet past it."""
    stale = dict(TUNING, rebase_stale_days=90)
    at = portfolio.ProjectRow(
        id="at", name="at",
        baseline_created_at=(NOW - timedelta(days=90)).isoformat(),
        counts={"HIGH": 1},
    )
    past = portfolio.ProjectRow(
        id="past", name="past",
        baseline_created_at=(NOW - timedelta(days=91)).isoformat(),
        counts={"HIGH": 1},
    )
    portfolio.score_rows([at, past], stale, now=NOW)
    assert at.rebase_recommended is False
    assert past.rebase_recommended is True


def test_a_project_with_no_baseline_date_is_never_flagged():
    row = portfolio.ProjectRow(id="x", name="x", counts={"HIGH": 1})
    portfolio.score_rows([row], TUNING)
    assert row.baseline_age_days is None
    assert row.rebase_recommended is False
    assert row.baseline_age_label == "unknown"


def test_raising_the_threshold_clears_the_flag_without_refetching():
    """The recommendation is derived at render time, like the score."""
    row = portfolio.ProjectRow(
        id="x", name="x", counts={"HIGH": 1},
        baseline_created_at=(NOW - timedelta(days=120)).isoformat(),
    )
    portfolio.score_rows([row], dict(TUNING, rebase_stale_days=90), now=NOW)
    assert row.rebase_recommended is True
    portfolio.score_rows([row], dict(TUNING, rebase_stale_days=365), now=NOW)
    assert row.rebase_recommended is False


def test_rebase_count_reports_only_flagged_rows():
    rows = [
        portfolio.ProjectRow(id=str(i), name=str(i), counts={"HIGH": 1},
                             baseline_created_at=(NOW - timedelta(days=days)).isoformat())
        for i, days in enumerate((10, 200, 400))
    ]
    portfolio.score_rows(rows, dict(TUNING, rebase_stale_days=90), now=NOW)
    assert rebase_count(rows) == 2


def test_sorting_by_baseline_puts_the_oldest_first_and_unknown_last():
    rows = [
        portfolio.ProjectRow(id="unknown", name="unknown", counts={"HIGH": 1}),
        portfolio.ProjectRow(id="recent", name="recent", counts={"HIGH": 1},
                             baseline_created_at=(NOW - timedelta(days=5)).isoformat()),
        portfolio.ProjectRow(id="ancient", name="ancient", counts={"HIGH": 1},
                             baseline_created_at=(NOW - timedelta(days=500)).isoformat()),
    ]
    portfolio.score_rows(rows, TUNING, now=NOW)
    assert [row.id for row in portfolio.sort_rows(rows, "baseline")] == [
        "ancient", "recent", "unknown",
    ]


def test_the_baseline_date_survives_the_snapshot_round_trip():
    row = portfolio.ProjectRow(
        id="x", name="x", baseline_created_at="2026-05-01T00:00:00Z"
    )
    assert rows_from_json(rows_to_json([row]))[0].baseline_created_at == (
        "2026-05-01T00:00:00Z"
    )


def test_a_snapshot_written_before_this_column_existed_still_loads():
    """An old cached snapshot must not take the page down."""
    old = [{"id": "x", "name": "x", "counts": None, "scans": 1, "branches": 1}]
    row = rows_from_json(old)[0]
    assert row.baseline_created_at is None


def test_an_unknown_snapshot_key_is_ignored_rather_than_fatal():
    """A snapshot from a newer build is read for what it has in common."""
    row = rows_from_json([{"id": "x", "name": "x", "invented_later": 1}])[0]
    assert row.id == "x"


def test_the_age_label_reads_in_months_once_past_a_month():
    row = portfolio.ProjectRow(
        id="x", name="x", counts={"HIGH": 1},
        baseline_created_at=(NOW - timedelta(days=155)).isoformat(),
    )
    portfolio.score_rows([row], TUNING, now=NOW)
    assert row.baseline_age_label == "5 mo ago"


# --- Phase 3.1: which projects are still candidates ---------------------------

from analysis.portfolio import (  # noqa: E402
    ALREADY_ENABLED,
    CONVERTED_ORIGINAL,
    exclusion_reason,
    is_converted_original,
    visible_rows,
)


def test_the_backup_suffix_is_matched_exactly_not_loosely():
    assert is_converted_original("acme/checkout_FA_BACKUP")
    # Ours end there. Anything past the suffix was named by a person.
    assert not is_converted_original("acme/checkout_FA_BACKUP_OLD")
    assert not is_converted_original("acme/checkout_FA")
    assert not is_converted_original("acme/checkout")
    assert not is_converted_original("")


def test_a_converted_original_is_out_of_scope():
    assert exclusion_reason(row(name="acme/x_FA_BACKUP")) == CONVERTED_ORIGINAL


def test_a_project_already_running_the_capability_is_out_of_scope():
    assert exclusion_reason(row(findings_analysis_enabled=True)) == ALREADY_ENABLED


def test_an_ordinary_project_is_still_a_candidate():
    assert exclusion_reason(row(name="acme/x")) is None


def test_the_name_rule_is_reported_ahead_of_the_flag():
    """A converted original explains itself by what it is, not by a setting."""
    excluded = row(name="acme/x_FA_BACKUP", findings_analysis_enabled=True)
    assert exclusion_reason(excluded) == CONVERTED_ORIGINAL


def test_visible_rows_drops_both_kinds_and_keeps_the_rest():
    rows = [
        row(name="acme/keep"),
        row(name="acme/gone_FA_BACKUP"),
        row(name="acme/enabled", findings_analysis_enabled=True),
    ]
    assert [r.name for r in visible_rows(rows)] == ["acme/keep"]


def test_the_flag_survives_the_snapshot_round_trip():
    stored = rows_to_json([row(name="x", findings_analysis_enabled=True)])
    assert rows_from_json(stored)[0].findings_analysis_enabled is True


def test_a_snapshot_written_before_the_flag_existed_shows_its_projects():
    """Failing visible is the safe direction: a stale cache must not hide work.

    A snapshot from before this column was collected knows nothing about the
    capability. Defaulting those rows to "enabled" would empty the list until
    someone happened to press Refresh.
    """
    old = [{"id": "x", "name": "x", "counts": None, "scans": 1, "branches": 1}]
    assert rows_from_json(old)[0].findings_analysis_enabled is False
    assert visible_rows(rows_from_json(old)) != []


# --- Phase 3.1: what the build spends on the flag -----------------------------

from cx.errors import CxApiError  # noqa: E402
from cx.portfolio import build_rows  # noqa: E402


class ConfigClient:
    """Minimal portfolio-shaped client that records which configs were read."""

    def __init__(self, projects, configs=None, failing=()):
        self.projects = projects
        self.configs = configs or {}
        self.failing = set(failing)
        self.config_reads = []

    def get_projects(self):
        return list(self.projects)

    def get_last_sast_scans(self, project_ids, branch=None):
        return {}

    def get_scan_summaries(self, scan_ids):
        return {}

    def iter_all_scans(self):
        return iter(())

    def get_project_config(self, project_id):
        self.config_reads.append(project_id)
        if project_id in self.failing:
            raise CxApiError("configuration/project returned 503")
        return self.configs.get(project_id, [])


def _fa_on():
    return [{"key": "scan.config.sast.findingsAnalysis", "value": "true"}]


def test_the_build_reads_the_flag_for_every_project_it_may_show():
    client = ConfigClient(
        [{"id": "a", "name": "acme/a"}, {"id": "b", "name": "acme/b"}],
        configs={"b": _fa_on()},
    )
    rows = {r.id: r for r in build_rows(client)}
    assert sorted(client.config_reads) == ["a", "b"]
    assert rows["a"].findings_analysis_enabled is False
    assert rows["b"].findings_analysis_enabled is True


def test_the_build_does_not_pay_for_a_project_its_name_already_excludes():
    client = ConfigClient(
        [{"id": "a", "name": "acme/a"}, {"id": "old", "name": "acme/old_FA_BACKUP"}]
    )
    build_rows(client)
    assert client.config_reads == ["a"]


def test_a_failed_config_read_leaves_the_project_visible():
    """One 503 must not silently drop a candidate off the list."""
    client = ConfigClient([{"id": "a", "name": "acme/a"}], failing={"a"})
    row = build_rows(client)[0]
    assert row.findings_analysis_enabled is False
    assert visible_rows([row]) == [row]


# --- Phase 3.1: which projects have already been analysed ---------------------


def test_a_project_is_analysed_when_its_copy_exists_in_the_tenant():
    client = ConfigClient([
        {"id": "a", "name": "acme/a"},
        {"id": "a-fa", "name": "acme/a_FA"},
        {"id": "b", "name": "acme/b"},
    ])
    rows = {r.id: r for r in build_rows(client)}
    assert rows["a"].analysed is True
    assert rows["b"].analysed is False


def test_a_copy_is_not_itself_marked_analysed():
    """`acme/a_FA_FA` does not exist, so the copy is not analysed."""
    client = ConfigClient([
        {"id": "a", "name": "acme/a"}, {"id": "a-fa", "name": "acme/a_FA"},
    ])
    rows = {r.id: r for r in build_rows(client)}
    assert rows["a-fa"].analysed is False


def test_a_near_miss_name_does_not_count_as_a_copy():
    client = ConfigClient([
        {"id": "a", "name": "acme/a"}, {"id": "x", "name": "acme/a_FACTORY"},
    ])
    assert build_rows(client)[0].analysed is False


def test_the_analysed_flag_survives_the_snapshot_round_trip():
    stored = rows_to_json([row(name="x", analysed=True)])
    assert rows_from_json(stored)[0].analysed is True


def test_a_snapshot_written_before_the_analysed_flag_defaults_to_false():
    old = [{"id": "x", "name": "x", "counts": None, "scans": 1, "branches": 1}]
    assert rows_from_json(old)[0].analysed is False
