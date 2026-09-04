"""Ranking a tenant's projects as Findings Analysis candidates.

Two independent signals per project, deliberately not blended:

* **Opportunity score** - how much noise the feature could plausibly remove,
  weighted by severity. Critical is excluded entirely, because the platform
  never evaluates Critical results; including it would rank a project highly for
  findings Findings Analysis is not permitted to touch.
* **Migration risk** - what re-onboarding would cost. Getting the feature onto
  an existing project means creating a new one, and a new project starts with no
  scan history. The risk label prices that loss in the two units that actually
  disappear: scans and branches.

Keeping them apart is the point. A high-benefit, high-risk project and a
low-benefit, low-risk one are different decisions, and a single blended
"recommendation" would hide which of the two a reviewer is looking at.

Everything here is a pure function over plain dicts, so the ranking can be
tested - and retuned - without a tenant.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from config import FA_BACKUP_SUFFIX

LOW_RISK = "Low"
MEDIUM_RISK = "Medium"
HIGH_RISK = "High"

#: Severities the score is built from, highest first. Mirrors
#: `config.ELIGIBLE_SEVERITIES` exactly - every severity Findings Analysis is
#: permitted to evaluate is scored, and only Critical, which it never evaluates,
#: is left out. INFO is in the list because the platform removes Info findings
#: like any other: a backlog that is mostly Info is still a backlog, and scoring
#: it at zero would rank the project as if it had nothing to gain.
SCORED_SEVERITIES: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW", "INFO")


@dataclass(frozen=True)
class RiskLabel:
    level: str
    scans: int
    branches: int

    @property
    def reason(self) -> str:
        """The sentence the UI reveals behind the label.

        A bare "High risk" is a black box; the numbers that produced it are what
        let someone disagree with the thresholds.
        """
        scans = f"{self.scans} scan" + ("" if self.scans == 1 else "s")
        branches = f"{self.branches} branch" + ("" if self.branches == 1 else "es")
        return (
            f"{self.level} risk: re-onboarding would discard {scans} "
            f"across {branches}."
        )


@dataclass
class ProjectRow:
    """One project's portfolio line. Mutable: `flagged` is set during ranking."""

    id: str
    name: str
    main_branch: str | None = None
    repo_url: str | None = None
    criticality: int | None = None
    counts: dict[str, int] | None = None
    baseline_scan_id: str | None = None
    baseline_branch: str | None = None
    baseline_created_at: str | None = None
    #: Read from the project's own SAST configuration at build time. A project
    #: that already has the capability is not a candidate for it, so this is a
    #: fetched fact and belongs in the snapshot - not something re-derived per
    #: page load, which would cost one config call per project on every render.
    findings_analysis_enabled: bool = False
    #: Whether a `<name>_FA` copy already exists in the tenant. Same question
    #: the detail page asks before it redirects to the existing run, answered
    #: from the project list the snapshot build already fetched.
    analysed: bool = False
    scans: int = 0
    branches: int = 0
    score: int | None = None
    risk: RiskLabel | None = None
    flagged: bool = False
    note: str = ""
    #: Derived at render time from the current settings, like `score` and `risk`
    #: - never stored in the snapshot, so changing the threshold re-evaluates
    #: every project without re-reading the tenant.
    baseline_age_days: int | None = None
    rebase_recommended: bool = False

    @property
    def has_baseline(self) -> bool:
        """Whether this project has SAST findings to score at all.

        Distinct from a score of zero. A project with no completed SAST scan is
        unmeasured; one with a real scan and no eligible findings is measured
        and clean. Sorting them together would bury the difference.
        """
        return self.counts is not None

    @property
    def baseline_age_label(self) -> str:
        """The age as the table shows it. Never a bare number of days.

        "142 days ago" reads as precision this figure does not have - the
        baseline is whatever scan happened to run last. Months are the unit the
        three-month threshold is expressed in, so months are the unit shown.
        """
        days = self.baseline_age_days
        if days is None:
            return "unknown"
        if days < 1:
            return "today"
        if days < 31:
            return f"{days}d ago"
        return f"{days // 30} mo ago"


#: Why a project is not offered as a candidate. Short enough to sit in a table
#: cell, specific enough that the detail page can explain itself with the same
#: string the list filtered on.
CONVERTED_ORIGINAL = "already converted"
ALREADY_ENABLED = "Findings Analysis already enabled"


def is_converted_original(name: str) -> bool:
    """Whether this is the disconnected original left behind by a re-onboarding.

    Exact suffix match on the name, because that suffix is applied by this tool
    and by nothing else. A project someone named `..._FA_BACKUP_OLD` by hand is
    not one of ours and stays visible.
    """
    return bool(name) and name.endswith(FA_BACKUP_SUFFIX)


def exclusion_reason(row: "ProjectRow") -> str | None:
    """Why this project is out of scope, or None if it is still a candidate.

    One function, three callers: the list filter, the detail-page block and the
    tests. Splitting it would let the list hide a project the detail page still
    happily starts a run against.
    """
    if is_converted_original(row.name):
        return CONVERTED_ORIGINAL
    if row.findings_analysis_enabled:
        return ALREADY_ENABLED
    return None


def visible_rows(rows: list["ProjectRow"]) -> list["ProjectRow"]:
    """The rows the portfolio is about: projects that could still adopt this.

    Applied before the search filter and before every count above the table, so
    "N of M projects" describes the set on screen rather than the raw tenant.
    """
    return [row for row in rows if exclusion_reason(row) is None]


def baseline_age_days(created_at: str | None, now: datetime | None = None) -> int | None:
    """Whole days since a scan's `createdAt`, or None if it cannot be read.

    None is not zero and not "stale". A project whose baseline date is missing
    or unparseable is *unknown*, and flagging it for re-basing on the strength of
    a timestamp nobody could read would be inventing a recommendation.
    """
    if not created_at:
        return None
    text = str(created_at).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    delta = (now or datetime.now(timezone.utc)) - parsed
    # A clock skew or a scan dated in the future is age zero, not a negative age.
    return max(0, delta.days)


def opportunity_score(counts: dict[str, int] | None, settings: dict) -> int | None:
    """Weighted count of the findings Findings Analysis could act on.

    The authoritative definition of "which project would benefit most". Nothing
    else in the dashboard may compute its own.

    Returns None - not 0 - when there is nothing to score, so an unmeasured
    project cannot be presented as an unattractive one.
    """
    if counts is None:
        return None
    weights = {
        "HIGH": int(settings["weight_high"]),
        "MEDIUM": int(settings["weight_medium"]),
        "LOW": int(settings["weight_low"]),
        "INFO": int(settings["weight_info"]),
    }
    return sum(int(counts.get(sev, 0)) * weights[sev] for sev in SCORED_SEVERITIES)


def migration_risk(scans: int, branches: int, settings: dict) -> RiskLabel:
    """How costly re-onboarding this project would be.

    Low requires *both* counts to be small; High needs only *one* to be large.
    That asymmetry is deliberate - a project with 40 scans on one branch and one
    with 3 scans across 9 branches have each accumulated history worth keeping,
    and either alone is enough to make re-onboarding expensive.
    """
    if (
        scans >= int(settings["risk_high_min_scans"])
        or branches >= int(settings["risk_high_min_branches"])
    ):
        level = HIGH_RISK
    elif (
        scans <= int(settings["risk_low_max_scans"])
        and branches <= int(settings["risk_low_max_branches"])
    ):
        level = LOW_RISK
    else:
        level = MEDIUM_RISK
    return RiskLabel(level=level, scans=scans, branches=branches)


def score_rows(
    rows: list[ProjectRow], settings: dict, now: datetime | None = None
) -> list[ProjectRow]:
    """Apply the score and risk label to every row, then flag the top N.

    Separate from the fetching so retuning a weight re-ranks the stored snapshot
    without touching the tenant - the finding counts did not change.

    `now` defaults to the wall clock and exists so a test can pin the instant it
    measures ages against, the same way `baseline_age_days` already allows. A
    staleness test written against the real clock passes on the day it is
    written and starts failing the next.
    """
    stale_days = max(1, int(settings.get("rebase_stale_days", 0) or 1))
    for row in rows:
        row.score = opportunity_score(row.counts, settings)
        row.risk = migration_risk(row.scans, row.branches, settings)
        row.flagged = False
        row.baseline_age_days = baseline_age_days(row.baseline_created_at, now)
        row.rebase_recommended = (
            row.baseline_age_days is not None and row.baseline_age_days > stale_days
        )

    top_n = max(0, int(settings.get("flag_top_n", 0)))
    ranked = [row for row in rows if row.score is not None and row.score > 0]
    ranked.sort(key=lambda row: -(row.score or 0))
    for row in ranked[:top_n]:
        row.flagged = True
    return rows


#: Sort keys the list page offers. Every one is a total order over rows that may
#: carry a None score, so unmeasured projects sort last rather than first.
SORT_KEYS = ("score", "name", "critical", "scans", "branches", "baseline", "risk")

_RISK_ORDER = {HIGH_RISK: 0, MEDIUM_RISK: 1, LOW_RISK: 2}


def sort_rows(rows: list[ProjectRow], sort: str = "score") -> list[ProjectRow]:
    unmeasured_last = lambda row: row.score is None  # noqa: E731
    if sort == "name":
        return sorted(rows, key=lambda row: row.name.lower())
    if sort == "critical":
        return sorted(
            rows,
            key=lambda row: (unmeasured_last(row), -(row.counts or {}).get("CRITICAL", 0)),
        )
    if sort == "scans":
        return sorted(rows, key=lambda row: -row.scans)
    if sort == "branches":
        return sorted(rows, key=lambda row: -row.branches)
    if sort == "baseline":
        # Oldest baseline first - the point of sorting on this column is to find
        # what needs re-basing. Projects with no readable baseline date sort
        # last: they are not old, they are unknown.
        return sorted(
            rows,
            key=lambda row: (
                row.baseline_age_days is None,
                -(row.baseline_age_days or 0),
            ),
        )
    if sort == "risk":
        return sorted(
            rows,
            key=lambda row: (
                _RISK_ORDER.get(row.risk.level if row.risk else "", 3),
                -(row.score or 0),
            ),
        )
    return sorted(rows, key=lambda row: (unmeasured_last(row), -(row.score or 0)))


def rebase_count(rows: list[ProjectRow]) -> int:
    """How many projects the snapshot bar should report as needing a re-base."""
    return sum(1 for row in rows if row.rebase_recommended)


def risk_distribution(rows: list[ProjectRow]) -> dict[str, int]:
    """Count per risk level, for the summary line above the table."""
    counts = {LOW_RISK: 0, MEDIUM_RISK: 0, HIGH_RISK: 0}
    for row in rows:
        if row.risk:
            counts[row.risk.level] = counts.get(row.risk.level, 0) + 1
    return counts
