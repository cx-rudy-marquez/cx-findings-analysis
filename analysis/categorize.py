"""Which findings Findings Analysis removed, and what kinds they were.

The headline counts come from `/api/scans-compare/sast/status`. This module
answers the follow-up question a skeptical reviewer always asks: *which*
findings went away? Knowing that the removals cluster in one or two query types
is what turns "the AI deleted 40 results" into "the AI deleted the reflected-XSS
false positives we already ignore by hand every sprint".

Rows come from `/api/sast-results/compare`, which classifies each finding across
the two scans as NEW, RECURRENT or FIXED. Removals are simply the FIXED rows -
the platform does the matching. An earlier version of this module joined two
separate result sets on `similarityId` and inferred disappearance from what
failed to match; on the live WebGoatNet pair that join covered only 112 of 133
findings, and every unmatched row was indistinguishable from a real removal.

Each compare row carries `queryName`, `cweID`, `group`, `languageName` and
`severity`, so grouping needs no second fetch.
"""

from __future__ import annotations

from dataclasses import dataclass

from analysis.compare import REMOVED_STATUS, SURVIVED_STATUS
from config import ELIGIBLE_SEVERITIES


@dataclass(frozen=True)
class CategoryBreakdown:
    label: str
    removed: int
    before: int

    @property
    def removal_rate_pct(self) -> float:
        if self.before <= 0:
            return 0.0
        return round(self.removed / self.before * 100, 1)


def eligible_only(rows: list[dict]) -> list[dict]:
    """Compare rows Findings Analysis is permitted to act on.

    Critical is excluded because the feature never touches it. Observed live: a
    baseline and a re-onboarded copy of the same source disagreed on Critical
    anyway - the mature project carried triage severity overrides the fresh one
    did not - and without this filter those rows are attributed to Findings
    Analysis in the breakdown, inventing removals it cannot have made.
    """
    return [
        row
        for row in rows
        if str(row.get("severity") or "").strip().upper() in ELIGIBLE_SEVERITIES
    ]


def query_name(row: dict) -> str:
    return str(row.get("queryName") or "Unknown query")


def cwe_label(row: dict) -> str:
    cwe = row.get("cweID")
    if cwe in (None, "", 0):
        return "No CWE mapped"
    return f"CWE-{cwe}"


def removed_findings(rows: list[dict]) -> list[dict]:
    """Eligible findings the platform classified as gone in the second scan."""
    return [
        row
        for row in eligible_only(rows)
        if str(row.get("status") or "").strip().upper() == REMOVED_STATUS
    ]


def breakdown(
    rows: list[dict], key=query_name, limit: int = 15
) -> list[CategoryBreakdown]:
    """Removed findings grouped by `key`, most-removed first.

    Baseline counts ride along in each row so a category can be read as a rate,
    not just a raw count: 8 of 9 removed is a much stronger signal about that
    query type than 8 of 400. "Baseline" here means the findings that were in
    the first scan - the ones that survived plus the ones removed, excluding
    anything that only appeared in the second.
    """
    eligible = eligible_only(rows)

    baseline_totals: dict[str, int] = {}
    for row in eligible:
        if str(row.get("status") or "").strip().upper() not in (
            REMOVED_STATUS,
            SURVIVED_STATUS,
        ):
            continue
        label = key(row)
        baseline_totals[label] = baseline_totals.get(label, 0) + 1

    removed_totals: dict[str, int] = {}
    for row in removed_findings(rows):
        label = key(row)
        removed_totals[label] = removed_totals.get(label, 0) + 1

    breakdown_rows = [
        CategoryBreakdown(
            label=label, removed=count, before=baseline_totals.get(label, count)
        )
        for label, count in removed_totals.items()
    ]
    breakdown_rows.sort(key=lambda row: (-row.removed, row.label))
    return breakdown_rows[:limit]
