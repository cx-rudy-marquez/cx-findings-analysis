"""Before/after arithmetic for a Findings Analysis impact run.

Everything here is a pure function over one `/api/scans-compare/sast/status`
payload, so the numbers a stakeholder sees can be tested without a tenant.

That payload is the platform's own comparison of the two scans: it classifies
every finding as NEW, RECURRENT or FIXED rather than leaving us to infer
disappearance from count deltas. Two consequences shape this module:

* `removed` is the FIXED count, not `before - after`. Subtraction nets
  appearances against removals, so a run that removed 8 and gained 8 would
  report a clean zero and look like a comparison that simply found nothing.
* Findings Analysis can only *remove* eligible findings. So on a valid run NEW
  is 0 and no CRITICAL is FIXED. Either violation means the two scans differ by
  something other than the feature, and `comparable` turns False - see the live
  finding recorded in README: re-onboarding a mature project into a fresh copy
  drops its accumulated triage, which shows up as exactly these two symptoms.

The other invariant worth stating plainly: CRITICAL is never eligible for
Findings Analysis. The platform returns Critical results untouched, so a flat
Critical row is the correct outcome, not a disappointing one. The comparison
carries that severity in its own labelled bucket rather than folding it into a
total where it would quietly drag the reduction percentage down.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from config import (
    ELIGIBLE_SEVERITIES,
    INELIGIBLE_SEVERITY,
    SEVERITY_ORDER,
)

#: Statuses in a compare response. NOT_EVALUATED only appears when
#: `evaluation-status=true` is requested, which the client does not do (it 500s
#: on this tenant) - tolerated here so an unexpected one is never silently
#: counted as something else.
REMOVED_STATUS = "FIXED"
APPEARED_STATUS = "NEW"
SURVIVED_STATUS = "RECURRENT"

log = logging.getLogger(__name__)


def _warn_unknown_severity(severity: str, source: str) -> None:
    """Say so when the platform sends a severity this module does not know.

    Both flatteners below silently skip anything outside `SEVERITY_ORDER`. That
    is the right behaviour - guessing which known severity an unrecognised
    string meant would put findings in the wrong row - but done silently it is
    indistinguishable from a severity that genuinely had no findings. If a
    tenant ever answers `INFORMATION` where this code expects `INFO`, every Info
    figure in the app reads zero and looks entirely correct.

    A diagnostic, never a fallback. Do not map the unknown value onto a known
    one here.
    """
    log.warning(
        "Ignoring unrecognised severity %r from %s; expected one of %s. "
        "Findings at this severity are missing from every figure derived from "
        "this response.",
        severity, source, ", ".join(SEVERITY_ORDER),
    )


def severity_counts(sast_counters: dict | None) -> dict[str, int]:
    """Flatten a scan-summary's `sastCounters.severityCounters` into {SEVERITY: n}.

    Used only for the project page's pre-run baseline, where no second scan
    exists yet and the compare endpoints have nothing to compare. Note this is
    not the same measurement as `compare_counts`: `severityCounters` exclude
    results the platform considers FIXED, so this reads lower than the compare
    API's `baseScanCounters` for the same scan (63 vs 68 on WebGoatNet). Do not
    mix the two in one calculation.
    """
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for entry in (sast_counters or {}).get("severityCounters") or []:
        severity = str(entry.get("severity") or "").upper()
        if severity in counts:
            counts[severity] = int(entry.get("counter") or 0)
        elif severity:
            _warn_unknown_severity(severity, "scan-summary severityCounters")
    return counts


def status_counts(sast_counters: dict | None) -> dict[str, int]:
    """Flatten a scan-summary's `sastCounters.statusCounters` into {STATUS: n}.

    Still sourced from `/api/scan-summary` rather than the compare endpoint,
    because it describes the *baseline alone* - how much of it was in NEW state,
    which is what bounds the benefit an established project can expect on future
    scans.
    """
    counts: dict[str, int] = {}
    for entry in (sast_counters or {}).get("statusCounters") or []:
        status = str(entry.get("status") or "").upper()
        if status:
            counts[status] = counts.get(status, 0) + int(entry.get("counter") or 0)
    return counts


def compare_counts(compare_summary: dict | None) -> dict[str, dict[str, int]]:
    """Flatten `severityStatusCounters` into {SEVERITY: {STATUS: count}}.

    Absent severities are present with zeroes rather than missing: a severity
    that dropped to nothing must still render as a row, otherwise the biggest
    win in the run disappears from the table.
    """
    counts: dict[str, dict[str, int]] = {
        severity: {} for severity in SEVERITY_ORDER
    }
    for entry in (compare_summary or {}).get("severityStatusCounters") or []:
        severity = str(entry.get("severity") or "").upper()
        if severity not in counts:
            if severity:
                _warn_unknown_severity(
                    severity, "scans-compare severityStatusCounters"
                )
            continue
        for row in entry.get("results") or []:
            status = str(row.get("status") or "").upper()
            if status:
                counts[severity][status] = counts[severity].get(status, 0) + int(
                    row.get("count") or 0
                )
    return counts


@dataclass(frozen=True)
class SeverityRow:
    severity: str
    removed: int
    appeared: int
    survived: int
    eligible: bool

    @property
    def before(self) -> int:
        """Findings this severity had in the baseline: survived plus removed."""
        return self.survived + self.removed

    @property
    def after(self) -> int:
        """Findings this severity has in the Findings Analysis scan."""
        return self.survived + self.appeared

    @property
    def reduction_pct(self) -> float:
        if self.before <= 0:
            return 0.0
        return round(self.removed / self.before * 100, 1)


@dataclass(frozen=True)
class Comparison:
    rows: list[SeverityRow]
    minutes_per_finding: int
    warnings: list[str] = field(default_factory=list)

    @property
    def eligible_rows(self) -> list[SeverityRow]:
        return [row for row in self.rows if row.eligible]

    @property
    def ineligible_rows(self) -> list[SeverityRow]:
        return [row for row in self.rows if not row.eligible]

    @property
    def eligible_before(self) -> int:
        return sum(row.before for row in self.eligible_rows)

    @property
    def eligible_after(self) -> int:
        return sum(row.after for row in self.eligible_rows)

    @property
    def removed(self) -> int:
        return sum(row.removed for row in self.eligible_rows)

    @property
    def appeared(self) -> int:
        return sum(row.appeared for row in self.rows)

    @property
    def total_before(self) -> int:
        return sum(row.before for row in self.rows)

    @property
    def total_after(self) -> int:
        return sum(row.after for row in self.rows)

    @property
    def eligible_reduction_pct(self) -> float:
        """Reduction across the severities Findings Analysis can actually act on.

        This is the honest headline. Dividing by the all-severity total instead
        would dilute the figure with Critical findings the feature is not
        permitted to touch.
        """
        if self.eligible_before <= 0:
            return 0.0
        return round(self.removed / self.eligible_before * 100, 1)

    @property
    def backlog_reduction_pct(self) -> float:
        """Reduction across the whole SAST backlog, Critical included.

        Reported alongside the eligible figure because it is the number a
        security lead feels: how much smaller is the queue.
        """
        if self.total_before <= 0:
            return 0.0
        return round(self.removed / self.total_before * 100, 1)

    @property
    def hours_saved(self) -> float:
        return round(self.removed * self.minutes_per_finding / 60, 1)

    @property
    def comparable(self) -> bool:
        """Whether the two scans can be read as a controlled before/after.

        False when the platform's own classification shows something Findings
        Analysis cannot do - findings appearing, or a Critical disappearing. The
        templates use this to withhold the headline rather than publish a
        business case built on drift.
        """
        return not self.warnings


def compare(
    compare_summary: dict | None,
    minutes_per_finding: int,
) -> Comparison:
    counts = compare_counts(compare_summary)

    rows = [
        SeverityRow(
            severity=severity,
            removed=counts[severity].get(REMOVED_STATUS, 0),
            appeared=counts[severity].get(APPEARED_STATUS, 0),
            survived=counts[severity].get(SURVIVED_STATUS, 0),
            eligible=severity in ELIGIBLE_SEVERITIES,
        )
        for severity in SEVERITY_ORDER
    ]

    warnings: list[str] = []

    critical_removed = counts[INELIGIBLE_SEVERITY].get(REMOVED_STATUS, 0)
    if critical_removed:
        # Findings Analysis cannot have caused this. Something else differs
        # between the two scans - a different preset, a different commit, or a
        # fresh project that did not inherit the original's triage - and the
        # whole comparison is suspect. Say so loudly rather than presenting a
        # clean-looking table.
        warnings.append(
            f"{critical_removed} Critical finding(s) disappeared between the two "
            "scans. Findings Analysis never modifies Critical results, so the "
            "two scans are not a controlled comparison - check the preset, "
            "branch and commit."
        )

    appeared = sum(row.appeared for row in rows)
    if appeared:
        warnings.append(
            f"{appeared} finding(s) are present in the Findings Analysis scan "
            "but not in the baseline. The feature only ever removes results, so "
            "these come from a difference between the scans themselves."
        )

    warnings.extend(_reconciliation_warnings(compare_summary, rows))

    return Comparison(
        rows=rows, minutes_per_finding=minutes_per_finding, warnings=warnings
    )


def _reconciliation_warnings(
    compare_summary: dict | None, rows: list[SeverityRow]
) -> list[str]:
    """Check the per-status breakdown against the response's own scan totals.

    `baseScanCounters` and `scanCounters` are computed independently of
    `severityStatusCounters` in the same response, so disagreement means one of
    the two is not describing the scans we think it is. Cheap to check, and the
    alternative is publishing a figure that does not add up.
    """
    payload = compare_summary or {}
    base_totals = payload.get("baseScanCounters") or {}
    scan_totals = payload.get("scanCounters") or {}
    if not base_totals and not scan_totals:
        return []

    warnings: list[str] = []
    for row in rows:
        for label, totals, derived in (
            ("baseline", base_totals, row.before),
            ("Findings Analysis scan", scan_totals, row.after),
        ):
            if row.severity not in totals:
                continue
            reported = int(totals.get(row.severity) or 0)
            if reported != derived:
                warnings.append(
                    f"{row.severity} {label} total disagrees with the per-status "
                    f"breakdown ({reported} vs {derived}); treat these figures "
                    "as unverified."
                )
    return warnings


def new_state_share(sast_counters: dict | None) -> float | None:
    """Share of baseline findings in NEW state, as a percentage.

    Findings Analysis only evaluates findings in NEW state. On a first scan
    everything is NEW, which is why a re-onboarded project shows the full drop.
    An established project only sees the benefit on newly introduced findings,
    so this figure is what a stakeholder should extrapolate from - not the
    headline reduction.
    """
    counts = status_counts(sast_counters)
    total = sum(counts.values())
    if total <= 0:
        return None
    return round(counts.get("NEW", 0) / total * 100, 1)
