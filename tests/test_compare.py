"""The arithmetic a stakeholder reads off the comparison page.

Input shape is one `/api/scans-compare/sast/status` payload: per severity, a
count for each of NEW / RECURRENT / FIXED.
"""

from analysis.compare import compare, compare_counts, new_state_share


def summary(severities: dict[str, dict[str, int]], totals: bool = True) -> dict:
    """Build a compare payload from {SEVERITY: {STATUS: count}}."""
    payload: dict = {
        "severityStatusCounters": [
            {
                "severity": severity,
                "results": [{"status": s, "count": c} for s, c in statuses.items()],
            }
            for severity, statuses in severities.items()
        ]
    }
    if totals:
        payload["baseScanCounters"] = {
            severity: statuses.get("RECURRENT", 0) + statuses.get("FIXED", 0)
            for severity, statuses in severities.items()
        }
        payload["scanCounters"] = {
            severity: statuses.get("RECURRENT", 0) + statuses.get("NEW", 0)
            for severity, statuses in severities.items()
        }
    return payload


def status_payload(statuses: dict) -> dict:
    return {"statusCounters": [{"status": k, "counter": v} for k, v in statuses.items()]}


def test_absent_severity_reads_as_zero_not_missing():
    counts = compare_counts(summary({"HIGH": {"RECURRENT": 2}}))
    assert counts["MEDIUM"] == {}
    assert set(counts) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def test_removed_is_the_fixed_count_not_a_subtraction():
    """A run that removed 3 and gained 3 nets to zero under subtraction.

    The compare API distinguishes them, and so must the row: reporting 0 removed
    here would hide both the removals and the reason the run is untrustworthy.
    """
    result = compare(summary({"HIGH": {"RECURRENT": 5, "FIXED": 3, "NEW": 3}}), 10)
    high = next(row for row in result.rows if row.severity == "HIGH")
    assert (high.before, high.after) == (8, 8)
    assert high.removed == 3
    assert high.appeared == 3


def test_reduction_excludes_critical_from_the_denominator():
    result = compare(
        summary(
            {
                "CRITICAL": {"RECURRENT": 63},
                "HIGH": {"RECURRENT": 4, "FIXED": 1},
                "MEDIUM": {"RECURRENT": 21, "FIXED": 12},
                "LOW": {"RECURRENT": 15, "FIXED": 12},
            }
        ),
        minutes_per_finding=10,
    )
    assert result.eligible_before == 65
    assert result.removed == 25
    # 25/65, not 25/128 - Critical is not something the feature may act on.
    assert result.eligible_reduction_pct == 38.5
    assert result.backlog_reduction_pct == 19.5


def test_critical_row_is_carried_but_marked_ineligible():
    result = compare(
        summary({"CRITICAL": {"RECURRENT": 10}, "HIGH": {"RECURRENT": 1, "FIXED": 3}}),
        minutes_per_finding=10,
    )
    critical = next(row for row in result.rows if row.severity == "CRITICAL")
    assert critical.eligible is False
    assert critical.before == critical.after == 10
    assert result.removed == 3  # Critical contributes nothing


def test_a_removed_critical_raises_a_comparability_warning():
    result = compare(
        summary({"CRITICAL": {"RECURRENT": 7, "FIXED": 3}, "HIGH": {"RECURRENT": 4}}),
        minutes_per_finding=10,
    )
    assert result.comparable is False
    assert any("Critical finding(s) disappeared" in w for w in result.warnings)


def test_any_appeared_finding_invalidates_the_comparison():
    """Findings Analysis only removes. Anything arriving came from elsewhere."""
    result = compare(summary({"HIGH": {"RECURRENT": 2, "NEW": 3}}), 10)
    assert result.comparable is False
    assert result.appeared == 3
    assert any("present in the Findings Analysis scan" in w for w in result.warnings)


def test_hours_saved_follows_the_stated_assumption():
    result = compare(summary({"HIGH": {"FIXED": 30}}), minutes_per_finding=12)
    assert result.hours_saved == 6.0  # 30 * 12 / 60


def test_empty_payload_does_not_divide_by_zero():
    result = compare(None, minutes_per_finding=10)
    assert result.eligible_reduction_pct == 0.0
    assert result.backlog_reduction_pct == 0.0
    assert result.hours_saved == 0.0
    assert result.comparable is True


def test_scan_totals_that_disagree_with_the_breakdown_are_flagged():
    payload = summary({"HIGH": {"RECURRENT": 4, "FIXED": 1}})
    payload["baseScanCounters"]["HIGH"] = 99  # independently computed, disagrees
    result = compare(payload, 10)
    assert result.comparable is False
    assert any("disagrees with the per-status breakdown" in w for w in result.warnings)


def test_the_live_webgoatnet_shape_is_not_comparable():
    """The real observed run, as the compare API reported it.

    10 findings FIXED (2 of them Critical) and 10 NEW. Re-onboarding a mature
    project into a fresh copy drops its accumulated triage; both symptoms are
    things Findings Analysis cannot produce, so no headline may be published.
    """
    result = compare(
        summary(
            {
                "CRITICAL": {"RECURRENT": 66, "FIXED": 2},
                "HIGH": {"NEW": 5, "RECURRENT": 4, "FIXED": 1},
                "MEDIUM": {"NEW": 4, "RECURRENT": 27, "FIXED": 6},
                "LOW": {"NEW": 1, "RECURRENT": 26, "FIXED": 1},
            }
        ),
        10,
    )
    assert result.comparable is False
    # The baseline the compare API reports, which is the full result set - not
    # scan-summary's 63, which silently excludes FIXED rows.
    critical = next(row for row in result.rows if row.severity == "CRITICAL")
    assert critical.before == 68
    assert result.removed == 8  # eligible only; the 2 Critical are excluded
    assert result.appeared == 10


def test_new_state_share_bounds_the_forecast():
    assert new_state_share(status_payload({"NEW": 20, "RECURRENT": 108})) == 15.6
    assert new_state_share({}) is None
