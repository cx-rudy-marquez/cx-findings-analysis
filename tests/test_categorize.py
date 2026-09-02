"""Grouping the removals by query and CWE, straight off the compare rows."""

from analysis import categorize


def row(status, severity="MEDIUM", query="Reflected XSS", cwe=79, sid=1):
    return {
        "similarityID": sid,
        "status": status,
        "severity": severity,
        "queryName": query,
        "cweID": cwe,
    }


def test_removed_findings_are_the_fixed_rows():
    rows = [row("FIXED", sid=1), row("RECURRENT", sid=2), row("NEW", sid=3)]
    assert [r["similarityID"] for r in categorize.removed_findings(rows)] == [1]


def test_critical_findings_are_never_attributed_to_findings_analysis():
    """Critical is not eligible, so a Critical marked FIXED is scan drift.

    Observed live: 2 Critical came back FIXED on a pair of scans over identical
    source, because the fresh project did not inherit the original's triage.
    """
    rows = [
        row("FIXED", severity="CRITICAL", query="SQL Injection", cwe=89, sid=1),
        row("FIXED", severity="MEDIUM", query="Reflected XSS", cwe=79, sid=2),
    ]
    assert [r["similarityID"] for r in categorize.removed_findings(rows)] == [2]
    assert [b.label for b in categorize.breakdown(rows)] == ["Reflected XSS"]


def test_breakdown_orders_by_most_removed():
    rows = (
        [row("FIXED", query="A", sid=i) for i in range(4)]
        + [row("RECURRENT", query="A", sid=100 + i) for i in range(5)]
        + [row("FIXED", query="B", sid=200 + i) for i in range(5)]
    )
    result = categorize.breakdown(rows)
    # B lost all 5 of its findings, A lost 4 of 9.
    assert [b.label for b in result] == ["B", "A"]
    assert [b.removed for b in result] == [5, 4]
    assert [b.before for b in result] == [5, 9]
    assert result[0].removal_rate_pct == 100.0
    assert result[1].removal_rate_pct == 44.4


def test_breakdown_sorts_by_severity_before_removal_count():
    """A High-severity label sorts first even if a Medium one removed more."""
    rows = [row("FIXED", severity="MEDIUM", query="B", sid=i) for i in range(5)] + [
        row("FIXED", severity="HIGH", query="A", sid=100 + i) for i in range(1)
    ]
    result = categorize.breakdown(rows)
    assert [b.label for b in result] == ["A", "B"]
    assert [b.severity for b in result] == ["HIGH", "MEDIUM"]


def test_appeared_findings_do_not_inflate_the_baseline():
    """A NEW row was never in the baseline, so it must not count towards it."""
    rows = [
        row("FIXED", query="A", sid=1),
        row("RECURRENT", query="A", sid=2),
        row("NEW", query="A", sid=3),
    ]
    assert categorize.breakdown(rows)[0].before == 2


def test_cwe_label_handles_an_unmapped_finding():
    assert categorize.cwe_label(row("FIXED", cwe=89)) == "CWE-89"
    assert categorize.cwe_label(row("FIXED", cwe=None)) == "No CWE mapped"


def test_query_name_falls_back_when_absent():
    assert categorize.query_name({"status": "FIXED"}) == "Unknown query"
