"""The check that decides whether a comparison means anything.

A false "everything matches" is the dangerous failure here: it certifies a
number that a preset swap or an exclusion change actually produced. So these
tests lean on the normalisation rules, which are where that mistake would hide.
"""

from analysis.parity import compare_config
from config import FINDINGS_ANALYSIS_KEY, SAST_PARITY_FIELDS, SAST_PRESET_KEY

FAST = "scan.config.sast.fastScanMode"
FILTER = "scan.config.sast.filter"
EXCLUSIONS = "scan.config.sast.recommendedExclusions"


def config(**overrides) -> list[dict]:
    """A full SAST configuration document, with named keys overridden."""
    values = {key: "false" for key, _, _ in SAST_PARITY_FIELDS}
    values[SAST_PRESET_KEY] = "ASA Premium"
    values[FILTER] = ""
    values.update(overrides)
    return [{"key": key, "value": value} for key, value in values.items()]


def field(report, key):
    return next(f for f in report.fields if f.key == key)


def test_identical_configurations_are_reliable():
    report = compare_config(config(), config())
    assert report.reliable
    assert report.mismatches == ()
    assert report.total == 7


def test_the_findings_analysis_difference_is_the_point_not_a_mismatch():
    report = compare_config(
        config(**{FINDINGS_ANALYSIS_KEY: "false"}),
        config(**{FINDINGS_ANALYSIS_KEY: "true"}),
    )
    assert report.reliable
    assert report.mismatches == ()
    # It is still reported as a difference - just an intended one.
    assert not field(report, FINDINGS_ANALYSIS_KEY).matches
    assert field(report, FINDINGS_ANALYSIS_KEY).expected_to_differ


def test_a_clean_run_reads_as_all_seven_not_six_of_seven():
    """The summary must not describe a correct run as a near miss."""
    report = compare_config(
        config(**{FINDINGS_ANALYSIS_KEY: "false"}),
        config(**{FINDINGS_ANALYSIS_KEY: "true"}),
    )
    assert report.matched == 6          # literal equality
    assert report.as_expected == 7      # what the reader is told
    assert report.summary == "7 of 7 SAST parameters as expected"


def test_one_unexpected_difference_makes_the_result_unreliable():
    report = compare_config(config(**{FAST: "false"}), config(**{FAST: "true"}))
    assert not report.reliable
    assert [f.key for f in report.mismatches] == [FAST]
    mismatch = field(report, FAST)
    assert mismatch.base == "false"
    assert mismatch.candidate == "true"


def test_every_unexpected_difference_is_listed_individually():
    report = compare_config(
        config(**{FAST: "false", EXCLUSIONS: "true"}),
        config(**{FAST: "true", EXCLUSIONS: "false"}),
    )
    assert {f.key for f in report.mismatches} == {FAST, EXCLUSIONS}


def test_an_absent_key_and_an_empty_value_mean_the_same_thing():
    """Both say "inherit from the tenant". Reporting a difference invents one."""
    without = [row for row in config() if row["key"] != FILTER]
    report = compare_config(without, config(**{FILTER: ""}))
    assert report.reliable
    assert field(report, FILTER).base_display == "not set"


def test_boolean_casing_is_not_a_configuration_difference():
    report = compare_config(config(**{FAST: "True"}), config(**{FAST: "true"}))
    assert report.reliable


def test_a_preset_the_base_pins_is_not_a_mismatch():
    """The scan payload carries it, so both scans ran the same rule set."""
    report = compare_config(
        config(**{SAST_PRESET_KEY: "ASA Premium"}),
        config(**{SAST_PRESET_KEY: ""}),
    )
    assert report.reliable
    preset = field(report, SAST_PRESET_KEY)
    assert preset.matches
    assert "ASA Premium" in preset.note


def test_a_preset_only_the_candidate_pins_is_a_real_mismatch():
    """Nothing overrides it: the copy would scan with rules the base did not."""
    report = compare_config(
        config(**{SAST_PRESET_KEY: ""}),
        config(**{SAST_PRESET_KEY: "Checkmarx Default"}),
    )
    assert not report.reliable
    assert [f.key for f in report.mismatches] == [SAST_PRESET_KEY]


def test_an_unreadable_configuration_does_not_certify_a_match():
    """Two empty documents are not evidence that two projects agree...

    ...but they are also not evidence that they disagree. What matters is that
    the missing `findingsAnalysis` difference is noticed: the run cannot have
    proven anything if the flag does not read as enabled on the candidate.
    """
    report = compare_config([], [])
    assert report.reliable                       # nothing contradicts anything
    assert field(report, FINDINGS_ANALYSIS_KEY).matches
    assert "expected to be enabled" in field(report, FINDINGS_ANALYSIS_KEY).note


def test_the_report_serialises_flat_for_the_template():
    from analysis.parity import report_to_json

    payload = report_to_json(compare_config(config(), config(**{FAST: "true"})))
    assert payload["reliable"] is False
    assert payload["total"] == 7
    assert len(payload["fields"]) == 7
    # Values are already display-ready: the template does no substitution.
    assert all(isinstance(f["base"], str) for f in payload["fields"])


# --- Phase 3.1: reading the flag off a project's own configuration ------------

from analysis.parity import findings_analysis_enabled  # noqa: E402


def param(key, value):
    return {"key": key, "value": value}


FA = "scan.config.sast.findingsAnalysis"


def test_the_flag_is_read_when_the_project_pins_it_on():
    assert findings_analysis_enabled([param(FA, "true")]) is True


def test_casing_from_the_api_does_not_change_the_answer():
    assert findings_analysis_enabled([param(FA, "True")]) is True
    assert findings_analysis_enabled([param(FA, " TRUE ")]) is True


def test_an_empty_value_means_inherit_not_enabled():
    """The tenant returns "" for a project that never touched the setting.

    Reading that as enabled would hide every untouched project - which is every
    candidate the tool exists to find.
    """
    assert findings_analysis_enabled([param(FA, "")]) is False


def test_an_explicit_false_is_not_enabled():
    assert findings_analysis_enabled([param(FA, "false")]) is False


def test_an_absent_key_is_not_enabled():
    assert findings_analysis_enabled([param("scan.config.sast.incremental", "true")]) is False
    assert findings_analysis_enabled([]) is False
    assert findings_analysis_enabled(None) is False
