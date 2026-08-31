"""Does the _FA copy actually scan the same way the base project does?

The whole tool rests on one claim: the difference between the two scans is
Findings Analysis. That claim only holds if nothing *else* differs. A different
preset runs a different rule set; a different exclusion filter scans different
files; fast scan mode skips queries entirely. Any of those moves the finding
count on its own, and the headline percentage would report it as Findings
Analysis having done the work.

So this module reads both projects' SAST configuration and diffs it field by
field. It never blocks a run - it labels the result, because a mismatch does not
make the numbers wrong, it makes them *unattributable*, and the person reading
them is the one who can judge that.

Pure functions over the plain dicts `get_project_config` returns, so the
comparison is testable without a tenant.
"""

from __future__ import annotations

from dataclasses import dataclass

from config import FINDINGS_ANALYSIS_KEY, SAST_PARITY_FIELDS, SAST_PRESET_KEY

#: Rendered in place of a value that is absent or empty. Both mean the same
#: thing to the platform - inherit from the tenant - so they must render the same
#: way too, or the table would show a difference the platform does not see.
UNSET_LABEL = "not set"


@dataclass(frozen=True)
class ParityField:
    """One SAST setting, as it stands on each side."""

    key: str
    label: str
    base: str | None
    candidate: str | None
    matches: bool
    expected_to_differ: bool = False
    note: str = ""

    @property
    def base_display(self) -> str:
        return self.base if self.base else UNSET_LABEL

    @property
    def candidate_display(self) -> str:
        return self.candidate if self.candidate else UNSET_LABEL


@dataclass(frozen=True)
class ParityReport:
    fields: tuple[ParityField, ...]

    @property
    def total(self) -> int:
        return len(self.fields)

    @property
    def matched(self) -> int:
        """Fields holding literally the same value on both sides."""
        return sum(1 for field in self.fields if field.matches)

    @property
    def as_expected(self) -> int:
        """Fields in the state a correct run produces.

        Not the same as `matched`. `findingsAnalysis` is *supposed* to differ, so
        a flawless run matches on six of seven fields - and reporting "6 of 7"
        would read as a near miss. What the reader needs to know is whether
        anything is off, and on a clean run nothing is.
        """
        return sum(
            1 for field in self.fields if field.matches != field.expected_to_differ
        )

    @property
    def mismatches(self) -> tuple[ParityField, ...]:
        """Differences that are *not* the point of the experiment.

        `findingsAnalysis` differing is the experiment succeeding, so it is
        excluded here even though it is reported as a difference in the table.
        """
        return tuple(
            field
            for field in self.fields
            if not field.matches and not field.expected_to_differ
        )

    @property
    def reliable(self) -> bool:
        """Whether the before/after difference can be attributed to the feature."""
        return not self.mismatches

    @property
    def summary(self) -> str:
        return f"{self.as_expected} of {self.total} SAST parameters as expected"


def _index(params: list[dict] | None) -> dict[str, str]:
    """Config parameter list keyed by config key, values normalised to strings."""
    values: dict[str, str] = {}
    for param in params or []:
        key = param.get("key")
        if not key:
            continue
        values[key] = str(param.get("value") if param.get("value") is not None else "")
    return values


def _normalise(value: str | None) -> str:
    """The comparable form of a configuration value.

    An absent key and an empty string are the same instruction - inherit - so
    they normalise together. Booleans arrive as strings with inconsistent casing
    across the API and the UI, so casing is dropped too. Comparing raw would
    report `"True"` and `"true"` as a mismatch and send someone hunting a
    configuration drift that does not exist.
    """
    return (value or "").strip().lower()


def findings_analysis_enabled(params: list[dict] | None) -> bool:
    """Whether a project pins Findings Analysis on at project level.

    Lives here rather than beside the portfolio because reading a config value
    correctly is this module's job. The tenant returns `value: ""` for a project
    that has never touched the setting - not `"false"` - so anything looser than
    an equality test against `true` would read "inherit" as "already enabled" and
    hide a project that is a candidate.
    """
    return _normalise(_index(params).get(FINDINGS_ANALYSIS_KEY)) == "true"


def _preset_pinned_by_the_scan(base: str | None) -> bool:
    """Whether the run forces the base project's preset onto the _FA scan.

    `cx/flow.py` reads the base project's preset and, when there is one, passes
    it in the scan payload - which overrides whatever the _FA project stores at
    project level. So a project-level preset difference is not a confound as
    long as the base pins something: both scans ran the base's rule set.

    The reverse is a real mismatch and is left as one. If the base inherits from
    the tenant, the flow passes no preset, and a preset sitting on the _FA
    project would then genuinely change which rules ran.
    """
    return bool(_normalise(base))


def compare_config(
    base_params: list[dict] | None, candidate_params: list[dict] | None
) -> ParityReport:
    """Diff the SAST settings that decide whether a comparison is attributable."""
    base_values = _index(base_params)
    candidate_values = _index(candidate_params)

    fields: list[ParityField] = []
    for key, label, expected_to_differ in SAST_PARITY_FIELDS:
        base = base_values.get(key)
        candidate = candidate_values.get(key)
        matches = _normalise(base) == _normalise(candidate)
        note = ""

        if not matches and key == SAST_PRESET_KEY and _preset_pinned_by_the_scan(base):
            matches = True
            note = f"The scan pins '{base}' from the base project."
        elif matches and expected_to_differ:
            note = (
                "Both sides carry the same value. Findings Analysis was expected "
                "to be enabled on the candidate only."
            )
        elif not matches and expected_to_differ:
            note = "Expected: this difference is what the run is testing."

        fields.append(
            ParityField(
                key=key,
                label=label,
                base=base,
                candidate=candidate,
                matches=matches,
                expected_to_differ=expected_to_differ,
                note=note,
            )
        )
    return ParityReport(fields=tuple(fields))


def report_to_json(report: ParityReport) -> dict:
    """Snapshot for the run row. Stored flat so the template needs no logic."""
    return {
        "matched": report.matched,
        "as_expected": report.as_expected,
        "total": report.total,
        "reliable": report.reliable,
        "summary": report.summary,
        "fields": [
            {
                "key": field.key,
                "label": field.label,
                "base": field.base_display,
                "candidate": field.candidate_display,
                "matches": field.matches,
                "expected_to_differ": field.expected_to_differ,
                "note": field.note,
            }
            for field in report.fields
        ],
    }
