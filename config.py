"""Runtime configuration, loaded from environment / .env.

Nothing in here is ever logged or rendered. `Settings.describe()` exists so the
UI and logs can show *which* variables are set without exposing their values.

Variable names deliberately match the sibling cx-analytics-and-risk-orchestration
project so one .env can serve both against the same tenant.
"""

from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass

from dotenv import load_dotenv

ROOT = pathlib.Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

# --- Domain vocabulary -------------------------------------------------------

SEVERITY_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

#: The only severities Findings Analysis is allowed to touch. Critical results
#: are always returned untouched by the platform, which is why the comparison
#: view renders Critical as an explicitly ineligible row rather than as a
#: severity that happened not to move.
ELIGIBLE_SEVERITIES: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW", "INFO")

INELIGIBLE_SEVERITY = "CRITICAL"

#: The project-level configuration key that turns the capability on. Not present
#: in any published OpenAPI spec - config keys are dynamic - so `cx/flow.py`
#: reads it back after writing rather than trusting the 204.
FINDINGS_ANALYSIS_KEY = "scan.config.sast.findingsAnalysis"

#: The SAST rule set the project scans with. Read from the source project so the
#: _FA scan runs the same one; an empty value means "inherit from the tenant",
#: which is what most projects do. Never substitute a literal name here - the
#: before/after difference has to come from Findings Analysis, not a preset swap.
SAST_PRESET_KEY = "scan.config.sast.presetName"

#: The SAST settings that must match between a base project and the _FA copy for
#: a before/after comparison to mean anything. Every key here was read off a live
#: `GET /api/configuration/project` response, not inferred: a wrong key would
#: silently compare two absent values and report a match.
#:
#: `findingsAnalysis` is in the list and is *expected* to differ - base false,
#: candidate true. That difference is the experiment. Any other difference is a
#: confound: a preset swap or an exclusion change moves the finding count on its
#: own, and would be read as Findings Analysis having done it.
#:
#: (key, label, expected_to_differ)
SAST_PARITY_FIELDS: tuple[tuple[str, str, bool], ...] = (
    ("scan.config.sast.fastScanMode", "Fast scan mode", False),
    ("scan.config.sast.filter", "Folder/file filter", False),
    ("scan.config.sast.incremental", "Incremental", False),
    ("scan.config.sast.extendedAnalysis", "LLM-based scanning", False),
    (SAST_PRESET_KEY, "Preset", False),
    ("scan.config.sast.recommendedExclusions", "Recommended exclusions", False),
    (FINDINGS_ANALYSIS_KEY, "Findings Analysis", True),
)

#: Suffix and tag applied to every project this tool creates, so the POC
#: projects it leaves behind in a tenant are trivially findable and cleanable.
FA_PROJECT_SUFFIX = "_FA"

#: Appended to the base project's name when a re-onboarding hands its repository
#: over. The base keeps its id and its entire scan history - the suffix is how
#: someone looking at the tenant later can tell which project used to own the
#: repo and why it stopped.
FA_BACKUP_SUFFIX = "_FA_BACKUP"
FA_PROJECT_TAGS: dict[str, str] = {"purpose": "findings-analysis-poc"}

#: Branches tried, in order, when locating a project's baseline SAST scan.
PREFERRED_BRANCHES: tuple[str, ...] = ("main", "master")

#: Default assumption behind the "analyst hours saved" figure. Surfaced as an
#: editable input in the UI - a hidden constant here would be presented as
#: fact, and it is an assumption.
DEFAULT_MINUTES_PER_FINDING = 10

# --- Portfolio scoring -------------------------------------------------------
# Defaults only. Every value below is overridable by environment variable and
# editable in the UI, because all of them are judgement calls rather than facts
# about the platform - the same reason MINUTES_PER_FINDING is an input and not a
# constant.

#: Weights behind the opportunity score. CRITICAL is deliberately absent rather
#: than present with weight 0: Findings Analysis never evaluates Critical
#: results, so a zero would read as a tuning choice someone could raise, when in
#: fact the severity is not eligible at all.
#:
#: INFO is present for the mirror-image reason. The platform *does* evaluate Info
#: results, so an Info finding is removable noise sitting in the same queue as the
#: rest - a project whose backlog is mostly Info is a real candidate, and scoring
#: it as empty would hide that. Weight 1 matches Low as a conservative opening
#: position: it is a statement about eligibility, not a claim that an Info finding
#: costs an analyst as much as a Low one. Retune it in the UI if it should.
DEFAULT_OPPORTUNITY_WEIGHTS: dict[str, int] = {
    "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 1
}

#: Migration-risk cutoffs, fitted to the reference tenant's real distribution:
#: 23 of 46 projects have a single scan and 28 a single branch, while only 5
#: exceed 9 scans (max 58) and 4 exceed 3 branches (max 11). Low needs *both*
#: counts small; High needs *either* one large.
DEFAULT_RISK_LOW_MAX_SCANS = 2
DEFAULT_RISK_LOW_MAX_BRANCHES = 1
DEFAULT_RISK_HIGH_MIN_SCANS = 10
DEFAULT_RISK_HIGH_MIN_BRANCHES = 4

#: How many top-scoring projects get flagged as candidates in the list.
DEFAULT_OPPORTUNITY_FLAG_TOP_N = 5

#: How old a project's baseline scan may be before the portfolio recommends
#: re-basing it. GOAL_PHASE3 says "three months"; expressed in days because that
#: is the only unit a date subtraction produces without a calendar library.
#:
#: A stale baseline is not just old data. The comparison this tool builds is
#: anchored to it, so measuring against a baseline from before six months of
#: merges reports a difference that is partly Findings Analysis and partly half a
#: year of code.
DEFAULT_REBASE_STALE_DAYS = 90

#: A portfolio snapshot older than this is labelled stale in the UI. It is still
#: shown - refusing to render cached numbers helps nobody - but never presented
#: as current.
DEFAULT_SNAPSHOT_STALE_HOURS = 24


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    base_url: str = ""
    auth_url: str = ""
    tenant: str = ""
    client_id: str = "ast-app"
    api_key: str = ""
    use_fixtures: bool = False
    db_path: str = "data/findings_analysis.db"
    host: str = "127.0.0.1"
    port: int = 8060
    log_level: str = "INFO"
    poll_interval_seconds: int = 8
    minutes_per_finding: int = DEFAULT_MINUTES_PER_FINDING
    snapshot_stale_hours: int = DEFAULT_SNAPSHOT_STALE_HOURS
    #: Whether the re-onboarding flow is offered at all. Off unless explicitly
    #: turned on: it is the one flow that moves a live repository from one
    #: project to another, so an operator opts into it rather than out.
    reonboard_enabled: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        # CX_CLIENT_SECRET and CX_API_KEY are the same thing: a Checkmarx One
        # API key, which is an OAuth *refresh token*. Accept either name so an
        # .env written for either sibling project works here unchanged.
        api_key = os.environ.get("CX_CLIENT_SECRET") or os.environ.get("CX_API_KEY") or ""
        return cls(
            base_url=(os.environ.get("CX_BASE_URL") or "").rstrip("/"),
            auth_url=(os.environ.get("CX_AUTH_URL") or "").rstrip("/"),
            tenant=os.environ.get("CX_TENANT") or "",
            client_id=os.environ.get("CX_CLIENT_ID") or "ast-app",
            api_key=api_key,
            use_fixtures=_env_bool("USE_FIXTURES", False),
            db_path=os.environ.get("CX_DB_PATH") or "data/findings_analysis.db",
            host=os.environ.get("APP_HOST") or "127.0.0.1",
            port=_env_int("APP_PORT", 8060),
            log_level=os.environ.get("LOG_LEVEL") or "INFO",
            poll_interval_seconds=_env_int("POLL_INTERVAL_SECONDS", 8),
            minutes_per_finding=_env_int(
                "MINUTES_PER_FINDING", DEFAULT_MINUTES_PER_FINDING
            ),
            snapshot_stale_hours=_env_int(
                "SNAPSHOT_STALE_HOURS", DEFAULT_SNAPSHOT_STALE_HOURS
            ),
            # Both spellings, for the same reason CX_CLIENT_SECRET/CX_API_KEY
            # accepts two: the conventional upper-case name is what is
            # documented, and a lower-case one written by hand still works.
            # Upper case is checked first because a lower-case environment
            # variable is unreliable on Windows.
            reonboard_enabled=(
                _env_bool("REONBOARD", False) or _env_bool("reonboard", False)
            ),
        )

    def portfolio_defaults(self) -> dict[str, int]:
        """Scoring and risk settings from environment, before any UI override.

        Flat so it round-trips through a form and a JSON column unchanged.
        """
        return {
            "weight_high": _env_int(
                "OPPORTUNITY_WEIGHT_HIGH", DEFAULT_OPPORTUNITY_WEIGHTS["HIGH"]
            ),
            "weight_medium": _env_int(
                "OPPORTUNITY_WEIGHT_MEDIUM", DEFAULT_OPPORTUNITY_WEIGHTS["MEDIUM"]
            ),
            "weight_low": _env_int(
                "OPPORTUNITY_WEIGHT_LOW", DEFAULT_OPPORTUNITY_WEIGHTS["LOW"]
            ),
            "weight_info": _env_int(
                "OPPORTUNITY_WEIGHT_INFO", DEFAULT_OPPORTUNITY_WEIGHTS["INFO"]
            ),
            "risk_low_max_scans": _env_int(
                "RISK_LOW_MAX_SCANS", DEFAULT_RISK_LOW_MAX_SCANS
            ),
            "risk_low_max_branches": _env_int(
                "RISK_LOW_MAX_BRANCHES", DEFAULT_RISK_LOW_MAX_BRANCHES
            ),
            "risk_high_min_scans": _env_int(
                "RISK_HIGH_MIN_SCANS", DEFAULT_RISK_HIGH_MIN_SCANS
            ),
            "risk_high_min_branches": _env_int(
                "RISK_HIGH_MIN_BRANCHES", DEFAULT_RISK_HIGH_MIN_BRANCHES
            ),
            "flag_top_n": _env_int(
                "OPPORTUNITY_FLAG_TOP_N", DEFAULT_OPPORTUNITY_FLAG_TOP_N
            ),
            "rebase_stale_days": _env_int(
                "REBASE_STALE_DAYS", DEFAULT_REBASE_STALE_DAYS
            ),
        }

    @property
    def db_file(self) -> pathlib.Path:
        path = pathlib.Path(self.db_path)
        if not path.is_absolute():
            path = ROOT / path
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def fixtures_dir(self) -> pathlib.Path:
        return ROOT / "fixtures"

    def missing_credentials(self) -> list[str]:
        """Names of required credential variables that are absent.

        Empty when fixtures are in use - demo mode is fully functional with no
        tenant access at all, which is the point of it.
        """
        if self.use_fixtures:
            return []
        required = {
            "CX_BASE_URL": self.base_url,
            "CX_AUTH_URL": self.auth_url,
            "CX_TENANT": self.tenant,
            "CX_CLIENT_SECRET": self.api_key,
        }
        return [name for name, value in required.items() if not value]

    def describe(self) -> dict[str, str]:
        """Non-sensitive summary for logs and the UI diagnostics panel."""
        return {
            "base_url": self.base_url or "<unset>",
            "auth_url": self.auth_url or "<unset>",
            "tenant": self.tenant or "<unset>",
            "client_id": self.client_id,
            "api_key": "<set>" if self.api_key else "<unset>",
            "use_fixtures": str(self.use_fixtures),
            "db_path": self.db_path,
        }


settings = Settings.from_env()
