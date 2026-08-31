"""Planning a re-onboarding, as pure functions over tenant facts.

Re-onboarding swaps which Checkmarx project owns a repository: the base project
is disconnected from its SCM (becoming a manual project, keeping every scan it
ever ran) and the `_FA` copy is connected in its place, so the project that
carries Findings Analysis is the one the repo pushes to from then on.

Two API calls do it, and both are irreversible from here:

* `POST /api/repos-manager/projects/{id}/disconnect`
* `POST /api/repos-manager/project-conversion`

Everything in this module runs *before* either of them. It turns what the tenant
already reports into an explicit plan, so the operator confirms a payload they
have actually read rather than a button that says "convert". Nothing here calls
the API and nothing here writes: given the same facts it produces the same plan,
which is what makes the preview trustworthy and the whole thing testable without
a tenant.

The base project is never deleted. There is no code path in this project that
deletes a project, and this module deliberately produces no plan that could.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from urllib.parse import urlparse

from config import FA_BACKUP_SUFFIX, FA_PROJECT_SUFFIX

#: The only scanners `project-conversion` accepts. A scan's `engines` list is
#: wider than this - real responses include `containers`, `aisc` and
#: `microengines` - and sending one of those is a 400 on the whole conversion.
CONVERTIBLE_ENGINES: tuple[str, ...] = ("sast", "sca", "kics", "apisec")

#: `scmType` vocabulary, from `GET /v2/scms`. `githubApp` is a distinct type: it
#: authenticates through an installed GitHub App rather than a token.
SCM_TYPES: tuple[str, ...] = ("github", "gitlab", "azure", "bitbucket", "githubApp")

#: Lower-cased `SCM_TYPES`, for matching a scan's `sourceType`. An uploaded
#: archive reports `zip`; a rescan reports `rescan`; a cloned scan reports one
#: of these.
SCM_TYPE_SET = frozenset(scm.lower() for scm in SCM_TYPES)

#: `origin` values the platform writes on a project it holds a repository record
#: for. Display names, not the API's `scmType` vocabulary - on the reference
#: tenant every connected project reads one of these and no unconnected one does.
SCM_ORIGINS: tuple[str, ...] = (
    "github", "github app", "gitlab", "bitbucket", "azure", "azure devops",
)

#: Host fragment → scmType, for the cloud SCMs. Only consulted when the tenant's
#: own integration list cannot settle it.
_HOST_HINTS: tuple[tuple[str, str], ...] = (
    ("github.", "github"),
    ("gitlab.", "gitlab"),
    ("dev.azure.com", "azure"),
    ("visualstudio.com", "azure"),
    ("bitbucket.", "bitbucket"),
)


@dataclass(frozen=True)
class Blocker:
    """A reason this re-onboarding must not proceed."""

    code: str
    message: str


@dataclass(frozen=True)
class ReonboardPlan:
    """Exactly what would happen, in the order it would happen."""

    base_project_id: str
    base_project_name: str
    candidate_project_id: str
    candidate_project_name: str
    repo_url: str
    scm_type: str
    scm_id: str | None
    org_identity: str
    protected_branches: tuple[str, ...]
    engines: tuple[str, ...]
    webhook_enabled: bool
    auto_scan: bool
    connected_project_count: int
    base_backup_name: str = ""
    candidate_final_name: str = ""
    #: Scanners the tenant is entitled to, read from the bearer token. Shown in
    #: the preview so the follow-up steps are disclosed, and deliberately kept
    #: out of `digest()` - see the note there.
    licensed_scanners: tuple[str, ...] = ()
    #: The project has no repository at all, so it is re-onboarded by renaming
    #: alone. See `is_manual_project` for what earns this.
    manual: bool = False
    #: Both renames have already landed - a resumed run that has nothing left to
    #: do. Only ever set on a manual plan.
    already_applied: bool = False
    blockers: tuple[Blocker, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def executable(self) -> bool:
        return not self.blockers

    def conversion_payload(self) -> dict:
        """The exact body of `POST /project-conversion`.

        Empty for a manual project: there is no conversion, and a payload of
        empty strings would render in the preview as a request about to be sent.

        No `token` key at all. This flow never accepts a credential, and relies
        on the documented behaviour that a token is unnecessary when another
        project in the same organisation is already connected - which is why
        `connected_project_count` is checked before the plan is executable.
        """
        if self.manual:
            return {}
        return {
            "scmType": self.scm_type,
            "orgIdentity": self.org_identity,
            "types": list(self.engines),
            "webhookEnabled": self.webhook_enabled,
            "autoScanCxProjectAfterConversion": self.auto_scan,
            "projects": [
                {
                    "cxProjectId": self.candidate_project_id,
                    "scmRepositoryUrl": self.repo_url,
                    "protectedBranches": list(self.protected_branches),
                    "types": list(self.engines),
                    "webhookEnabled": self.webhook_enabled,
                }
            ],
        }

    def manual_steps(self) -> list[dict]:
        """The reduced path: two renames and a rescan, plus what is skipped.

        The skipped calls are listed rather than omitted. Someone reading this
        page against an SCM re-onboarding has to be able to see that the
        disconnect and the conversion did not merely fail quietly - they were
        never applicable, and the reason is stated on each row.
        """
        return [
            {
                "order": 1,
                "method": "PATCH",
                "path": f"/api/projects/{self.base_project_id}",
                "target": f"{self.base_project_name} ({self.base_project_id})",
                "effect": (
                    f"Renamed to '{self.base_backup_name}', freeing its old name. "
                    "Only the name changes - same project, same id, same history."
                ),
            },
            {
                "order": 2,
                "method": "PATCH",
                "path": f"/api/projects/{self.candidate_project_id}",
                "target": (
                    f"{self.candidate_project_name} ({self.candidate_project_id})"
                ),
                "effect": (
                    f"Renamed to '{self.candidate_final_name}', taking over the "
                    "name the base project just released. Verified by reading "
                    "the name back before anything else runs."
                ),
            },
            {
                "order": 3,
                "method": "POST",
                "path": "/api/scans/rescan",
                "effect": (
                    "Re-runs the copy's existing source under its new name. No "
                    "archive is downloaded or uploaded, and the scanners stay as "
                    "the comparison run configured them. Best effort."
                ),
                "target": (
                    f"{self.candidate_final_name} ({self.candidate_project_id})"
                ),
            },
            {
                "order": "—",
                "method": "skipped",
                "path": f"/api/repos-manager/projects/{self.base_project_id}/disconnect",
                "target": self.base_project_name,
                "effect": (
                    "Manual project: it is connected to no repository, so there "
                    "is no webhook or connection to remove."
                ),
            },
            {
                "order": "—",
                "method": "skipped",
                "path": "/api/repos-manager/project-conversion",
                "target": self.candidate_final_name,
                "effect": (
                    "Manual project: there is no repository to connect the copy "
                    "to, and no organisation to scope a conversion to."
                ),
            },
            {
                "order": "—",
                "method": "skipped",
                "path": "/api/repos-manager/repo/{repoId}",
                "target": self.candidate_final_name,
                "effect": (
                    "Manual project: it has no repoId, so there are no repository "
                    "scanner settings to change. The rescan runs with whatever "
                    "the Findings Analysis comparison was configured with."
                ),
            },
        ]

    def steps(self) -> list[dict]:
        """The four calls, in the order they fire.

        The two renames sit between the disconnect and the conversion because
        the order is forced: the base has to give up its name before the copy
        can take it, and it only gives it up once it no longer owns the repo.
        """
        if self.manual:
            return self.manual_steps()
        return [
            {
                "order": 1,
                "method": "POST",
                "path": f"/api/repos-manager/projects/{self.base_project_id}/disconnect",
                "target": f"{self.base_project_name} ({self.base_project_id})",
                "effect": (
                    "Becomes a manual project. Scan history is preserved and its "
                    "webhook is removed. It is not deleted."
                ),
            },
            {
                "order": 2,
                "method": "PATCH",
                "path": f"/api/projects/{self.base_project_id}",
                "target": f"{self.base_project_name} ({self.base_project_id})",
                "effect": (
                    f"Renamed to '{self.base_backup_name}', freeing its old name. "
                    "Only the name changes - same project, same id, same history."
                ),
            },
            {
                "order": 3,
                "method": "PATCH",
                "path": f"/api/projects/{self.candidate_project_id}",
                "target": (
                    f"{self.candidate_project_name} ({self.candidate_project_id})"
                ),
                "effect": (
                    f"Renamed to '{self.candidate_final_name}', taking over the "
                    "name the base project just released."
                ),
            },
            {
                "order": 4,
                "method": "POST",
                "path": "/api/repos-manager/project-conversion",
                "target": (
                    f"{self.candidate_final_name} ({self.candidate_project_id})"
                ),
                "effect": (
                    f"Connects to {self.repo_url} in {self.org_identity}, "
                    f"protecting {', '.join(self.protected_branches)}."
                ),
            },
            # Steps 5 and 6 are the post-conversion follow-up. They are listed
            # because nothing in this flow may fire undisclosed, but they are
            # best-effort: neither can leave a repository half-owned, and a
            # failure in either is a warning against a re-onboarding that has
            # already succeeded.
            {
                "order": 5,
                "method": "PATCH",
                "path": "/api/repos-manager/repo/{repoId}",
                "target": (
                    f"{self.candidate_final_name} - repoId resolved after "
                    "conversion"
                ),
                "effect": (
                    "Enables every licensed scanner the repository accepts"
                    + (
                        f" ({', '.join(self.licensed_scanners)})"
                        if self.licensed_scanners
                        else ""
                    )
                    + ", and turns Incremental Scan and SCA auto pull requests "
                    "off. Best effort."
                ),
            },
            {
                "order": 6,
                "method": "POST",
                "path": "/api/scans/rescan",
                "target": (
                    f"{self.candidate_final_name} ({self.candidate_project_id})"
                ),
                "effect": (
                    "Queues one fresh full scan across the scanners just "
                    "enabled. Not waited on. Best effort."
                ),
            },
        ]

    def digest(self) -> str:
        """Fingerprint of the plan the operator was shown.

        The confirm form posts this back. If the tenant moved between preview
        and confirmation - a branch added, the repo reconnected elsewhere - the
        recomputed plan no longer matches and the run is refused rather than
        executing something nobody read.

        Covers steps 1-4 only: the calls that move a repository from one project
        to another, which is the decision being approved. Steps 5 and 6 are
        deliberately excluded. A scanner flag or a licence entry changing
        between preview and confirmation would otherwise refuse a re-onboarding
        that is in every meaningful respect the one that was reviewed, and the
        two follow-up calls cannot leave the tenant in a state that needs a
        human either way.

        Needs no special case for a manual plan, and that is load-bearing. The
        material is the conversion payload (empty there), the base project's id
        and the two *target* names - none of which move when the base has
        already been renamed by a run that failed half-way. So a resumed manual
        re-onboarding still matches the digest the operator originally approved,
        which is exactly what makes it resumable rather than a fresh decision.
        """
        material = json.dumps(
            {
                "payload": self.conversion_payload(),
                "base": self.base_project_id,
                "base_backup_name": self.base_backup_name,
                "candidate_final_name": self.candidate_final_name,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode()).hexdigest()[:16]


def backup_name_for(base_name: str, suffix: str) -> str:
    """What the base project is renamed to once it hands over its repository.

    Idempotent: a name that already carries the suffix is left alone, so a
    retry cannot produce `x_FA_BACKUP_FA_BACKUP`.
    """
    name = (base_name or "").strip()
    return name if name.endswith(suffix) else f"{name}{suffix}"


def promoted_name_for(candidate_name: str, fa_suffix: str) -> str:
    """The name the copy takes once the base has vacated it.

    Only a trailing `_FA` is removed - the suffix this tool appended when it
    created the copy. Stripping the substring wherever it appeared would mangle
    a project legitimately named `FOO_FACTORY`.
    """
    name = (candidate_name or "").strip()
    if name.endswith(fa_suffix):
        return name[: -len(fa_suffix)]
    return name


def normalise_repo_url(repo_url: str | None) -> str:
    """The repo URL in the form `project-conversion` expects.

    The `.git` suffix must go: the API documents the URL without it, and real
    tenant projects carry it either way (`.../juice-shop.git` sits alongside
    `.../Scheduler`). Case is left exactly as found - the field is documented
    case sensitive, so "tidying" it would break the match.
    """
    url = (repo_url or "").strip().rstrip("/")
    if url.endswith(".git"):
        url = url[: -len(".git")]
    return url


#: `repoBaseUrl` for Bitbucket Cloud is the *API* host. The URL a conversion
#: needs is the browse host, and they are not the same string.
_BROWSE_HOST_FIXUPS: tuple[tuple[str, str], ...] = (
    ("https://api.bitbucket.org", "https://bitbucket.org"),
)

#: A Checkmarx-proxied integration registers its `repoBaseUrl` as a link address
#: on Checkmarx's own domain (`https://<region>.ast.checkmarx.net/link/<uuid>`)
#: rather than the customer's SCM hostname. It is still the address Checkmarx
#: clones through - scan metadata shows exactly this URL in the git handler - so
#: it is usable. It is flagged in the preview because an operator reading the
#: plan should see that the URL is a Checkmarx address and not their own host.
_PROXY_URL_MARKER = "/link/"


def is_proxy_base(integration: dict | None) -> bool:
    return _PROXY_URL_MARKER in ((integration or {}).get("repoBaseUrl") or "")


def browse_base_url(integration: dict | None) -> str:
    """The base URL repositories under an integration are addressed at.

    Only the Bitbucket Cloud fixup is applied: its `repoBaseUrl` is the API
    host, and a conversion needs the browse host. Everything else is returned as
    the tenant reported it, including Checkmarx link addresses - those identify
    a real integration and are what the platform itself clones through.
    """
    base = ((integration or {}).get("repoBaseUrl") or "").strip().rstrip("/")
    if not base:
        return ""
    for api_host, browse_host in _BROWSE_HOST_FIXUPS:
        if base.lower() == api_host:
            return browse_host
    return base


def repo_path(project: dict) -> str:
    """The `org/repo` path a Checkmarx project stands for.

    Taken from the project **name**, because that is the string
    `scms/{id}/projects` matches on - so the project whose membership identified
    the integration is the same one naming the repository. `imported_proj_name`
    is the fallback for a project whose display name has been changed.
    """
    for candidate in (project.get("name"), project.get("imported_proj_name")):
        path = str(candidate or "").strip().strip("/")
        if "/" in path:
            return path
    return ""


def resolve_repo_url(
    project: dict, integration: dict | None, handler_repo_url: str | None = None
) -> str:
    """The repository a project scans.

    Two shapes exist in one tenant and they do not overlap:

    * A project connected through a Code Repository Integration reports an
      **empty** `repoUrl` - verified against a live tenant, where every connected
      project did. That is how the integration flow stores things, not evidence
      the project is unconnected. Its address is the integration's base URL plus
      its `org/repo` path.
    * A legacy manual project carries `repoUrl` directly.

    `handler_repo_url` outranks both. It is the URL recorded in the scan's own
    git handler - literally the address Checkmarx cloned from - so it is a fact
    rather than a reconstruction, and it is right even when the integration
    listing is wrong. On a live tenant it was the only source that produced
    `https://gitlab.com/rmarquez/WebGoat8` for a project whose `repoUrl` was
    empty and which no integration listing claimed.
    """
    from_handler = normalise_repo_url(handler_repo_url)
    if from_handler:
        return from_handler

    base = browse_base_url(integration)
    path = repo_path(project)
    if base and path:
        return normalise_repo_url(f"{base}/{path}")
    return normalise_repo_url(project.get("repoUrl"))


def org_identity(repo_url: str | None) -> str:
    """The SCM organisation a repo URL belongs to.

    The first path segment, which is the organisation for GitHub, the top-level
    group for GitLab, the workspace for Bitbucket cloud and the organisation for
    Azure DevOps. Nested GitLab groups and Bitbucket Server project keys do not
    follow this rule, which is why the value is shown in the preview for the
    operator to check rather than used silently.
    """
    path = urlparse(normalise_repo_url(repo_url)).path.strip("/")
    return path.split("/")[0] if path else ""


def scm_type_for(
    repo_url: str | None,
    source_type: str | None,
    scms: list[dict] | None = None,
    integration: dict | None = None,
    origin: str | None = None,
) -> str:
    """Which SCM this repository lives on, best evidence first.

    The integration the project is actually connected through is authoritative -
    it is the thing the conversion will talk to. A scan's `sourceType` comes
    next, then the project's `origin` ("GitLab"), then a `repoBaseUrl` prefix
    match, then the hostname. The later rules exist for manual projects, which
    belong to no integration yet.
    """
    from_integration = ((integration or {}).get("type") or "").strip()
    if from_integration in SCM_TYPES:
        return from_integration

    declared = (source_type or "").strip()
    if declared in SCM_TYPES:
        return declared

    # `origin` is a display name - "GitLab", "GitHub" - not the API vocabulary.
    lowered = (origin or "").strip().lower()
    for scm_type in SCM_TYPES:
        if lowered and lowered == scm_type.lower():
            return scm_type

    url = normalise_repo_url(repo_url)
    for scm in scms or []:
        base = (scm.get("repoBaseUrl") or "").strip().rstrip("/")
        if base and _PROXY_URL_MARKER not in base and url.lower().startswith(
            base.lower()
        ):
            candidate = (scm.get("type") or "").strip()
            if candidate in SCM_TYPES:
                return candidate

    host = (urlparse(url).hostname or "").lower()
    for fragment, scm_type in _HOST_HINTS:
        if fragment in host:
            return scm_type
    return ""


def any_scan_was_cloned(scans: list[dict] | None) -> bool:
    """Whether any of these scans pulled its source from a repository.

    Reads `sourceType` off the scan list rows, which already carry it - no
    per-scan fetch. An uploaded archive reports `zip` or `upload` and a rescan
    reports `rescan`; anything naming an SCM means Checkmarx cloned the code,
    which means something out there addresses this project by name.
    """
    return any(
        _normalise_name(scan.get("sourceType")) in SCM_TYPE_SET for scan in scans or []
    )


def is_manual_project(
    project: dict,
    *,
    integration: dict | None,
    handler_repo_url: str | None,
    recent_scans: list[dict] | None = None,
) -> bool:
    """Whether a project has no tie to source control of any kind.

    A manual project cannot be re-onboarded the normal way - there is no
    repository to disconnect and none to convert to - but it can be re-onboarded
    by renaming, and that is a very different thing from a project this beta
    merely failed to *resolve*. Renaming a project that is still connected would
    leave its pushes landing on the `_FA_BACKUP` copy, so every one of the four
    conditions below has to hold.

    `repoId`/`scmRepoId` is the positive signal: it is the repos-manager record
    itself. On the reference tenant all 31 connected projects carry both and all
    16 unconnected ones carry neither.

    `repoUrl` is deliberately **not** consulted, because it settles nothing in
    either direction. `rudy-marquez/juice-shop` is connected (`repoId 57514`)
    with an empty `repoUrl`, and `VulnPascal` is manual while still carrying
    `https://github.com/syhunt/vulnpascal.git` from however it was created.

    The last three conditions catch what the project fields alone miss: a
    project can have no repos-manager record and still be driven by source
    control. `scheduler` has no `repoId` yet its scans arrive from a GitHub PR
    webhook, with the repository URL and credentials in the scan's own git
    handler.

    `recent_scans` is checked as well as the baseline's handler because the
    baseline alone is not enough, and the tenant proves it: `delphilint`,
    `VulnPascal`, `kubernetes-goat` and four others have an uploaded or rescanned
    baseline sitting on top of a history of cloned scans. Judging them on the
    baseline would have called every one of them manual and renamed a project
    something out there still addresses by name.
    """
    if project.get("repoId") or project.get("scmRepoId"):
        return False
    if _normalise_name(project.get("origin")) in SCM_ORIGINS:
        return False
    if integration is not None:
        return False
    if any_scan_was_cloned(recent_scans):
        return False
    return not normalise_repo_url(handler_repo_url)


def _normalise_name(value: object) -> str:
    return str(value or "").strip().lower()


def convertible_engines(engines: list[str] | None) -> tuple[str, ...]:
    """A scan's engines, reduced to the ones a conversion may request.

    Order follows `CONVERTIBLE_ENGINES` so the same set always serialises the
    same way and the plan digest is stable. Falls back to SAST: a conversion
    needs at least one scanner, and SAST is the one this tool measures.
    """
    present = {str(engine).strip().lower() for engine in engines or []}
    kept = tuple(engine for engine in CONVERTIBLE_ENGINES if engine in present)
    return kept or ("sast",)


def protected_branch_patterns(
    branches: list[dict] | None, fallback_branch: str | None
) -> tuple[str, ...]:
    """Branch patterns to carry across, or the baseline branch if none are set.

    `protectedBranches` is required and a conversion with an empty list fails,
    so an unprotected base project falls back to the branch its baseline scan
    actually ran on - the one branch known to exist.
    """
    patterns = []
    for branch in branches or []:
        pattern = str(branch.get("pattern") or "").strip()
        if pattern and pattern not in patterns:
            patterns.append(pattern)
    if patterns:
        return tuple(patterns)
    fallback = (fallback_branch or "").strip()
    return (fallback,) if fallback else ()


def build_plan(
    *,
    base_project: dict,
    candidate_project_id: str,
    candidate_project_name: str,
    baseline_scan: dict | None,
    baseline_branch: str | None,
    protected_branches: list[dict] | None,
    scms: list[dict] | None,
    connected_project_names: list[str] | None,
    integration: dict | None = None,
    handler_repo_url: str | None = None,
    existing_project_names: list[str] | None = None,
    backup_suffix: str = FA_BACKUP_SUFFIX,
    fa_suffix: str = FA_PROJECT_SUFFIX,
    webhook_enabled: bool = True,
    auto_scan: bool = False,
    licensed_scanners: tuple[str, ...] | list[str] | None = None,
    manual: bool = False,
) -> ReonboardPlan:
    """Assemble the plan and decide whether it may run at all.

    Blockers are returned rather than raised. The preview has to be able to show
    an operator *why* a re-onboarding is refused, and a refusal with no plan
    attached explains nothing.

    `manual` waives the five preconditions that exist only because
    `project-conversion` demands them. It is passed in rather than inferred
    here: deciding a project is manual takes tenant facts this function is not
    given, and inferring it from these checks failing is precisely the mistake
    the goal warns against - an unsupported provider fails them too.
    """
    base_id = base_project.get("id") or ""
    base_name = base_project.get("name") or base_id
    repo_url = resolve_repo_url(base_project, integration, handler_repo_url)
    scan = baseline_scan or {}
    scm_type = scm_type_for(
        repo_url,
        scan.get("sourceType"),
        scms,
        integration=integration,
        origin=base_project.get("origin"),
    )
    # The `org/repo` path states the organisation directly; parsing it back out
    # of the assembled URL would only re-derive what we already had.
    # When the handler supplied the URL, its own path is the organisation; the
    # project name is only a stand-in for when it did not.
    org = org_identity(repo_url) if handler_repo_url else ""
    if not org:
        path = repo_path(base_project)
        org = path.split("/")[0] if "/" in path else org_identity(repo_url)
    engines = convertible_engines(scan.get("engines"))
    # Nothing to protect on a project with no repository, and recording the
    # baseline branch as a "protected branch" would put a claim in the stored
    # plan that the tenant does not make.
    patterns = (
        () if manual else protected_branch_patterns(protected_branches, baseline_branch)
    )

    connected = list(connected_project_names or [])
    connected_count = len(connected)

    backup_name = backup_name_for(base_name, backup_suffix)
    final_name = promoted_name_for(candidate_project_name, fa_suffix)
    taken = {
        name for name in (existing_project_names or [])
        if name not in {base_name, candidate_project_name}
    }

    blockers: list[Blocker] = []
    warnings: list[str] = []

    # Both renames have already landed: the base gave up its name and the copy
    # took it. A resumed run that has nothing left to do, not a failure.
    released_name = (
        base_name[: -len(backup_suffix)] if base_name.endswith(backup_suffix) else ""
    )
    already_applied = bool(
        manual and released_name and candidate_project_name == released_name
    )

    # Every check in this block is a `project-conversion` precondition. A manual
    # project is never converted, so requiring them would refuse the one path
    # that can actually re-onboard it.
    if not manual:
        if not repo_url:
            # Reached only when no integration lists the project *and* it carries
            # no repoUrl of its own. An empty `repoUrl` alone is not a failure -
            # it is simply how the Code Repository integration stores a connected
            # project.
            blockers.append(Blocker(
                "no-repo-url",
                f"No integration lists '{base_name}', and it reports no repository "
                "URL of its own, so there is no repository address to convert to. "
                "The project is either manual or connected in a way this beta does "
                "not yet support.",
            ))
        if not scm_type:
            blockers.append(Blocker(
                "unknown-scm",
                f"Could not determine which SCM {repo_url or 'this project'} belongs "
                "to. The conversion API needs an explicit scmType and guessing it "
                "would connect the copy to the wrong integration.",
            ))
        if not org:
            blockers.append(Blocker(
                "no-org",
                f"Could not read an SCM organisation from {repo_url}. A conversion "
                "is scoped to one organisation and cannot be submitted without it.",
            ))
        if not patterns:
            blockers.append(Blocker(
                "no-branches",
                "No protected branches are configured on the base project and its "
                "baseline scan records no branch, so there is nothing to protect on "
                "the converted project. The conversion API rejects an empty list.",
            ))
        if not repo_url:
            pass  # already reported above; do not pile a second blocker on it
        elif connected_count <= 1:
            # The hazard that makes ordering dangerous. Disconnect runs first,
            # and the conversion that follows carries no token - it borrows the
            # credential from another connected project in the organisation. If
            # this is the last one, that credential disappears at exactly the
            # wrong moment and the base is left disconnected with nothing to
            # convert into.
            blockers.append(Blocker(
                "last-connected-project",
                f"'{base_name}' appears to be the only project connected through "
                "this integration. Disconnecting it would remove the credential the "
                "conversion needs, and this flow never accepts a token - the base "
                "would be left disconnected with the conversion unable to proceed. "
                "Connect another project in this organisation first, or perform the "
                "conversion in the Checkmarx One UI.",
            ))

    if repo_url and is_proxy_base(integration):
        # Not a defect, and not a reason to refuse: this is the address
        # Checkmarx itself clones through, and the scan's git handler records
        # exactly this URL. Shown because an operator confirming the plan should
        # notice that the repository address is a Checkmarx one.
        warnings.append(
            f"This integration is registered with a Checkmarx link address, so "
            f"the repository is addressed as {repo_url} rather than by your "
            "own SCM hostname. That is the address Checkmarx scans it through."
        )
    if backup_name in taken:
        # A leftover from an earlier attempt. Renaming onto it would either be
        # rejected or leave two projects a person cannot tell apart.
        blockers.append(Blocker(
            "backup-name-taken",
            f"A different project is already called '{backup_name}', so the base "
            "project cannot be renamed out of the way. Rename or remove that "
            "project first - most likely it is left over from an earlier "
            "re-onboarding of this same project.",
        ))
    if final_name in taken:
        blockers.append(Blocker(
            "final-name-taken",
            f"A different project is already called '{final_name}', so the "
            "Findings Analysis copy cannot take that name. Resolve the "
            "collision in Checkmarx One first.",
        ))
    if final_name == candidate_project_name and not already_applied:
        # Suppressed when both renames have already landed: the copy has no
        # suffix left precisely *because* it has taken the base's name, and
        # saying it cannot take a name it already holds explains nothing.
        blockers.append(Blocker(
            "candidate-not-suffixed",
            f"'{candidate_project_name}' does not end in '{fa_suffix}', so there "
            "is no suffix to remove and the copy cannot take over the base "
            "project's name. This flow only handles copies this tool created.",
        ))

    if already_applied:
        warnings.append(
            f"Both renames have already been applied - '{final_name}' holds the "
            f"live name and '{base_name}' is the backup. Confirming will only "
            "retry the rescan."
        )

    # All three describe the conversion. On a manual plan there is none, and a
    # warning about protected branches or the conversion's engine list would be
    # commentary on a call that is not going to be made.
    if not manual:
        if scm_type == "githubApp":
            warnings.append(
                "This organisation is integrated through a GitHub App. Conversion "
                "relies on that installation already covering the repository."
            )
        if len(patterns) == 1 and not (protected_branches or []):
            warnings.append(
                f"The base project has no protected branches configured, so "
                f"'{patterns[0]}' - the branch its baseline scan ran on - is being "
                "carried across as the only protected branch."
            )
        if "sast" not in engines:
            warnings.append(
                "The base project's baseline scan did not report SAST among its "
                "engines, which is unusual for a project measured by this tool."
            )

    return ReonboardPlan(
        base_project_id=base_id,
        base_project_name=base_name,
        candidate_project_id=candidate_project_id,
        candidate_project_name=candidate_project_name,
        repo_url=repo_url,
        scm_type=scm_type,
        scm_id=(
            str(integration.get("id"))
            if integration is not None and integration.get("id") is not None
            else None
        ),
        org_identity=org,
        protected_branches=patterns,
        engines=engines,
        webhook_enabled=webhook_enabled,
        auto_scan=auto_scan,
        connected_project_count=connected_count,
        base_backup_name=backup_name,
        candidate_final_name=final_name,
        licensed_scanners=tuple(licensed_scanners or ()),
        manual=manual,
        already_applied=already_applied,
        blockers=tuple(blockers),
        warnings=tuple(warnings),
    )


def plan_to_json(plan: ReonboardPlan) -> dict:
    """Stored on the run, and rendered by the template without further logic."""
    return {
        "base_project_id": plan.base_project_id,
        "base_project_name": plan.base_project_name,
        "candidate_project_id": plan.candidate_project_id,
        "candidate_project_name": plan.candidate_project_name,
        "repo_url": plan.repo_url,
        "scm_type": plan.scm_type,
        "scm_id": plan.scm_id,
        "org_identity": plan.org_identity,
        "protected_branches": list(plan.protected_branches),
        "engines": list(plan.engines),
        "webhook_enabled": plan.webhook_enabled,
        "auto_scan": plan.auto_scan,
        "connected_project_count": plan.connected_project_count,
        "base_backup_name": plan.base_backup_name,
        "candidate_final_name": plan.candidate_final_name,
        "licensed_scanners": list(plan.licensed_scanners),
        "manual": plan.manual,
        "already_applied": plan.already_applied,
        "executable": plan.executable,
        "blockers": [
            {"code": b.code, "message": b.message} for b in plan.blockers
        ],
        "warnings": list(plan.warnings),
        "steps": plan.steps(),
        "payload": plan.conversion_payload(),
        "digest": plan.digest(),
    }
