# Findings Analysis Impact Dashboard

Measures what Checkmarx One's **SAST Findings Analysis** would remove from a
project's backlog, so the decision to enable it tenant-wide can be made from a
number rather than a hunch.

Findings Analysis is an optional AI pass that runs after a SAST scan and drops
results it classifies as false positives. It is off by default. This tool picks
an onboarded project, reads its current SAST severity profile, re-onboards the
same source as `<name>_FA` with the capability enabled, scans it, and renders
the before/after.

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env        # then fill in your tenant details

# Demo mode - no credentials, no tenant contact, every number badged "Sample data"
USE_FIXTURES=true .venv/bin/uvicorn app:app --port 8060

# Live mode
.venv/bin/uvicorn app:app --port 8060
```

Then open http://127.0.0.1:8060.

`.env` accepts the same variable names as the sibling
`cx-analytics-and-risk-orchestration` project, so one file can serve both. A
Checkmarx One API key is an OAuth **refresh token**, not a client secret — the
token exchange uses `grant_type=refresh_token`.

## What a run does

Only the confirmation dialog on a project page can start one. There is no GET
that creates anything, so a reload or a prefetch cannot spend a scan.

1. Resolve the baseline — the project's most recent completed scan **that ran
   the SAST engine**, via `GET /api/projects/last-scan?engine=sast`. This is not
   the same as its most recent scan: on the reference project, the newest run is
   on a different branch and the newest run *on master* is a later SCA-only pass
   carrying no SAST results. Picking by recency or by the UI's "Full Scan" label
   compares against nothing.
2. Read `sastCounters` from `GET /api/scan-summary` for the baseline's status
   mix — per-engine, so the SAST figure needs no hand-subtraction of SCA
   findings. The before/after totals come later, from the compare API.
3. `HEAD /api/repostore/scans/{id}` — stop here with an explanation if the
   tenant no longer retains the source.
4. Create `<name>_FA`, tagged `purpose=findings-analysis-poc`.
5. PATCH `scan.config.sast.findingsAnalysis=true` on it, then **read it back**.
   The key is not in any published spec, so a 204 alone is not proof.
6. Download the source, request a pre-signed upload URL, PUT the archive.
7. Submit a **full** SAST scan. Not incremental: Findings Analysis only
   evaluates findings in `NEW` state, and on a fresh project every finding is
   new — which is what makes the measured drop a ceiling rather than a sample.
8. Poll to completion, then ask the platform to compare the two scans:
   `GET /api/scans-compare/sast/status` for the severity x status tiles and
   `GET /api/sast-results/compare` for the per-finding breakdown.

Every one of those writes is journalled to SQLite before it fires, so an
interrupted run still shows what was created in the tenant.

## Reading the result

- Every figure comes from Checkmarx's own comparison of the two scans
  (`GET /api/scans-compare/sast/status` and `GET /api/sast-results/compare`),
  which labels each finding **NEW**, **RECURRENT** or **FIXED**. **Removed** is
  the FIXED count — not two severity totals subtracted, which would net
  appearances against removals and report a run that removed 8 and gained 8 as
  a clean zero.
- **Reduction %** is measured against eligible findings only. Critical results
  are never analysed by the platform, so folding them into the denominator would
  understate the effect; they appear as their own labelled, ineligible row.
- Two things Findings Analysis cannot do invalidate a run, and either one
  withholds the headline percentage: a **Critical marked FIXED**, and **anything
  marked NEW** (the feature only ever removes). The per-severity table is still
  shown, with the warnings explaining why the headline is blank.
- **Analyst hours saved** is `removed x minutes-per-finding`. The assumption is
  an editable input on the confirmation dialog, not a buried constant.
- The **NEW-state share** of the original baseline is shown alongside, because
  an established project only sees this benefit on newly introduced findings.
  The headline number is the ceiling, not the recurring monthly figure.
- Demo runs are badged **Sample data**; live runs are badged **Live result**.
  The baseline counts in `fixtures/webgoatnet.json` are real; the after-numbers
  in it are invented, which is exactly why the badge exists.

## What the first live run established

Run against `rmarquez/WebGoatNet` on 2026-08-30. Recorded here because three of
these are tenant behaviours no published spec states, and the last one is the
main threat to the tool's own conclusion.

- **The source download is a 302, not the archive.**
  `GET /api/repostore/code/{scan-id}` redirects to a presigned URL on the
  tenant's storage gateway. Redirects must be followed, and because 302 is not
  an error status, an unfollowed redirect writes a few hundred bytes of HTML and
  looks like success. `download_code` now follows the hop and rejects any body
  that is not a zip.
- **The presigned URLs still require the tenant bearer.** They are served from
  `<base_url>/storage/...`, not raw S3, and the gateway answers an
  unauthenticated GET or PUT with 401 regardless of Content-Type. The token is
  attached only when the URL is on the tenant's own host.
- **There is no preset named `Default`.** Sending one fails the scan with
  `Preset not found` (errorCode 1024100). WebGoatNet's baseline ran with an
  empty `presetName`, i.e. inheriting from tenant configuration, so the `_FA`
  scan inherits too. A substituted rule set would change which findings exist
  and the comparison would measure the swap, not the feature.
- **Findings Analysis removed nothing on this tenant.** The `_FA` scan completed
  in 2 minutes over the same 15,389 LOC and returned the same 133 SAST findings.
  The project config key reads back `true`; the SAST engine log contains no
  Findings Analysis activity for either scan. Whether the feature ran and found
  no false positives, or did not run for want of a tenant-level entitlement, is
  not distinguishable from the API alone — take it up with Checkmarx before
  reading any conclusion into a zero.
- **A re-onboarded copy is not a clean control.** A mature project carries
  triage severity overrides that a freshly created copy does not inherit. The
  compare API states the damage plainly: of 143 findings across the two scans,
  10 are FIXED (2 of them Critical) and 10 are NEW. Both are things Findings
  Analysis cannot produce, so the dashboard withholds the headline rather than
  publish the residual difference as a win.
- **`/api/scan-summary` and the compare API disagree, and the compare API is
  right.** `severityCounters` exclude results the platform considers FIXED, so
  the same baseline scan reads Critical 63 there and 68 through
  `baseScanCounters`. The comparison is built entirely from the compare
  endpoints so both halves are measured with one instrument; `scan-summary`
  survives only on the project page, where no second scan exists yet.

## The portfolio view

The landing page ranks the whole tenant, so the enable-it-everywhere decision can
start from a shortlist instead of 46 individual visits.

Two signals per project, deliberately in separate columns:

- **Opportunity score** = `High×3 + Medium×2 + Low×1`. Critical is excluded
  outright — the platform never evaluates Critical results, so those findings
  cannot be part of the opportunity. A project with 31 Critical and little else
  correctly ranks near the bottom.
- **Migration risk** — Low / Medium / High, from the scan and branch history that
  re-onboarding would discard. Low needs *both* counts small; High needs *either*
  one large, because 40 scans on one branch and 3 scans across 9 branches are
  each expensive to lose. The label always carries the numbers behind it
  ("High risk: re-onboarding would discard 42 scans across 5 branches"), on hover
  and to a screen reader.

Blending the two into one recommendation is deliberately deferred: a
high-benefit/high-risk project and a low-benefit/low-risk one are different
decisions, and one combined verdict would hide which is which.

A project with no completed SAST scan is shown **unscored**, never as zero — 12 of
46 on the reference tenant. Unmeasured and measured-but-clean are different
states, and sorting them together would bury the difference.

### Why it is cached

Building the view costs ~10s against a 46-project tenant, so it is built on
demand and cached in SQLite. The page always shows **as of `<timestamp>`** and
marks a snapshot older than `SNAPSHOT_STALE_HOURS` as stale; cached numbers are
never presented as current. Refresh is a POST, so a reload or a prefetch cannot
spend the cost.

The cost is what it is because of what batches and what does not:

| Work | How |
|---|---|
| Baselines for all projects | `last-scan` takes `project-ids` as an array — one call per candidate branch, not one per project |
| Severity counts | `scan-summary` takes `scan-ids` as an array — 34 scans in two chunked calls |
| Scan + branch history | One unfiltered walk of `/api/scans` (223 rows tenant-wide); every row carries `projectId` and `branch` |

The history walk replaced the obvious approach of `/api/scans?project-id=` plus
`/api/projects/branches?project-id=` per project — 92 calls, and `/branches`
defaults to `limit=20`, which would have silently undercounted any project with
more branches than that.

### Tuning

Weights and thresholds are defaults in `config.py` (all env-overridable) and
editable on the page, persisted in SQLite. Reset deletes the saved row rather
than writing a second copy of the defaults, so the two can never drift apart.
Re-scoring reads the stored snapshot — changing a weight re-ranks instantly and
makes no tenant call, because the finding counts did not change.

Defaults are fitted to the reference tenant's real distribution rather than
guessed: 23 of 46 projects have a single scan and 28 a single branch, while only
a handful exceed 9 scans (max 58) or 3 branches (max 11). Low ≤2 scans and 1
branch; High ≥10 scans or ≥4 branches. That yields 28 low / 11 medium / 7 high.

## Three tabs

**Projects** ranks the portfolio, **Recent runs** is the history, and the gear
opens **Settings**. They were one page until the scoring knobs and the run log
started competing for attention with the ranking they exist to serve.

## Is this comparison trustworthy?

Two checks answer that, because a number nobody can attribute is worse than no
number.

**Parameter parity.** After enabling Findings Analysis on the `_FA` copy and
before scanning it, the run diffs seven SAST settings against the base project —
fast scan mode, folder/file filter, incremental, LLM-based scanning, preset,
recommended exclusions, and Findings Analysis itself. The last one is *expected*
to differ; that difference is the experiment. Any of the other six differing is
a confound: a preset swap or a changed exclusion filter moves the finding count
on its own, and the headline percentage would report it as Findings Analysis
having done the work. A mismatch never aborts the run — it labels the comparison
"needs review" and lists each differing field with both values.

Two normalisations carry the weight, and both are in `analysis/parity.py`: an
absent key and an empty value both mean "inherit from the tenant" and must
compare equal, and a preset the base pins is not a mismatch because the flow
passes that preset in the scan payload, so both scans ran the same rule set.

**Baseline staleness.** Every figure on a project's row is measured against one
scan. Past 90 days (tunable) that scan is flagged "Re-base" on the Projects
list, because a comparison anchored to it measures the intervening months of
code alongside the capability. The flag is an indicator only — this tool does
not trigger scans on projects it did not create.

## [BETA] Re-onboarding

Once a comparison shows the capability is worth having, the repository still
points at the wrong project: the base scans without Findings Analysis, the `_FA`
copy scans with it. Re-onboarding swaps them with four calls, in this order:

1. `POST /api/repos-manager/projects/{base}/disconnect` — the base becomes a
   manual project. **Its scan history is preserved and it is never deleted.**
   Its webhook is removed.
2. `PATCH /api/projects/{base}` → `{"name": "<base>_FA_BACKUP"}` — the base is
   renamed out of the way. Same project, same id, same scans; only the name
   moves, and the suffix is how someone reading the tenant later can tell which
   project used to own the repository.
3. `PATCH /api/projects/{copy}` → `{"name": "<base>"}` — the copy drops its
   `_FA` suffix and takes over the name the base just released.
4. `POST /api/repos-manager/project-conversion` — the copy is connected to the
   repository, then polled through `GET /project-conversion?processId=…` to a
   terminal `migrationStatus`.

The order is forced at both ends. The base only gives up its name once it has
given up the repository, and the copy can only take that name once it is free —
so the renames sit between the disconnect and the conversion rather than
anywhere more convenient. Only a *trailing* `_FA` is stripped, so a project
legitimately named `FOO_FACTORY` is left alone, and the backup suffix is not
applied twice if a name already carries it.

Because four things can now be half-applied, a failure reports exactly which of
them landed, in order, rather than a single "it broke".

**Then two more, best effort.** The project now serving the repository has only
ever run the SAST-only comparison scan, so once the conversion reports `OK`:

5. `PATCH /api/repos-manager/repo/{repoId}?projectId={copy}` — turn on every
   scanner the tenant is licensed for, and turn `sastIncrementalScan` and
   `scaAutoPrEnabled` off. The tenant's entitlement is read from the
   `ast-license` claim of the bearer token this tool already holds, so Step A of
   the goal costs no API call at all. `repoId` comes straight off
   `GET /api/projects/{id}`, which reports it for every connected project —
   deliberately not looked up through repos-manager, whose organisation and
   repository listings return `500 ReposManager generic exception` on the
   reference tenant.
6. `POST /api/scans/rescan` with `{"project_id": "<copy>"}` — one fresh full
   scan across the scanners just enabled. It is not waited on.

Both are listed in the dry run, because nothing here fires undisclosed. Neither
is in the plan digest: they cannot leave a repository half-owned, and binding
them would refuse a re-onboarding over a scanner flag that drifted between
preview and confirm. Both are best effort — **a failure in either is a warning
against a re-onboarding still reported as successful**, because the repository
did in fact move. The scan is attempted even when the settings update failed: a
full scan under the old settings beats no scan, and the audit trail records
which settings it ran under, along with both requests and both responses.

A licensed scanner the repository reports as not editable is *omitted* rather
than sent as `false`. Those say different things — omitting leaves the
platform's answer alone, while `false` would assert a scanner should be off when
all this tool knows is that it may not set it. The platform is the final
authority either way: the route applies "license/FF + cascade enforcement only",
and a conversion on the reference tenant recorded
`ossfScoreCardScannerEnabled: UNSUPPORTED_SCM_TYPE`.

It is reachable only from a completed comparison that carries a parity report,
and only after a mandatory dry run that names both project ids, both calls and
the exact request body. Confirming posts back a digest of that plan; the plan is
rebuilt from the tenant before anything is sent, and a mismatch refuses rather
than applying something nobody read. No token is ever entered — the conversion
borrows the integration's existing credential.

**Finding the repository.** A project connected through the Code Repository
integration reports `repoUrl: ""`. That is how the integration flow stores
things — it is *not* evidence the project is unconnected, and only the legacy
manual flow populates that field. The address is resolved instead by:

1. `GET /v2/scms` for every integration in the tenant.
2. `GET /scms/{id}/projects` on **each** of them (paginated on `limit`/`offset`,
   following `hasMore`), looking for the project by name — never stopping at the
   first integration whose type looks right. A tenant routinely has several
   integrations of one type; on a live tenant, four Checkmarx-proxied GitLab
   entries sit alongside the cloud one, and their base URLs cannot tell them
   apart. Membership is the only reliable signal, and it yields the
   connected-project count the safety check needs anyway.
3. `scmRepositoryUrl` = that integration's `repoBaseUrl` + the project's
   `org/repo` path. Bitbucket Cloud reports its *API* host, which is translated
   to the browse host. When more than one integration lists the project, a
   directly-addressed one wins over a Checkmarx-proxied one.

A Checkmarx link address (`https://<region>.ast.checkmarx.net/link/<uuid>`) is a
usable repository address — the scan's own git handler records exactly that URL —
so it is used, and flagged in the preview so the operator can see the address is
a Checkmarx one rather than their own hostname.

**Why it still refuses sometimes.** Both conditions were found on a live tenant:

| Blocker | Why |
|---|---|
| `last-connected-project` | Disconnect runs first and the conversion carries no token. If the base is the only project connected through its integration, the credential disappears between the two calls and the base is left disconnected with nothing able to convert. |
| `backup-name-taken` / `final-name-taken` | A different project already holds a name one of the renames needs — usually left over from an earlier attempt. Renaming onto it would fail, or leave two projects nobody can tell apart. |
| `candidate-not-suffixed` | The copy's name does not end in `_FA`, so there is no suffix to drop. This flow only handles copies the tool itself created. |

Failure is never retried. If the conversion fails after the disconnect landed,
the result says so explicitly: the base still exists with its full history as a
manual project, its repository is connected to nothing, and a human needs to
reconnect it.

### Projects with no repository at all

A project that was never connected to source control has no repository URL, no
`scmType` and no SCM organisation, so it fails three of the conversion's
preconditions and used to be permanently stuck: measurable, never re-onboardable.
It now takes a reduced path — **two renames and a rescan**:

1. `PATCH /api/projects/{base}` → `{"name": "<base>_FA_BACKUP"}`
2. `PATCH /api/projects/{copy}` → `{"name": "<base>"}`
3. `POST /api/scans/rescan` with `{"project_id": "<copy>"}` — best effort

No disconnect (no connection to remove), no `project-conversion` (nothing to
connect to), no `PATCH /repo/{repoId}` (no `repoId`, so the rescan runs with
whatever the comparison configured), no protected branches. All three skipped
calls are listed in the preview and journalled with the reason they were
skipped, so a manual run's audit trail reads the same way an SCM one's does.

The rescan is not a guess: a manual project on the reference tenant carries a
completed scan of `type: "rescan"` whose `Handler.RescanHandler` names the scan
it re-ran, with per-engine `sourceScanId`. It re-runs source Checkmarx already
holds — nothing is downloaded or uploaded.

**Telling manual apart from "connected in a way this beta cannot resolve"** is
the whole difficulty, because renaming a project that still receives pushes
leaves them landing on the backup copy. Five conditions must all hold, and every
one of them earns its place on the reference tenant's 47 projects:

| Condition | What it catches |
|---|---|
| no `repoId` and no `scmRepoId` | The repository-manager record itself. All 30 connected projects carry both; none of the 17 unconnected ones do. |
| `origin` is not an SCM display name | Same set, from the project's own field. |
| no integration lists the project by name | A connection the project fields under-report. |
| no cloned scan in the last page of history | `delphilint`, `VulnPascal`, `kubernetes-goat` and four others: an uploaded or rescanned *baseline* sitting on top of git-cloned scans. Judging on the baseline alone called all seven manual. |
| the baseline scan has no git handler | `scheduler`, whose scans arrive from a GitHub PR webhook with repo URL and credentials in the handler. |

`repoUrl` is deliberately never consulted. It settles nothing in either
direction on this tenant: `rudy-marquez/juice-shop` is connected with an empty
one, and manual projects still carry the URL they were created with. The scan
history is read only for projects that already look manual on the cheaper
signals — for the 30 connected ones the call never happens — and an unreadable
history is treated as "not manual", which leaves the project exactly as stuck as
it was rather than renaming it on no evidence.

**This path is resumable, and the SCM one still is not.** A failure between the
two renames leaves no repository pointing anywhere unexpected — the live name is
simply unclaimed — so the failure page offers the confirmation again. The
pre-flight reads both current names, decides from the *suffixes* which rename is
outstanding, and resumes from it; the plan's own name fields cannot tell a fresh
run from a resumed one, because they are built from whatever the tenant
currently reports and the backup suffix is applied idempotently. Both renames
are verified by reading the name back before the next write, since
`PATCH /api/projects/{id}` answers 204 with no body. The approved digest still
matches on a resume, because it binds ids and *target* names, neither of which
moves when the first rename lands. A pair of names in no recognised state aborts
before writing anything.

## Layout

| Path | What lives there |
|---|---|
| `cx/auth.py`, `cx/errors.py` | Token exchange and credential scrubbing, ported from the sibling analytics project |
| `cx/client.py` | Reads, then a clearly separated block of tenant-modifying writes |
| `cx/flow.py` | The re-onboarding sequence, run as a background task |
| `cx/fixtures.py` | Demo-mode stand-in with the same surface |
| `analysis/` | Pure before/after arithmetic, per-finding attribution, and portfolio scoring |
| `analysis/parity.py` | The SAST-configuration diff that decides whether a comparison is attributable |
| `analysis/reonboard.py` | Pure planning for the BETA re-onboarding: the payload, the refusals, the plan digest |
| `cx/reonboard.py` | The disconnect/convert sequence, run as a background task |
| `cx/portfolio.py` | Builds the tenant-wide snapshot the landing page ranks |
| `store.py` | Runs, step log, cached result sets, portfolio snapshot and tuning |
| `routes/`, `templates/`, `static/` | FastAPI routers and the server-rendered UI |

## Tests

```bash
.venv/bin/python -m pytest
```

Covers the severity arithmetic (including the Critical-ineligible invariant
and the refusal to headline a run the platform's own classification shows is
uncontrolled), credential scrubbing, the flow's write ordering and its refusal
to scan when a precondition fails, plus end-to-end renders through the real
ASGI app in demo mode.

Several tests exist because a live run found the bug they now pin: the
compare endpoint's **row** offset against `/api/results`' page index, its
20-row default `limit`, the 302 on the source download, and the tenant bearer
the storage gateway requires despite the URL already being presigned.
