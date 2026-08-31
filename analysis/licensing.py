"""Which scanners a tenant may turn on, read from its own bearer token.

A Checkmarx One access token carries the tenant's entitlement in its
`ast-license` claim, so "what is this tenant licensed for" costs nothing: no
endpoint, no extra round trip, no permission this tool does not already hold to
call the API at all.

Two vocabularies meet here and they are not the same list. The licence names
engines the way a contract does - "Repository Health", "Enterprise Secrets" -
while the repository settings API names flags the way code does -
`ossfScoreCardScannerEnabled`. The mapping below is the translation, and each
flag accepts every licence name observed to grant it, because a package that
ships Secret Detection under `SCS` and one that names it outright are the same
entitlement.

Pure functions over plain dicts, so the mapping is testable without a tenant and
without a token.
"""

from __future__ import annotations

#: (payload field, licence names that grant it).
#:
#: `sastScannerEnabled` is deliberately absent. SAST is already on for every
#: project this flow touches - it is what the comparison scan ran - and sending
#: it would be asserting something the tool did not check.
SCANNER_ENTITLEMENTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("kicsScannerEnabled", ("KICS",)),
    ("scaScannerEnabled", ("SCA",)),
    ("apiSecScannerEnabled", ("API Security",)),
    ("containerScannerEnabled", ("Containers",)),
    ("secretsDetectionScannerEnabled", ("Secret Detection", "Enterprise Secrets", "SCS")),
    ("aiscScannerEnabled", ("AISC", "AI Protection")),
    ("ossfScoreCardScannerEnabled", ("Repository Health", "SCS", "OSSF Scorecard")),
)

#: Forced off whatever the licence says, because neither is a scanner: they are
#: scan *behaviour*. An incremental scan measures a delta, and the point of this
#: step is one complete scan of the whole repository; SCA's automatic pull
#: requests write to the customer's repository, which this tool does not do.
FORCED_OFF: tuple[str, ...] = ("sastIncrementalScan", "scaAutoPrEnabled")


def _normalise(name: object) -> str:
    return str(name or "").strip().lower()


def allowed_engines(claims: dict | None) -> tuple[str, ...]:
    """The engine names in a token's `ast-license` claim.

    Returns an empty tuple for anything it cannot read. That degrades into a
    payload of forced-off flags only - no scanner is ever enabled on the
    strength of a claim nobody could parse.
    """
    license_claim = (claims or {}).get("ast-license") or {}
    if not isinstance(license_claim, dict):
        return ()
    data = license_claim.get("LicenseData") or license_claim.get("licenseData") or {}
    if not isinstance(data, dict):
        return ()
    engines = data.get("allowedEngines")
    if not isinstance(engines, (list, tuple)):
        return ()
    return tuple(str(engine) for engine in engines if str(engine or "").strip())


def scanner_payload(
    engines: tuple[str, ...] | list[str] | None,
    editable: dict[str, bool] | None = None,
) -> dict[str, bool]:
    """The `PATCH /repo/{repoId}` body: every licensed scanner this repo accepts.

    `editable` is the repository's own `isEditable` map. A flag it reports as
    not editable is omitted rather than sent as `false`, because those two say
    different things: omitting leaves the platform's answer alone, while sending
    `false` would be this tool asserting a scanner should be off when all it
    knows is that it may not set it. The platform refuses such fields anyway -
    a live conversion on the reference tenant recorded
    `ossfScoreCardScannerEnabled: UNSUPPORTED_SCM_TYPE` - so the omission is
    what makes that refusal visible as a recorded skip instead of a silently
    dropped field.

    Passing `editable=None` means "nothing is known about editability", and
    every licensed flag is sent.
    """
    licensed = {_normalise(engine) for engine in engines or ()}

    def allowed(field: str) -> bool:
        return editable is None or bool(editable.get(field, False))

    payload: dict[str, bool] = {}
    for field, grants in SCANNER_ENTITLEMENTS:
        if any(_normalise(grant) in licensed for grant in grants) and allowed(field):
            payload[field] = True
    for field in FORCED_OFF:
        if allowed(field):
            payload[field] = False
    return payload


def editable_flags(settings: dict | None) -> dict[str, bool]:
    """The `isEditable` map out of a `GET /repo/{repoId}` response.

    That endpoint returns each setting as `{"value": bool, "isEditable": bool}`,
    while the PATCH body is flat booleans. This reads one shape; nothing else
    needs to know about the other.
    """
    flags: dict[str, bool] = {}
    for key, value in (settings or {}).items():
        if isinstance(value, dict) and "isEditable" in value:
            flags[key] = bool(value.get("isEditable"))
    return flags


def current_values(settings: dict | None) -> dict[str, object]:
    """The `value` of each setting, for the before-image in the audit trail."""
    return {
        key: value.get("value")
        for key, value in (settings or {}).items()
        if isinstance(value, dict) and "value" in value
    }
