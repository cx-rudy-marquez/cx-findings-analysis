"""Which scanners a licence permits, and what the PATCH body says.

Every case here decides whether a scanner is switched on for a customer. Getting
one wrong either leaves a licensed scanner off - the whole point of the step - or
asserts an entitlement the tenant may not have bought.
"""

from analysis.licensing import (
    FORCED_OFF,
    allowed_engines,
    current_values,
    editable_flags,
    scanner_payload,
)


def claims(*engines):
    return {"ast-license": {"LicenseData": {"allowedEngines": list(engines)}}}


ALL_EDITABLE = None


# -- reading the claim ---------------------------------------------------------


def test_the_engine_list_is_read_from_the_token_claim():
    assert allowed_engines(claims("SAST", "SCA")) == ("SAST", "SCA")


def test_a_camel_case_claim_key_is_accepted_too():
    payload = {"ast-license": {"licenseData": {"allowedEngines": ["KICS"]}}}
    assert allowed_engines(payload) == ("KICS",)


def test_an_unreadable_claim_licenses_nothing():
    """No scanner is ever enabled on the strength of a claim nobody could parse."""
    for payload in (None, {}, {"ast-license": None}, {"ast-license": "nope"},
                    {"ast-license": {"LicenseData": {"allowedEngines": "SAST"}}}):
        assert allowed_engines(payload) == ()


def test_blank_engine_names_are_dropped():
    assert allowed_engines(claims("SCA", "", "   ")) == ("SCA",)


# -- building the payload ------------------------------------------------------


def test_only_licensed_scanners_are_switched_on():
    payload = scanner_payload(["KICS", "SCA"], ALL_EDITABLE)
    assert payload["kicsScannerEnabled"] is True
    assert payload["scaScannerEnabled"] is True
    assert "apiSecScannerEnabled" not in payload
    assert "containerScannerEnabled" not in payload


def test_licence_names_match_regardless_of_case_or_padding():
    payload = scanner_payload([" api security ", "kics"], ALL_EDITABLE)
    assert payload["apiSecScannerEnabled"] is True
    assert payload["kicsScannerEnabled"] is True


def test_each_alias_grants_the_same_flag():
    """The licence and the API do not use the same words for the same thing."""
    for name in ("Secret Detection", "Enterprise Secrets", "SCS"):
        assert scanner_payload([name], ALL_EDITABLE)["secretsDetectionScannerEnabled"]
    for name in ("Repository Health", "SCS", "OSSF Scorecard"):
        assert scanner_payload([name], ALL_EDITABLE)["ossfScoreCardScannerEnabled"]
    for name in ("AISC", "AI Protection"):
        assert scanner_payload([name], ALL_EDITABLE)["aiscScannerEnabled"]


def test_sast_is_never_in_the_payload():
    """SAST is already on for every re-onboarded project; asserting it is noise."""
    assert "sastScannerEnabled" not in scanner_payload(["SAST"], ALL_EDITABLE)


def test_incremental_and_auto_pull_requests_are_always_turned_off():
    payload = scanner_payload([], ALL_EDITABLE)
    assert payload == {"sastIncrementalScan": False, "scaAutoPrEnabled": False}
    assert set(FORCED_OFF) == set(payload)


def test_a_scanner_the_repo_cannot_edit_is_omitted_not_sent_as_false():
    """Omitting leaves the platform's answer alone; false would assert one."""
    editable = {"kicsScannerEnabled": True, "ossfScoreCardScannerEnabled": False}
    payload = scanner_payload(["KICS", "Repository Health"], editable)
    assert payload["kicsScannerEnabled"] is True
    assert "ossfScoreCardScannerEnabled" not in payload


def test_a_forced_off_field_the_repo_cannot_edit_is_omitted_too():
    payload = scanner_payload([], {"sastIncrementalScan": False, "scaAutoPrEnabled": True})
    assert payload == {"scaAutoPrEnabled": False}


def test_an_unknown_field_in_the_editable_map_is_ignored():
    payload = scanner_payload(["SCA"], {"scaScannerEnabled": True, "invented": True})
    assert payload == {"scaScannerEnabled": True}


# -- reading the repo settings document ----------------------------------------

REPO = {
    "id": "72768",
    "kicsScannerEnabled": {"value": True, "isEditable": True},
    "ossfScoreCardScannerEnabled": {"value": False, "isEditable": False},
}


def test_editability_is_read_out_of_the_settings_document():
    assert editable_flags(REPO) == {
        "kicsScannerEnabled": True, "ossfScoreCardScannerEnabled": False
    }


def test_scalar_fields_are_not_mistaken_for_settings():
    assert "id" not in editable_flags(REPO)
    assert "id" not in current_values(REPO)


def test_the_before_image_records_current_values():
    assert current_values(REPO) == {
        "kicsScannerEnabled": True, "ossfScoreCardScannerEnabled": False
    }


def test_an_empty_settings_document_reads_as_nothing_known():
    assert editable_flags(None) == {}
    assert current_values(None) == {}
