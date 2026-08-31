"""Credentials must not survive into an error message, a log line or the UI."""

from cx.errors import CxApiError, CxError, scrub

FAKE_JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NSIsInRlbmFudCI6ImFjbWUifQ."
    "c2lnbmF0dXJlLXZhbHVlLWhlcmU"
)


def test_a_bearer_token_never_survives():
    assert FAKE_JWT not in scrub(f"Authorization: Bearer {FAKE_JWT}")


def test_a_bare_jwt_in_a_url_never_survives():
    assert FAKE_JWT not in scrub(f"https://host/cb?id_token={FAKE_JWT}")


def test_form_encoded_secrets_never_survive():
    scrubbed = scrub("grant_type=refresh_token&refresh_token=abc123secret&client_id=ast-app")
    assert "abc123secret" not in scrubbed
    assert "client_id=ast-app" in scrubbed  # non-sensitive context is preserved


def test_scrubbing_happens_at_construction_not_at_display():
    error = CxError(f"boom {FAKE_JWT}")
    assert FAKE_JWT not in str(error)
    assert FAKE_JWT not in repr(error)


def test_api_error_keeps_its_status_code():
    error = CxApiError("nope", status_code=403)
    assert error.status_code == 403
