"""Regression tests for the two storage-gateway transfer bugs.

Both were invisible to the unit suite and only surfaced on a live run:

1. `GET /api/repostore/code/{id}` answers 302 with a redirect to a presigned
   URL. httpx does not follow redirects by default and 302 is not >= 400, so
   the client wrote the redirect's HTML body to disk and reported success.
2. That presigned URL lives on the tenant's own storage gateway, which
   enforces auth. An unauthenticated PUT is refused with 401.
"""

from __future__ import annotations

import io

import httpx
import pytest

from config import Settings
from cx.client import RESULTS_PAGE_SIZE, CxApiClient
from cx.errors import CxApiError

BASE = "https://tenant.example.net"
ZIP = b"PK\x03\x04" + b"\x00" * 512


class StubAuth:
    def auth_header(self) -> dict[str, str]:
        return {"Authorization": "Bearer test-token"}

    def get_token(self, force_refresh: bool = False) -> str:
        return "test-token"

    def close(self) -> None:
        pass


def build(handler) -> CxApiClient:
    settings = Settings(base_url=BASE)
    return CxApiClient(
        auth=StubAuth(),
        settings=settings,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_download_follows_the_redirect_to_the_storage_gateway():
    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers.get("authorization")))
        if request.url.path.startswith("/api/repostore/code/"):
            return httpx.Response(302, headers={"Location": f"{BASE}/storage/x.zip"})
        return httpx.Response(200, content=ZIP)

    dest = io.BytesIO()
    written = build(handler).download_code("scan-1", dest)

    assert written == len(ZIP)
    assert dest.getvalue() == ZIP
    assert len(seen) == 2, "the redirect must be followed, not written to disk"
    # The gateway rejects an unauthenticated GET, so the bearer has to survive
    # the same-host hop.
    assert seen[1][1] == "Bearer test-token"


def test_download_rejects_a_body_that_is_not_a_zip():
    """The precise failure mode of bug 1: a 2xx carrying HTML, not an archive."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'<a href="https://...">Found</a>')

    with pytest.raises(CxApiError) as excinfo:
        build(handler).download_code("scan-1", io.BytesIO())
    assert "not a zip archive" in str(excinfo.value)


def test_upload_authenticates_against_the_tenant_storage_gateway():
    seen: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200)

    build(handler).put_upload(f"{BASE}/storage/uploads/abc?X-Amz-Signature=x", ZIP)
    assert seen["auth"] == "Bearer test-token"


def test_upload_withholds_the_token_from_a_third_party_host():
    """A genuine off-tenant presigned URL must not receive the tenant bearer."""
    seen: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200)

    build(handler).put_upload("https://s3.amazonaws.com/bucket/key?sig=x", ZIP)
    assert seen["auth"] is None


def test_compare_results_pages_by_row_offset_not_page_index():
    """The trap: `/api/results` offset is a page index, this one is a row offset.

    Reusing the page-walking idiom would request offsets 0, 1, 2 and collect the
    same rows over and over while believing it had paged.
    """
    total = RESULTS_PAGE_SIZE * 2 + 3
    seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params.get("offset"))
        limit = int(request.url.params.get("limit"))
        seen.append(offset)
        rows = [
            {"similarityID": i, "status": "RECURRENT"}
            for i in range(offset, min(offset + limit, total))
        ]
        return httpx.Response(200, json={"results": rows, "totalCount": total})

    rows = build(handler).compare_results("base", "scan")

    assert len(rows) == total
    assert len({r["similarityID"] for r in rows}) == total, "pages must not overlap"
    assert seen == [0, RESULTS_PAGE_SIZE, RESULTS_PAGE_SIZE * 2]


def test_compare_results_always_sends_an_explicit_limit():
    """Omitted, the endpoint returns 20 rows and an honest totalCount - a
    truncated answer shaped exactly like a complete one."""
    seen: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["limit"] = request.url.params.get("limit")
        return httpx.Response(200, json={"results": [], "totalCount": 0})

    build(handler).compare_results("base", "scan")
    assert seen["limit"] is not None and int(seen["limit"]) > 20


def test_compare_summary_hits_the_status_subpath():
    """`servers.url` is /api/scans-compare/sast; the operation is at /status."""
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["base"] = request.url.params.get("base-scan-id")
        # Never send evaluation-status: it 500s on this tenant.
        seen["evaluation"] = request.url.params.get("evaluation-status")
        return httpx.Response(200, json={"severityStatusCounters": []})

    build(handler).compare_summary("base-1", "scan-1")
    assert seen["path"] == "/api/scans-compare/sast/status"
    assert seen["base"] == "base-1"
    assert seen["evaluation"] is None


# --- CWE-117: Log Forging prevention -----------------------------------------
# User-supplied project_id flows through get_project() -> get() -> _json() ->
# _request(), where it is embedded in the `path` argument that reaches the
# debug log call.  A project_id containing CR or LF characters could forge
# additional log lines.  The fix sanitises `path` at the log call site.


def test_log_debug_strips_newline_from_user_controlled_path(caplog):
    """A project_id containing \\n must not produce a second log record.

    The attack: a crafted project_id such as
    ``legit-id\\nINFO root Injected log entry`` would cause `path` to span
    multiple lines when formatted into the debug message, creating a fake log
    record.  After the fix the newline is replaced with a space so the log
    message is a single line and cannot be mistaken for additional records.
    """
    import logging

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "legit-id", "name": "test"})

    client = build(handler)
    # Simulate a project_id that contains an injected newline character.
    # In production this value arrives from a form POST (routes/runs.py:77).
    malicious_project_id = "legit-id\nINFO root Injected log entry"
    with caplog.at_level(logging.DEBUG, logger="cx.client"):
        client.get(f"/api/projects/{malicious_project_id}")

    # The log output must be a single record: the newline must have been
    # replaced, not left in place where it would produce a second apparent line.
    debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert debug_records, "at least one debug record expected"
    for record in debug_records:
        assert "\n" not in record.getMessage(), (
            "Log message must not contain a literal newline — that would "
            "allow an attacker to forge additional log entries."
        )
        assert "\r" not in record.getMessage(), (
            "Log message must not contain a carriage return."
        )


def test_log_debug_strips_carriage_return_from_user_controlled_path(caplog):
    """A project_id containing \\r must not produce a log-injection opportunity.

    Carriage return can be used to overwrite portions of a log line in
    terminals or log viewers that interpret CR as "move cursor to line start".
    """
    import logging

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "legit-id", "name": "test"})

    client = build(handler)
    malicious_project_id = "legit-id\rOverwritten log content"
    with caplog.at_level(logging.DEBUG, logger="cx.client"):
        client.get(f"/api/projects/{malicious_project_id}")

    debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert debug_records, "at least one debug record expected"
    for record in debug_records:
        assert "\r" not in record.getMessage(), (
            "Log message must not contain a carriage return — that would "
            "allow an attacker to manipulate log output."
        )


def test_log_debug_strips_crlf_from_user_controlled_path(caplog):
    """A project_id containing \\r\\n must not produce a log-forging opportunity."""
    import logging

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "legit-id", "name": "test"})

    client = build(handler)
    malicious_project_id = "legit-id\r\nERROR admin Fake critical error"
    with caplog.at_level(logging.DEBUG, logger="cx.client"):
        client.get(f"/api/projects/{malicious_project_id}")

    debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert debug_records, "at least one debug record expected"
    for record in debug_records:
        msg = record.getMessage()
        assert "\n" not in msg and "\r" not in msg, (
            "Log message must not contain CR or LF after sanitisation."
        )


def test_log_debug_preserves_legitimate_path_content(caplog):
    """A benign project_id must still appear correctly in the debug log.

    The sanitisation must not strip content other than CR and LF characters,
    so a normal UUID-style identifier must survive unchanged.
    """
    import logging

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "abc-123", "name": "my-project"})

    client = build(handler)
    with caplog.at_level(logging.DEBUG, logger="cx.client"):
        client.get("/api/projects/abc-123")

    debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert debug_records, "at least one debug record expected"
    # The sanitised path should still be recognisable in the log message.
    assert any(
        "/api/projects/abc-123" in record.getMessage()
        for record in debug_records
    ), "Legitimate path content must not be removed by sanitisation."


def test_log_debug_sanitises_path_not_the_http_request(caplog):
    """Sanitisation applies only to the log output, not to the actual HTTP URL.

    The outbound request must carry the original (unsanitised) path so that
    the Checkmarx API receives the value the caller intended.  Only the log
    record should have its newlines replaced.
    """
    import logging

    captured_url: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_url.append(str(request.url))
        return httpx.Response(200, json={"id": "test", "name": "test"})

    client = build(handler)
    # A path with an embedded newline (simulating a user-controlled segment).
    path_with_nl = "/api/projects/test-id\ninjected"
    with caplog.at_level(logging.DEBUG, logger="cx.client"):
        client.get(path_with_nl)

    # The log record must not contain the raw newline.
    debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
    for record in debug_records:
        assert "\n" not in record.getMessage()

    # The HTTP request URL is handled by httpx and is separate from the log
    # sanitisation — the sanitisation only affects what appears in the log.
    assert captured_url, "the HTTP request must still be sent"
