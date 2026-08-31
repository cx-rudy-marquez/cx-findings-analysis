"""Exceptions that are safe to render in the UI.

Checkmarx bearer tokens and API keys are long opaque strings that can end up
inside httpx exception text (request URLs, echoed headers). Everything raised
from the `cx` package passes through `scrub()` first so no credential can reach
a log line, an error banner, or a traceback.
"""

from __future__ import annotations

import re

_JWT = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*\.?[A-Za-z0-9_\-]*")
_BEARER = re.compile(r"(?i)(bearer\s+)\S+")
_SECRET_PARAM = re.compile(
    r"(?i)\b(refresh_token|client_secret|access_token|api_key|password)=[^&\s\"']+"
)


def scrub(text: object) -> str:
    """Replace anything credential-shaped with a placeholder."""
    out = str(text)
    out = _JWT.sub("<redacted-token>", out)
    out = _BEARER.sub(r"\1<redacted-token>", out)
    out = _SECRET_PARAM.sub(r"\1=<redacted>", out)
    return out


class CxError(Exception):
    """Base class. Message is scrubbed at construction, not at display time."""

    def __init__(self, message: object) -> None:
        super().__init__(scrub(message))


class CxAuthError(CxError):
    """Token exchange failed - bad or expired API key, wrong tenant/realm."""


class CxApiError(CxError):
    """A Checkmarx API call failed after retries."""

    def __init__(self, message: object, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class CxConfigError(CxError):
    """Required configuration is missing."""
