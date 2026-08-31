"""Bearer-token acquisition for Checkmarx One.

A Checkmarx One API key is an OAuth *refresh token*, not a client secret, so the
exchange is `grant_type=refresh_token` against the tenant's Keycloak realm -
not the client-credentials flow the name `CX_CLIENT_SECRET` suggests. Verified
against the live tenant: the realm path keeps the legacy `/auth` prefix
(`{auth_url}/auth/realms/{tenant}/protocol/openid-connect/token`); dropping it
returns 404.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import threading
import time

import httpx

from config import Settings, settings as default_settings
from cx.errors import CxAuthError, CxConfigError

log = logging.getLogger(__name__)

#: Refresh this many seconds before the token actually expires, so an in-flight
#: request cannot straddle the boundary. Tenant issues 1800s tokens.
EXPIRY_MARGIN_SECONDS = 60


class CxAuthClient:
    """Exchanges the API key for a bearer token and caches it until near expiry.

    Thread-safe: `finding_timeline.py` in the sibling cxone-reports project hit
    redundant refreshes because its token getter had no lock and worker threads
    raced at expiry. The ETL here fans out across scans, so the lock is load-
    bearing, not decorative.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.settings = settings or default_settings
        self._client = client or httpx.Client(timeout=30.0)
        self._owns_client = client is None
        self._token: str | None = None
        self._expires_at: float = 0.0
        self._lock = threading.Lock()

    @property
    def token_url(self) -> str:
        return (
            f"{self.settings.auth_url}/auth/realms/"
            f"{self.settings.tenant}/protocol/openid-connect/token"
        )

    def get_token(self, force_refresh: bool = False) -> str:
        with self._lock:
            if not force_refresh and self._token and time.time() < self._expires_at:
                return self._token
            return self._refresh_locked()

    def _refresh_locked(self) -> str:
        missing = self.settings.missing_credentials()
        if missing:
            raise CxConfigError(
                "Missing Checkmarx credentials: " + ", ".join(missing)
            )
        try:
            response = self._client.post(
                self.token_url,
                data={
                    "grant_type": "refresh_token",
                    "client_id": self.settings.client_id,
                    "refresh_token": self.settings.api_key,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            raise CxAuthError(f"Could not reach the Checkmarx token endpoint: {exc}") from None

        if response.status_code != 200:
            raise CxAuthError(
                f"Token exchange failed ({response.status_code}): {response.text[:300]}"
            )

        try:
            payload = response.json()
            token = payload["access_token"]
            expires_in = int(payload.get("expires_in", 1800))
        except (ValueError, KeyError, TypeError) as exc:
            raise CxAuthError(f"Unexpected token response: {exc}") from None

        self._token = token
        self._expires_at = time.time() + max(expires_in - EXPIRY_MARGIN_SECONDS, 0)
        log.debug("Acquired Checkmarx token, valid for %ss", expires_in)
        return token

    def token_claims(self) -> dict:
        """The claims carried by our own bearer token.

        Read, not verified. The signature is the token endpoint's business and
        was already checked by every API call this client makes; the reason to
        look inside is the `ast-license` claim, which names the engines the
        tenant is entitled to and saves an endpoint that does not exist.

        Returns `{}` for anything unreadable. A caller decides what to do with
        no claims, and every caller here treats that as "assume nothing is
        licensed" - the safe direction, since the alternative is turning a
        scanner on for a tenant that may not have bought it.
        """
        try:
            payload = self.get_token().split(".")[1]
        except (CxAuthError, CxConfigError, IndexError, AttributeError):
            return {}
        payload += "=" * (-len(payload) % 4)
        try:
            claims = json.loads(base64.urlsafe_b64decode(payload))
        except (binascii.Error, ValueError, TypeError):
            return {}
        return claims if isinstance(claims, dict) else {}

    def auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.get_token()}"}

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
