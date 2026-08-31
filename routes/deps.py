"""Shared wiring: one client, one store, one Jinja environment.

The client choice is the demo/live switch. Nothing downstream knows which one
it has, which is what keeps the fixture path honest - the templates and the
comparison maths run identically either way.
"""

from __future__ import annotations

from functools import lru_cache

from fastapi import HTTPException
from fastapi.templating import Jinja2Templates

from config import ROOT, settings
from cx.client import CxApiClient
from cx.fixtures import FixtureClient
from store import Store

templates = Jinja2Templates(directory=str(ROOT / "templates"))


@lru_cache(maxsize=1)
def get_client():
    if settings.use_fixtures:
        return FixtureClient(settings)
    return CxApiClient(settings=settings)


@lru_cache(maxsize=1)
def get_store() -> Store:
    return Store(settings)


def require_reonboard_enabled() -> None:
    """404 unless the operator has turned re-onboarding on.

    404 rather than 403: with the flag off the feature does not exist as far as
    this deployment is concerned, and "forbidden" would advertise a flow whose
    whole point is that nobody has opted into it.

    Lives here, and reads `settings` at call time rather than closing over it,
    so it sees the same Settings object `base_context` does. The routes import
    `settings` by value at import time; a check written that way would answer
    from a snapshot taken before the process was configured.
    """
    if not settings.reonboard_enabled:
        raise HTTPException(
            status_code=404,
            detail="Re-onboarding is disabled. It moves a live repository from "
                   "one project to another, so it is off unless REONBOARD=true "
                   "is set for this deployment.",
        )


def base_context(request, tab: str = "projects") -> dict:
    """Context every page needs, plus which tab the nav should mark active.

    `tab` is passed by the route rather than derived from the URL in the
    template: `/projects/{id}` and `/runs/{id}` both belong under a tab whose
    path they do not share, and path-sniffing would get exactly those two wrong.
    """
    return {
        "request": request,
        "demo_mode": settings.use_fixtures,
        "tenant": settings.tenant or "demo",
        "tab": tab,
        # Whether the re-onboarding flow is offered. Templates read this to grey
        # the tab out; the routes enforce it, because a hidden link is not a
        # control.
        "reonboard_enabled": settings.reonboard_enabled,
    }
