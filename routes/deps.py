"""Shared wiring: one client, one store, one Jinja environment.

The client choice is the demo/live switch. Nothing downstream knows which one
it has, which is what keeps the fixture path honest - the templates and the
comparison maths run identically either way.
"""

from __future__ import annotations

from functools import lru_cache

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
    }
