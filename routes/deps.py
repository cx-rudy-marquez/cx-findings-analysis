"""Shared wiring: one client, one store, one Jinja environment."""

from __future__ import annotations

from functools import lru_cache

from fastapi import HTTPException
from fastapi.templating import Jinja2Templates

from config import ROOT, settings
from cx.client import CxApiClient
from store import Store

templates = Jinja2Templates(directory=str(ROOT / "templates"))


def pluralize(count: int, singular: str, plural: str | None = None) -> str:
    """Standard English pluralization for count-dependent modal copy.

    Registered as a Jinja global so both server-rendered callers of the
    shared confirm modal (single-project N=1, bulk's static shell) get
    correct grammar without duplicating the singular/plural branch.
    """
    return singular if count == 1 else (plural or f"{singular}s")


templates.env.globals["pluralize"] = pluralize


def phase_timeline(timestamps: dict) -> str:
    """One compact tooltip string from a run's phase timestamps, skipping any
    phase not yet reached.

    Backs the Bulk Run view's per-row tooltip (GOAL_FIX_BULK_ANALYSIS.md
    FIX 4's "clearer, more granular phase logging/timestamps"), so a batch's
    actual concurrency is readable on the page instead of inferred from UI
    polling snapshots. Mirrored in JS (templates/run_bulk.html) for the poller
    that replaces these rows client-side.
    """
    labels = (
        ("created", timestamps.get("created_at")),
        ("download started", timestamps.get("download_started_at")),
        ("scan started", timestamps.get("scan_started_at")),
        ("completed", timestamps.get("completed_at")),
    )
    return " · ".join(f"{label} {value}" for label, value in labels if value)


templates.env.globals["phase_timeline"] = phase_timeline


@lru_cache(maxsize=1)
def get_client():
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
        "tenant": settings.tenant or "demo",
        "tab": tab,
        # Whether the re-onboarding flow is offered. Templates read this to grey
        # the tab out; the routes enforce it, because a hidden link is not a
        # control.
        "reonboard_enabled": settings.reonboard_enabled,
    }
