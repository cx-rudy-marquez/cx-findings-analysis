"""Findings Analysis Impact Dashboard.

Run: uvicorn app:app --reload --port 8060
"""

from __future__ import annotations

import logging

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from config import ROOT, settings
from routes import projects, runs
from routes.deps import templates
from store import Store

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(_: FastAPI):
    Store()  # create the schema before the first request needs it
    log.info("Settings: %s", settings.describe())
    missing = settings.missing_credentials()
    if missing:
        log.warning("Missing credentials (%s).", ", ".join(missing))
    yield


app = FastAPI(title="Findings Analysis Impact Dashboard", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
app.include_router(projects.router)
app.include_router(runs.router)


@app.exception_handler(500)
async def _server_error(request: Request, exc: Exception) -> HTMLResponse:
    # Exceptions from the cx package are already credential-scrubbed at
    # construction (cx/errors.py), so rendering the message here is safe.
    return templates.TemplateResponse(
        request, "error.html", {"message": str(exc)}, status_code=500
    )


@app.get("/healthz")
def healthz() -> dict:
    return {
        "ok": True,
        "missing_credentials": settings.missing_credentials(),
    }
