# Findings Analysis Impact Dashboard

A web application for comparing SAST scan results with Findings Analysis
enabled. It reports finding counts, severity changes, attribution details, and
the potential reduction in triage effort.

## Features

- Compare a baseline scan with a Findings Analysis scan.
- Review changes by severity, query, and CWE.
- Show scan configuration parity and an audit trail.
- Rank projects by potential opportunity and migration risk.

## Requirements

- Python 3.11 or newer
- Checkmarx One credentials for live mode

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
```

Configure the environment values in `.env` for live mode. The application
uses a local SQLite database for run history and cached portfolio data.

## Run

```bash
.venv/bin/uvicorn app:app --reload --port 8060
```

Open <http://127.0.0.1:8060> in a browser.

## Technology

- **Python** - Main programming language.
- **FastAPI** - Provides the web application and API routes.
- **Uvicorn** - Runs the FastAPI application server.
- **Jinja2** - Renders the HTML pages.
- **HTTPX** - Sends requests to external APIs.
- **SQLite** - Stores run history and cached data.
- **Pytest** - Runs the automated tests.

## Tests

```bash
.venv/bin/python -m pytest
```
