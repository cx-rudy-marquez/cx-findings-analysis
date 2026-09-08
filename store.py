"""SQLite persistence for runs, their step log, and cached result sets.

Two reasons this exists rather than holding runs in memory:

1. The comparison view must not re-fetch thousands of findings from the tenant
   on every page load.
2. A live run creates real tenant resources. If the process dies mid-flow, the
   step log is the only record of what was already created - which project, and
   whether a scan is still running. Losing that means orphaned `_FA` projects
   nobody can account for.

Every write in `cx/client.py` is journalled here *before* it fires, so a crash
between the log line and the API call leaves evidence of an attempt rather than
silence.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from config import settings as default_settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id                 TEXT PRIMARY KEY,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    is_synthetic       INTEGER NOT NULL DEFAULT 0,
    status             TEXT NOT NULL,
    phase              TEXT,
    error              TEXT,
    source_project_id  TEXT,
    source_project_name TEXT,
    baseline_scan_id   TEXT,
    baseline_branch    TEXT,
    fa_project_id      TEXT,
    fa_project_name    TEXT,
    fa_scan_id         TEXT,
    minutes_per_finding INTEGER NOT NULL,
    baseline_counters  TEXT,
    compare_counters   TEXT,
    compare_results    TEXT,
    parity_report      TEXT,
    reonboard_status   TEXT,
    reonboard_plan     TEXT,
    reonboard_result   TEXT
);

CREATE TABLE IF NOT EXISTS run_steps (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id    TEXT NOT NULL REFERENCES runs(id),
    at        TEXT NOT NULL,
    step      TEXT NOT NULL,
    outcome   TEXT NOT NULL,
    detail    TEXT
);

CREATE INDEX IF NOT EXISTS idx_run_steps_run ON run_steps(run_id, id);

-- One row per bulk-analyze submission. `dropped_json` records projects that
-- failed live re-validation at confirm time and were never given a run - kept
-- here, not in `runs`, because they never got an id in that table.
-- No `status` column: aggregate progress is computed live from the batch's
-- child runs on every read (`Store.list_runs_for_batch`), which avoids N
-- concurrent background threads racing to write "am I the last one done" into
-- a single row.
CREATE TABLE IF NOT EXISTS run_batches (
    id            TEXT PRIMARY KEY,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    project_count INTEGER NOT NULL,
    dropped_json  TEXT
);

-- Portfolio snapshot. One row, replaced wholesale on refresh: this is a cache
-- of an expensive read, not a history worth keeping.
CREATE TABLE IF NOT EXISTS portfolio_snapshot (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    built_at  TEXT NOT NULL,
    rows_json TEXT NOT NULL
);

-- Scoring weights and risk thresholds, absent until someone saves them.
-- Absence means "use the config defaults", which makes Reset a delete rather
-- than a second copy of the defaults that could drift from them.
CREATE TABLE IF NOT EXISTS portfolio_settings (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    updated_at    TEXT NOT NULL,
    settings_json TEXT NOT NULL
);
"""

#: Run lifecycle. `pending` exists so the confirmation modal can create a row
#: the user can still abandon before anything is created in the tenant.
PENDING = "pending"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
CANCELED = "canceled"

TERMINAL_RUN_STATUSES = frozenset({COMPLETED, FAILED, CANCELED})

#: Run columns holding JSON. `baseline_counters` is the baseline scan's own
#: `sastCounters` (used for the NEW-state share); the other two are the compare
#: endpoints' payloads.
#: `parity_report` is the SAST-configuration diff between the base project and
#: the _FA copy, written once per run by `cx/flow.py`. `reonboard_plan` is the
#: dry-run preview an operator confirmed, and `reonboard_result` is what the two
#: SCM calls actually did - both written by `cx/reonboard.py`.
JSON_COLUMNS = frozenset(
    {
        "baseline_counters",
        "compare_counters",
        "compare_results",
        "parity_report",
        "reonboard_plan",
        "reonboard_result",
    }
)

_write_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, settings=None) -> None:
        self.settings = settings or default_settings
        self.path = self.settings.db_file
        self._init_schema()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)
            conn.commit()

    @staticmethod
    def _migrate(conn) -> None:
        """Add columns the DDL gained after a database was first created.

        `CREATE TABLE IF NOT EXISTS` is a no-op against an existing file, so a
        database written before the compare API was adopted keeps its old
        columns and every insert naming a new one fails. Runs recorded then are
        left in place: they render as an empty comparison rather than
        disappearing or crashing the page.
        """
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(runs)")}
        for column in (
            "baseline_counters",
            "compare_counters",
            "compare_results",
            "parity_report",
            "reonboard_status",
            "reonboard_plan",
            "reonboard_result",
            "batch_id",
        ):
            if column not in existing:
                conn.execute(f"ALTER TABLE runs ADD COLUMN {column} TEXT")

    # -- runs -----------------------------------------------------------------

    def create_run(
        self,
        *,
        source_project_id: str,
        source_project_name: str,
        baseline_scan_id: str | None,
        baseline_branch: str | None,
        minutes_per_finding: int,
        is_synthetic: bool = False,
        status: str = PENDING,
        batch_id: str | None = None,
    ) -> str:
        run_id = uuid.uuid4().hex
        now = _now()
        with _write_lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO runs (
                    id, created_at, updated_at, is_synthetic, status, phase,
                    source_project_id, source_project_name, baseline_scan_id,
                    baseline_branch, minutes_per_finding, batch_id
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    run_id, now, now, int(is_synthetic), status, "created",
                    source_project_id, source_project_name, baseline_scan_id,
                    baseline_branch, minutes_per_finding, batch_id,
                ),
            )
            conn.commit()
        return run_id

    def update_run(self, run_id: str, **fields) -> None:
        if not fields:
            return
        json_columns = JSON_COLUMNS
        columns, values = [], []
        for key, value in fields.items():
            columns.append(f"{key} = ?")
            values.append(json.dumps(value) if key in json_columns else value)
        columns.append("updated_at = ?")
        values.append(_now())
        values.append(run_id)
        with _write_lock, self._connect() as conn:
            conn.execute(f"UPDATE runs SET {', '.join(columns)} WHERE id = ?", values)
            conn.commit()

    def get_run(self, run_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return _decode_run(row) if row else None

    def list_runs(self, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_decode_run(row) for row in rows]

    def find_active_run_for_project(self, project_id: str) -> dict | None:
        """An in-flight run for this project, if one exists.

        Guards the confirmation modal against a double submit creating a second
        `_FA` project and a second scan for the same source.
        """
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM runs
                 WHERE source_project_id = ? AND status IN (?, ?)
                 ORDER BY created_at DESC LIMIT 1
                """,
                (project_id, PENDING, RUNNING),
            ).fetchone()
        return _decode_run(row) if row else None

    def find_latest_run_for_project(self, project_id: str) -> dict | None:
        """The run to show instead of offering a fresh one.

        A completed run first, whatever its date - it is the one that has a
        comparison to read. Only if none completed does the most recent attempt
        of any status stand in, so a project whose every run failed still leads
        somewhere that says why.

        Deliberately not `find_active_run_for_project`: that one answers "is
        something in flight right now" and must keep ignoring finished runs.
        """
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM runs
                 WHERE source_project_id = ?
                 ORDER BY (status = ?) DESC, created_at DESC
                 LIMIT 1
                """,
                (project_id, COMPLETED),
            ).fetchone()
        return _decode_run(row) if row else None

    # -- run batches ------------------------------------------------------------

    def create_batch(self, project_count: int, dropped: list[dict]) -> str:
        """A bulk-analyze submission. `dropped` is written once and never changed."""
        batch_id = uuid.uuid4().hex
        now = _now()
        with _write_lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO run_batches (id, created_at, updated_at, "
                "project_count, dropped_json) VALUES (?,?,?,?,?)",
                (batch_id, now, now, project_count, json.dumps(dropped)),
            )
            conn.commit()
        return batch_id

    def get_batch(self, batch_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM run_batches WHERE id = ?", (batch_id,)
            ).fetchone()
        return _decode_batch(row) if row else None

    def list_runs_for_batch(self, batch_id: str) -> list[dict]:
        """A batch's runs, oldest first - a progress list reads top to bottom."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM runs WHERE batch_id = ? ORDER BY created_at ASC",
                (batch_id,),
            ).fetchall()
        return [_decode_run(row) for row in rows]

    # -- portfolio ------------------------------------------------------------

    def save_snapshot(self, rows: list[dict]) -> str:
        built_at = _now()
        with _write_lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO portfolio_snapshot (id, built_at, rows_json) "
                "VALUES (1,?,?) "
                "ON CONFLICT(id) DO UPDATE SET built_at=excluded.built_at, "
                "rows_json=excluded.rows_json",
                (built_at, json.dumps(rows)),
            )
            conn.commit()
        return built_at

    def get_snapshot(self) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT built_at, rows_json FROM portfolio_snapshot WHERE id = 1"
            ).fetchone()
        if not row:
            return None
        return {"built_at": row["built_at"], "rows": json.loads(row["rows_json"])}

    def save_portfolio_settings(self, values: dict) -> None:
        with _write_lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO portfolio_settings (id, updated_at, settings_json) "
                "VALUES (1,?,?) "
                "ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at, "
                "settings_json=excluded.settings_json",
                (_now(), json.dumps(values)),
            )
            conn.commit()

    def get_portfolio_settings(self) -> dict | None:
        """Saved overrides, or None when the config defaults are in force."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT settings_json FROM portfolio_settings WHERE id = 1"
            ).fetchone()
        return json.loads(row["settings_json"]) if row else None

    def clear_portfolio_settings(self) -> None:
        with _write_lock, self._connect() as conn:
            conn.execute("DELETE FROM portfolio_settings WHERE id = 1")
            conn.commit()

    # -- step log -------------------------------------------------------------

    def log_step(self, run_id: str, step: str, outcome: str, detail: str = "") -> None:
        with _write_lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO run_steps (run_id, at, step, outcome, detail) "
                "VALUES (?,?,?,?,?)",
                (run_id, _now(), step, outcome, detail[:2000]),
            )
            conn.commit()

    def get_steps(self, run_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT at, step, outcome, detail FROM run_steps "
                "WHERE run_id = ? ORDER BY id",
                (run_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_step_timestamps(self, run_id: str) -> dict[str, str]:
        """Earliest timestamp per step name for one run.

        Lets a caller answer "when did this project start downloading its
        archive / start its scan" directly from the journal already written by
        every step, rather than a new column per phase or inferring it from
        polling snapshots (GOAL_FIX_BULK_ANALYSIS.md FIX 4).
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT step, MIN(at) AS at FROM run_steps "
                "WHERE run_id = ? GROUP BY step",
                (run_id,),
            ).fetchall()
        return {row["step"]: row["at"] for row in rows}


def _decode_run(row: sqlite3.Row) -> dict:
    run = dict(row)
    run["is_synthetic"] = bool(run.get("is_synthetic"))
    for column in JSON_COLUMNS:
        raw = run.get(column)
        run[column] = json.loads(raw) if raw else None
    return run


def _decode_batch(row: sqlite3.Row) -> dict:
    batch = dict(row)
    batch["dropped"] = json.loads(batch.pop("dropped_json") or "[]")
    return batch
