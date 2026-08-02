"""SQLite-backed campaign run, action, and lifecycle history."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Mapping


class RunStore:
    """Persist immutable manifests and append-only action/event evidence."""

    def __init__(self, path: str | Path = "agent_sim_runs.db") -> None:
        self.path = Path(path)
        if not self.path.parent.exists():
            raise FileNotFoundError(f"run database directory does not exist: {self.path.parent}")
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    target_uri TEXT NOT NULL,
                    authorization_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    status TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    summary_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS actions (
                    run_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    ability_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, action_id),
                    FOREIGN KEY (run_id) REFERENCES runs(run_id)
                );
                CREATE TABLE IF NOT EXISTS lifecycle_events (
                    run_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    lifecycle_state TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, sequence),
                    UNIQUE (event_id),
                    FOREIGN KEY (run_id) REFERENCES runs(run_id)
                );
                """
            )

    def create_run(self, manifest: Mapping[str, object], manifest_sha256: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO runs (
                    run_id, campaign_id, mode, provider, target_uri,
                    authorization_id, started_at, status, manifest_sha256, manifest_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?, ?)
                """,
                (
                    manifest["run_id"],
                    manifest["campaign_id"],
                    manifest["mode"],
                    manifest["provider"],
                    manifest["target_uri"],
                    manifest["authorization_id"],
                    manifest["started_at"],
                    manifest_sha256,
                    json.dumps(manifest, sort_keys=True),
                ),
            )

    def append_event(self, event: Mapping[str, object]) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO lifecycle_events (
                    run_id, sequence, event_id, lifecycle_state, event_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    event["run_id"],
                    event["sequence"],
                    event["event_id"],
                    event["lifecycle_state"],
                    json.dumps(event, sort_keys=True),
                ),
            )

    def append_action(self, run_id: str, result: Mapping[str, object]) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO actions (run_id, action_id, ability_id, status, result_json) VALUES (?, ?, ?, ?, ?)",
                (
                    run_id,
                    result["action_id"],
                    result["ability_id"],
                    result["status"],
                    json.dumps(result, sort_keys=True),
                ),
            )

    def finish_run(
        self,
        run_id: str,
        *,
        finished_at: str,
        status: str,
        summary: Mapping[str, object],
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE runs SET finished_at = ?, status = ?, summary_json = ? WHERE run_id = ?",
                (finished_at, status, json.dumps(summary, sort_keys=True), run_id),
            )

    def history(self, limit: int = 25) -> list[dict[str, object]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("history limit must be between 1 and 500")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT run_id, campaign_id, mode, provider, target_uri,
                       authorization_id, started_at, finished_at, status,
                       manifest_sha256, summary_json
                FROM runs ORDER BY started_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                **{key: row[key] for key in row.keys() if key != "summary_json"},
                "summary": json.loads(row["summary_json"]),
            }
            for row in rows
        ]

    def events_for_run(self, run_id: str) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event_json FROM lifecycle_events WHERE run_id = ? ORDER BY sequence",
                (run_id,),
            ).fetchall()
        return [json.loads(row["event_json"]) for row in rows]
