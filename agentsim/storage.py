"""SQLite-backed campaign run, action, and lifecycle history."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Mapping


class RunStore:
    """Persist immutable manifests and append-only action/event evidence."""

    def __init__(self, path: str | Path = "agent_sim_runs.db") -> None:
        self.path = Path(path)
        if not self.path.parent.exists():
            raise FileNotFoundError(f"run database directory does not exist: {self.path.parent}")
        self.initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            with connection:
                yield connection
        finally:
            connection.close()

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
                CREATE TABLE IF NOT EXISTS detection_evaluations (
                    run_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    ability_id TEXT,
                    matched INTEGER NOT NULL,
                    evaluation_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, rule_id, ability_id),
                    FOREIGN KEY (run_id) REFERENCES runs(run_id)
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    run_id TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    path TEXT NOT NULL,
                    sha256 TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY (run_id, artifact_type),
                    FOREIGN KEY (run_id) REFERENCES runs(run_id)
                );
                CREATE TABLE IF NOT EXISTS telemetry_queries (
                    query_id TEXT PRIMARY KEY,
                    run_id TEXT,
                    connector TEXT NOT NULL,
                    dataset TEXT NOT NULL,
                    target TEXT NOT NULL,
                    since TEXT NOT NULL,
                    until TEXT NOT NULL,
                    status TEXT NOT NULL,
                    query_sha256 TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    audit_json TEXT NOT NULL
                );
                """
            )
            query_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(telemetry_queries)").fetchall()
            }
            if "run_id" not in query_columns:
                connection.execute("ALTER TABLE telemetry_queries ADD COLUMN run_id TEXT")

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

    def append_detection(
        self,
        run_id: str,
        *,
        rule_id: str,
        ability_id: str | None,
        matched: bool,
        evaluation: Mapping[str, object],
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO detection_evaluations
                    (run_id, rule_id, ability_id, matched, evaluation_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (run_id, rule_id, ability_id or "", int(matched), json.dumps(evaluation, sort_keys=True)),
            )

    def record_artifact(
        self,
        run_id: str,
        *,
        artifact_type: str,
        path: str,
        sha256: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO artifacts
                    (run_id, artifact_type, path, sha256, metadata_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (run_id, artifact_type, path, sha256, json.dumps(metadata or {}, sort_keys=True)),
            )

    def record_telemetry_query(
        self, query_id: str, audit: Mapping[str, object], *, run_id: str | None = None
    ) -> None:
        """Persist only redacted query metadata; credentials and headers are rejected."""

        serialized = json.dumps(audit, sort_keys=True)
        lowered = serialized.casefold()
        if '"authorization"' in lowered or '"credential_value"' in lowered:
            raise ValueError("telemetry query audit may not contain credentials or authorization headers")
        query = audit.get("query")
        if not isinstance(query, Mapping):
            raise ValueError("telemetry query audit is missing query metadata")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO telemetry_queries (
                    query_id, run_id, connector, dataset, target, since, until,
                    status, query_sha256, event_count, audit_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    query_id,
                    run_id,
                    query["connector"],
                    query["dataset"],
                    query["target"],
                    query["since"],
                    query["until"],
                    audit.get("status", "unknown"),
                    query["query_sha256"],
                    int(audit.get("record_count", 0)),
                    serialized,
                ),
            )

    def telemetry_query_history(self, limit: int = 25) -> list[dict[str, object]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("telemetry query history limit must be between 1 and 500")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT query_id, run_id, audit_json FROM telemetry_queries ORDER BY rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "query_id": row["query_id"],
                "campaign_run_id": row["run_id"],
                **json.loads(row["audit_json"]),
            }
            for row in rows
        ]

    def ability_ids_for_run(self, run_id: str) -> tuple[str, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT DISTINCT ability_id FROM actions WHERE run_id = ? ORDER BY ability_id",
                (run_id,),
            ).fetchall()
        if not rows:
            raise ValueError(f"unknown campaign run or run has no actions: {run_id}")
        return tuple(str(row["ability_id"]) for row in rows)

    def apply_detection_outcomes(
        self, run_id: str, outcomes: list[Mapping[str, object]]
    ) -> None:
        """Update only detection counters after a separately audited telemetry query."""

        with self._connect() as connection:
            row = connection.execute(
                "SELECT summary_json FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise ValueError(f"unknown campaign run: {run_id}")
            summary = json.loads(row["summary_json"])
            stored = connection.execute(
                "SELECT evaluation_json FROM detection_evaluations WHERE run_id = ?",
                (run_id,),
            ).fetchall()
            merged = [json.loads(item["evaluation_json"]) for item in stored] or outcomes
            detected = sum(item.get("status") == "detected" for item in merged)
            missed = sum(item.get("status") == "missed" for item in merged)
            evaluated = len(merged)
            planned = int(summary.get("planned_actions", len(outcomes)))
            summary["detections"] = detected
            summary["misses"] = missed
            summary["visibility_gaps"] = sum(
                item.get("status") == "visibility_gap" for item in merged
            )
            summary["pending_detection_results"] = max(0, planned - evaluated)
            connection.execute(
                "UPDATE runs SET summary_json = ? WHERE run_id = ?",
                (json.dumps(summary, sort_keys=True), run_id),
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

    def artifacts_for_run(self, run_id: str) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT artifact_type, path, sha256, metadata_json FROM artifacts WHERE run_id = ? ORDER BY artifact_type",
                (run_id,),
            ).fetchall()
        return [
            {
                "artifact_type": row["artifact_type"],
                "path": row["path"],
                "sha256": row["sha256"],
                "metadata": json.loads(row["metadata_json"]),
            }
            for row in rows
        ]
