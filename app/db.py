import json
import sqlite3
from datetime import datetime, timezone

DB_PATH = "incidents.db"


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT,
                reputation TEXT,
                decision TEXT,
                action_result TEXT
            )
            """
        )


def save_incident(incident, reputation: dict, decision: dict, action_result) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            """
            INSERT INTO incidents
            (received_at, source_ip, alert_type, severity, reputation, decision, action_result)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                str(incident.source_ip),
                incident.alert_type,
                incident.severity,
                json.dumps(reputation),
                json.dumps(decision),
                json.dumps(action_result),
            ),
        )
        return cur.lastrowid


def list_incidents(limit: int = 50) -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]