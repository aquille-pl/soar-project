import json
import sqlite3
from datetime import datetime, timedelta, timezone

DB_PATH = "incidents.db"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                ip TEXT NOT NULL,
                backend TEXT,
                rule TEXT,
                blocked_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                ended_at TEXT
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
                _now().isoformat(),
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
    result = []
    for row in rows:
        item = dict(row)
        for key in ("reputation", "decision", "action_result"):
            item[key] = json.loads(item[key]) if item[key] else None
        result.append(item)
    return result


def record_block(incident_id, ip, backend, rule, ttl_minutes: int) -> int:
    now = _now()
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            """
            INSERT INTO blocks (incident_id, ip, backend, rule, blocked_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                ip,
                backend,
                rule,
                now.isoformat(),
                (now + timedelta(minutes=ttl_minutes)).isoformat(),
            ),
        )
        return cur.lastrowid


def due_blocks() -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM blocks WHERE status = 'active' AND expires_at <= ?",
            (_now().isoformat(),),
        ).fetchall()
    return [dict(r) for r in rows]


def mark_block(block_id: int, status: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE blocks SET status = ?, ended_at = ? WHERE id = ?",
            (status, _now().isoformat(), block_id),
        )


def end_blocks_for_ip(ip: str, status: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE blocks SET status = ?, ended_at = ? WHERE ip = ? AND status = 'active'",
            (status, _now().isoformat(), ip),
        )


def list_blocks(limit: int = 50) -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM blocks ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]