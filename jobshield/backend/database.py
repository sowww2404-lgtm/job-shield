# database.py
# Simple SQLite storage for saved checks. No external DB server needed.

import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "jobshield.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            source TEXT NOT NULL,          -- 'job', 'course', or 'link'
            input_snippet TEXT NOT NULL,   -- short preview of what was checked
            score INTEGER NOT NULL,
            level TEXT NOT NULL,           -- 'Low', 'Medium', 'High'
            flags_json TEXT NOT NULL       -- JSON list of {label, why, weight}
        )
        """
    )
    conn.commit()
    conn.close()


def save_check(source, input_snippet, score, level, flags):
    conn = get_connection()
    conn.execute(
        "INSERT INTO checks (created_at, source, input_snippet, score, level, flags_json) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            datetime.utcnow().isoformat(),
            source,
            input_snippet[:200],
            score,
            level,
            json.dumps(flags),
        ),
    )
    conn.commit()
    check_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    conn.close()
    return check_id


def get_history(limit=50):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM checks ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        result.append(
            {
                "id": r["id"],
                "created_at": r["created_at"],
                "source": r["source"],
                "input_snippet": r["input_snippet"],
                "score": r["score"],
                "level": r["level"],
                "flags": json.loads(r["flags_json"]),
            }
        )
    return result


def get_check(check_id):
    conn = get_connection()
    r = conn.execute("SELECT * FROM checks WHERE id = ?", (check_id,)).fetchone()
    conn.close()
    if not r:
        return None
    return {
        "id": r["id"],
        "created_at": r["created_at"],
        "source": r["source"],
        "input_snippet": r["input_snippet"],
        "score": r["score"],
        "level": r["level"],
        "flags": json.loads(r["flags_json"]),
    }


def get_dashboard_stats():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) AS c FROM checks").fetchone()["c"]
    high = conn.execute("SELECT COUNT(*) AS c FROM checks WHERE level = 'High'").fetchone()["c"]
    medium = conn.execute("SELECT COUNT(*) AS c FROM checks WHERE level = 'Medium'").fetchone()["c"]
    low = conn.execute("SELECT COUNT(*) AS c FROM checks WHERE level = 'Low'").fetchone()["c"]
    recent = conn.execute(
        "SELECT score, created_at FROM checks ORDER BY id DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
        "trend": [{"score": r["score"], "created_at": r["created_at"]} for r in reversed(recent)],
    }
