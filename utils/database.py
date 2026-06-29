# =============================================================================
# Password Guardian Pro — utils/database.py
# =============================================================================
# SQLite persistence layer for password analysis history and statistics.
#
# Security principles applied:
#   - Raw passwords are NEVER stored — only SHA-256 hashes.
#   - All queries use parameterised statements (no string interpolation).
#   - Database file lives outside the Flask app root (database/ directory).
#   - WAL journal mode enabled for better concurrent read performance.
# =============================================================================

import sqlite3
import os
import logging
from datetime import datetime, timezone
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Path configuration
# ---------------------------------------------------------------------------

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH   = os.path.join(_BASE_DIR, "database", "guardian.db")

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
-- Analysis history: one row per password checked
CREATE TABLE IF NOT EXISTS analyses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT    NOT NULL,           -- ISO-8601 UTC timestamp
    hash        TEXT    NOT NULL,           -- SHA-256 of the password
    score       INTEGER NOT NULL,           -- 0-100 blended score
    strength    TEXT    NOT NULL,           -- Very Weak / Weak / Fair / Strong / Very Strong
    entropy     REAL    NOT NULL,           -- True entropy in bits
    grade       TEXT    NOT NULL,           -- F / D / C / B / A / A+
    length      INTEGER NOT NULL,           -- Password length
    breached    INTEGER NOT NULL DEFAULT 0  -- 1 if found in common passwords list
);

-- Session-level aggregates (updated on each analysis)
CREATE TABLE IF NOT EXISTS stats (
    id              INTEGER PRIMARY KEY CHECK (id = 1),  -- Singleton row
    total_checked   INTEGER NOT NULL DEFAULT 0,
    total_score_sum INTEGER NOT NULL DEFAULT 0,
    strong_count    INTEGER NOT NULL DEFAULT 0,          -- score >= 80
    weak_count      INTEGER NOT NULL DEFAULT 0,          -- score <  40
    last_updated    TEXT    NOT NULL DEFAULT ''
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_score   ON analyses(score);
CREATE INDEX IF NOT EXISTS idx_analyses_hash    ON analyses(hash);
"""

# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def init_db() -> None:
    """
    Initialise the SQLite database: create directory, apply schema, seed stats row.

    Safe to call multiple times — uses CREATE TABLE IF NOT EXISTS throughout.
    Called once at Flask app startup.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    with _get_connection() as conn:
        conn.executescript(_SCHEMA)

        # Ensure the singleton stats row exists
        conn.execute("""
            INSERT OR IGNORE INTO stats (id, total_checked, total_score_sum,
                                         strong_count, weak_count, last_updated)
            VALUES (1, 0, 0, 0, 0, '')
        """)
        conn.commit()

    logger.info("Database initialised at %s", DB_PATH)


# ---------------------------------------------------------------------------
# Write operations
# ---------------------------------------------------------------------------

def save_analysis(report: dict) -> int:
    """
    Persist a password analysis report to the database.

    Only safe, non-sensitive fields are stored. The raw password is never
    passed to this function — the caller provides the SHA-256 hash.

    Args:
        report (dict): The analysis report from checker.analyze_password().
                       Expected keys: hash, score, strength, entropy,
                                      grade, length, breached.

    Returns:
        int: Row ID of the newly inserted record.

    Raises:
        KeyError:    If a required field is missing from report.
        sqlite3.Error: On database write failure.
    """
    required = {"hash", "score", "strength", "entropy", "grade", "length", "breached"}
    missing  = required - report.keys()
    if missing:
        raise KeyError(f"Missing required fields in report: {missing}")

    now = _utc_now()

    with _get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO analyses (created_at, hash, score, strength,
                                   entropy, grade, length, breached)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                report["hash"],
                int(report["score"]),
                report["strength"],
                float(report["entropy"]),
                report["grade"],
                int(report["length"]),
                1 if report["breached"] else 0,
            )
        )
        row_id = cursor.lastrowid

        # Update singleton stats row atomically
        conn.execute(
            """
            UPDATE stats SET
                total_checked   = total_checked + 1,
                total_score_sum = total_score_sum + ?,
                strong_count    = strong_count + ?,
                weak_count      = weak_count + ?,
                last_updated    = ?
            WHERE id = 1
            """,
            (
                int(report["score"]),
                1 if report["score"] >= 80 else 0,
                1 if report["score"] <  40 else 0,
                now,
            )
        )
        conn.commit()

    logger.debug("Saved analysis id=%d score=%d strength=%s",
                 row_id, report["score"], report["strength"])
    return row_id


# ---------------------------------------------------------------------------
# Read operations
# ---------------------------------------------------------------------------

def get_history(limit: int = 20, offset: int = 0) -> list[dict]:
    """
    Retrieve paginated analysis history, newest first.

    Args:
        limit  (int): Maximum number of records to return. Clamped to [1, 100].
        offset (int): Number of records to skip (for pagination).

    Returns:
        list[dict]: List of analysis records. Each dict contains:
            id, created_at, hash (truncated), score, strength,
            entropy, grade, length, breached.
    """
    limit  = max(1, min(100, limit))
    offset = max(0, offset)

    with _get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, created_at,
                   substr(hash, 1, 16) || '...' AS hash,  -- Truncate for display
                   score, strength, entropy, grade, length, breached
            FROM   analyses
            ORDER  BY created_at DESC
            LIMIT  ? OFFSET ?
            """,
            (limit, offset)
        ).fetchall()

    return [_row_to_dict(row) for row in rows]


def get_stats() -> dict:
    """
    Retrieve aggregated statistics from the singleton stats row.

    Computes derived metrics (average score, strong/weak percentages) inline.

    Returns:
        dict: {
            total_checked:    int,
            average_score:    float,
            strong_count:     int,
            weak_count:       int,
            fair_count:       int,
            strong_percent:   float,
            weak_percent:     float,
            last_updated:     str,
            score_distribution: dict,
            strength_breakdown: dict,
        }
    """
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM stats WHERE id = 1"
        ).fetchone()

        # Strength breakdown from analyses table
        breakdown_rows = conn.execute(
            """
            SELECT strength, COUNT(*) AS cnt
            FROM   analyses
            GROUP  BY strength
            """
        ).fetchall()

        # Score distribution in bands of 20
        dist_rows = conn.execute(
            """
            SELECT
                CASE
                    WHEN score < 20 THEN '0-19'
                    WHEN score < 40 THEN '20-39'
                    WHEN score < 60 THEN '40-59'
                    WHEN score < 80 THEN '60-79'
                    ELSE                 '80-100'
                END AS band,
                COUNT(*) AS cnt
            FROM analyses
            GROUP BY band
            ORDER BY band
            """
        ).fetchall()

    if not row:
        return _empty_stats()

    total     = row["total_checked"]
    score_sum = row["total_score_sum"]
    strong    = row["strong_count"]
    weak      = row["weak_count"]
    fair      = max(0, total - strong - weak)

    avg_score      = round(score_sum / total, 1) if total > 0 else 0.0
    strong_percent = round((strong / total) * 100, 1) if total > 0 else 0.0
    weak_percent   = round((weak   / total) * 100, 1) if total > 0 else 0.0

    strength_breakdown = {r["strength"]: r["cnt"] for r in breakdown_rows}
    score_distribution = {r["band"]: r["cnt"]     for r in dist_rows}

    return {
        "total_checked":      total,
        "average_score":      avg_score,
        "strong_count":       strong,
        "weak_count":         weak,
        "fair_count":         fair,
        "strong_percent":     strong_percent,
        "weak_percent":       weak_percent,
        "last_updated":       row["last_updated"],
        "strength_breakdown": strength_breakdown,
        "score_distribution": score_distribution,
    }


def get_total_count() -> int:
    """
    Return the total number of analyses stored.

    Returns:
        int: Row count in the analyses table.
    """
    with _get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM analyses").fetchone()
    return row["cnt"] if row else 0


def clear_history() -> int:
    """
    Delete all analysis records and reset the stats counters.

    Returns:
        int: Number of rows deleted.
    """
    with _get_connection() as conn:
        deleted = conn.execute("DELETE FROM analyses").rowcount
        conn.execute("""
            UPDATE stats SET
                total_checked   = 0,
                total_score_sum = 0,
                strong_count    = 0,
                weak_count      = 0,
                last_updated    = ?
            WHERE id = 1
        """, (_utc_now(),))
        conn.commit()

    logger.info("Cleared %d analysis records.", deleted)
    return deleted


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------

@contextmanager
def _get_connection():
    """
    Context manager that yields a configured SQLite connection.

    Configuration applied:
        - row_factory = sqlite3.Row  (dict-like row access)
        - WAL journal mode           (better concurrent reads)
        - foreign_keys = ON
        - timeout = 10s              (avoids indefinite lock waits)

    Yields:
        sqlite3.Connection
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
    except sqlite3.Error as exc:
        conn.rollback()
        logger.error("Database error: %s", exc)
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row_to_dict(row: sqlite3.Row) -> dict:
    """
    Convert a sqlite3.Row to a plain Python dict.

    Args:
        row (sqlite3.Row): Database row.

    Returns:
        dict: Plain dictionary with all column values.
    """
    return dict(row)


def _utc_now() -> str:
    """
    Return the current UTC time as an ISO-8601 string.

    Returns:
        str: e.g. "2024-11-15T14:32:07.123456+00:00"
    """
    return datetime.now(timezone.utc).isoformat()


def _empty_stats() -> dict:
    """
    Return a zero-value stats dictionary when no data exists.

    Returns:
        dict: Stats dict with all numeric fields set to 0.
    """
    return {
        "total_checked":      0,
        "average_score":      0.0,
        "strong_count":       0,
        "weak_count":         0,
        "fair_count":         0,
        "strong_percent":     0.0,
        "weak_percent":       0.0,
        "last_updated":       "",
        "strength_breakdown": {},
        "score_distribution": {},
    }
