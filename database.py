"""
database.py - SQLite Database Manager
======================================
CNS Concept: Persistent storage of URL analysis history
This module handles all database operations using SQLite.
SQLite is used here for simplicity — suitable for academic projects.

Security Note: All queries use parameterized statements to prevent SQL injection.
CNS Concept: SQL Injection Prevention via parameterized queries

Author: Phishing Detection System
Project: Computer and Network Security (CNS) College Project
"""

import sqlite3
import os
import json
from datetime import datetime

# Database file path
DB_PATH = os.path.join(os.path.dirname(__file__), "database", "phishing.db")


def get_connection():
    """
    Create and return a SQLite database connection.
    
    CNS Concept: Secure database access with row factory for
    dictionary-based result access.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Allows dict-like row access
    # Enable WAL mode for better concurrency
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_database():
    """
    Initialize the database — create tables if they don't exist.
    
    CNS Concept: Database schema design for security audit logging.
    Storing analysis history allows forensic review and pattern detection.
    """
    # Ensure database directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    conn = get_connection()
    cursor = conn.cursor()
    
    # ----------------------------------------------------------
    # URLHistory Table: Stores each URL analysis record
    # This forms the audit log of all analyzed URLs
    # ----------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS URLHistory (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT NOT NULL,
            risk_score  INTEGER NOT NULL,
            risk_level  TEXT NOT NULL,
            reasons     TEXT,           -- JSON array stored as text
            positives   TEXT,           -- JSON array stored as text
            analyzed_at TEXT NOT NULL   -- ISO format timestamp
        )
    """)
    
    # ----------------------------------------------------------
    # Statistics Table: Aggregated counters for dashboard
    # Maintained separately for efficient dashboard queries
    # ----------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Statistics (
            id          INTEGER PRIMARY KEY CHECK (id = 1),
            total       INTEGER DEFAULT 0,
            low_count   INTEGER DEFAULT 0,
            susp_count  INTEGER DEFAULT 0,
            high_count  INTEGER DEFAULT 0
        )
    """)
    
    # Insert default statistics row if not present
    cursor.execute("""
        INSERT OR IGNORE INTO Statistics (id, total, low_count, susp_count, high_count)
        VALUES (1, 0, 0, 0, 0)
    """)
    
    conn.commit()
    conn.close()
    print(f"[DB] Database initialized at: {DB_PATH}")


def save_analysis(url: str, risk_score: int, risk_level: str,
                  reasons: list, positives: list) -> int:
    """
    Save a URL analysis result to the database.
    
    CNS Concept: Audit logging — maintaining a record of all
    security analysis events for review and trend analysis.
    
    Security: Uses parameterized queries to prevent SQL injection.
    
    Args:
        url: The analyzed URL
        risk_score: Numeric risk score (0-100)
        risk_level: Categorical level (LOW/SUSPICIOUS/HIGH)
        reasons: List of suspicious findings
        positives: List of safe characteristics
        
    Returns:
        ID of the newly inserted record
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # CNS Security: Parameterized query prevents SQL injection attacks
    cursor.execute("""
        INSERT INTO URLHistory (url, risk_score, risk_level, reasons, positives, analyzed_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        url,
        risk_score,
        risk_level,
        json.dumps(reasons),    # Serialize list to JSON string
        json.dumps(positives),  # Serialize list to JSON string
        timestamp
    ))
    
    # Update statistics counters
    if risk_level == "LOW":
        cursor.execute("UPDATE Statistics SET total = total + 1, low_count = low_count + 1 WHERE id = 1")
    elif risk_level == "SUSPICIOUS":
        cursor.execute("UPDATE Statistics SET total = total + 1, susp_count = susp_count + 1 WHERE id = 1")
    elif risk_level == "HIGH":
        cursor.execute("UPDATE Statistics SET total = total + 1, high_count = high_count + 1 WHERE id = 1")
    
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return new_id


def get_history(limit: int = 50) -> list:
    """
    Retrieve recent URL analysis history.
    
    Args:
        limit: Maximum number of records to return (default 50)
        
    Returns:
        List of analysis records as dictionaries
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # CNS Security: Parameterized query for safe limit injection
    cursor.execute("""
        SELECT id, url, risk_score, risk_level, reasons, positives, analyzed_at
        FROM URLHistory
        ORDER BY analyzed_at DESC
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        record = dict(row)
        # Deserialize JSON strings back to lists
        try:
            record["reasons"] = json.loads(record["reasons"]) if record["reasons"] else []
        except (json.JSONDecodeError, TypeError):
            record["reasons"] = []
        try:
            record["positives"] = json.loads(record["positives"]) if record["positives"] else []
        except (json.JSONDecodeError, TypeError):
            record["positives"] = []
        results.append(record)
    
    return results


def clear_history() -> int:
    """
    Delete all URL analysis history records.
    
    Returns:
        Number of records deleted
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Get count before deletion
    cursor.execute("SELECT COUNT(*) FROM URLHistory")
    count = cursor.fetchone()[0]
    
    # Delete all history
    cursor.execute("DELETE FROM URLHistory")
    
    # Reset statistics
    cursor.execute("""
        UPDATE Statistics 
        SET total = 0, low_count = 0, susp_count = 0, high_count = 0
        WHERE id = 1
    """)
    
    conn.commit()
    conn.close()
    
    return count


def get_statistics() -> dict:
    """
    Retrieve dashboard statistics.
    
    Returns:
        Dictionary with analysis statistics
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM Statistics WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    
    if row:
        stats = dict(row)
        # Recompute from actual data for accuracy
        return {
            "total": stats.get("total", 0),
            "low": stats.get("low_count", 0),
            "suspicious": stats.get("susp_count", 0),
            "high": stats.get("high_count", 0),
        }
    
    return {"total": 0, "low": 0, "suspicious": 0, "high": 0}


def get_recent_for_dashboard(limit: int = 5) -> list:
    """
    Get recent analyses for dashboard display.
    
    Args:
        limit: Number of recent records
        
    Returns:
        Abbreviated list of recent analyses
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT url, risk_score, risk_level, analyzed_at
        FROM URLHistory
        ORDER BY analyzed_at DESC
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]
