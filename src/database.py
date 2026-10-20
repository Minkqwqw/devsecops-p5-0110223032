"""
Modul Lapisan Akses Data / Database Layer (src/database.py)
Mengelola skema tabel SQLite dan transaksi database menggunakan Parameterized Query.
"""

import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class DatabaseManager:
    """Manajer koneksi database SQLite dengan penerapan Parameterized Query (Anti-SQLi)."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        """Membuat tabel users, tasks, dan audit_logs jika belum tersedia."""
        cursor = self.connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                created_at TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                priority TEXT NOT NULL DEFAULT 'medium',
                status TEXT NOT NULL DEFAULT 'pending',
                owner_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users (id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        self.connection.commit()

    def log_audit_event(self, event_type: str, actor: str, details: str) -> None:
        """Mencatat aktivitas keamanan ke dalam tabel audit_logs."""
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor = self.connection.cursor()
        cursor.execute(
            "INSERT INTO audit_logs (event_type, actor, details, timestamp) VALUES (?, ?, ?, ?)",
            (event_type, actor, details, now_iso),
        )
        self.connection.commit()

    def get_audit_logs(self) -> List[Dict[str, Any]]:
        """Mengambil seluruh catatan audit keamanan."""
        cursor = self.connection.cursor()
        cursor.execute("SELECT id, event_type, actor, details, timestamp FROM audit_logs ORDER BY id DESC")
        return [dict(row) for row in cursor.fetchall()]

    def close(self) -> None:
        """Menutup koneksi database."""
        if self.connection:
            self.connection.close()
