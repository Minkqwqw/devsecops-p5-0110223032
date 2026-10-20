"""
Modul Layanan Manajemen Tugas (src/task_service.py)
Mengelola operasi CRUD tugas dengan validasi kepemilikan (Anti-IDOR / Broken Access Control).
"""

from datetime import datetime, timezone
from typing import Any, Dict, List

from src.database import DatabaseManager
from src.security import sanitize_text


class TaskService:
    """Layanan pengelolaan tugas dengan kontrol akses berbasis kepemilikan dan role."""

    ALLOWED_PRIORITIES = {"low", "medium", "high", "critical"}
    ALLOWED_STATUSES = {"pending", "in_progress", "completed"}

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def create_task(
        self, owner_id: int, title: str, description: str, priority: str = "medium"
    ) -> Dict[str, Any]:
        """Membuat tugas baru setelah memvalidasi dan membersihkan input."""
        clean_title = sanitize_text(title, max_length=120)
        clean_desc = sanitize_text(description, max_length=500)
        if not clean_title:
            raise ValueError("Judul tugas tidak boleh kosong.")

        if priority not in self.ALLOWED_PRIORITIES:
            raise ValueError(f"Prioritas tidak valid: {priority}")

        now_iso = datetime.now(timezone.utc).isoformat()
        cursor = self.db.connection.cursor()
        cursor.execute(
            """
            INSERT INTO tasks (title, description, priority, status, owner_id, created_at)
            VALUES (?, ?, ?, 'pending', ?, ?)
            """,
            (clean_title, clean_desc, priority, owner_id, now_iso),
        )
        self.db.connection.commit()
        task_id = cursor.lastrowid
        self.db.log_audit_event("TASK_CREATED", f"user:{owner_id}", f"Task ID {task_id}: {clean_title}")

        return {
            "id": task_id,
            "title": clean_title,
            "description": clean_desc,
            "priority": priority,
            "status": "pending",
            "owner_id": owner_id,
            "created_at": now_iso,
        }

    def list_tasks_for_user(self, user_id: int, role: str = "member") -> List[Dict[str, Any]]:
        """Mengambil daftar tugas sesuai hak akses (admin dapat melihat semua, member hanya miliknya)."""
        cursor = self.db.connection.cursor()
        if role == "admin":
            cursor.execute("SELECT * FROM tasks ORDER BY id DESC")
        else:
            cursor.execute("SELECT * FROM tasks WHERE owner_id = ? ORDER BY id DESC", (user_id,))
        return [dict(row) for row in cursor.fetchall()]

    def update_task_status(
        self, task_id: int, new_status: str, requester_id: int, requester_role: str = "member"
    ) -> Dict[str, Any]:
        """Memperbarui status tugas dengan pencegahan Broken Access Control (IDOR)."""
        if new_status not in self.ALLOWED_STATUSES:
            raise ValueError(f"Status tidak valid: {new_status}")

        cursor = self.db.connection.cursor()
        cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
        row = cursor.fetchone()
        if not row:
            raise LookupError("Tugas tidak ditemukan.")

        if row["owner_id"] != requester_id and requester_role != "admin":
            self.db.log_audit_event(
                "UNAUTHORIZED_ACCESS",
                f"user:{requester_id}",
                f"Attempted to modify task {task_id} owned by user:{row['owner_id']}",
            )
            raise PermissionError("Akses ditolak: Anda bukan pemilik tugas ini.")

        cursor.execute(
            "UPDATE tasks SET status = ? WHERE id = ?",
            (new_status, task_id),
        )
        self.db.connection.commit()
        self.db.log_audit_event(
            "TASK_UPDATED", f"user:{requester_id}", f"Task {task_id} status -> {new_status}"
        )

        updated = dict(row)
        updated["status"] = new_status
        return updated
