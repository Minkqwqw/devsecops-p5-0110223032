"""
Entry Point Aplikasi SecureTask API (src/app.py)
Menyediakan antarmuka layanan terpadu dan simulasi alur kerja aplikasi.
"""

from typing import Any, Dict

from src.auth_service import AuthService
from src.config import AppConfig
from src.database import DatabaseManager
from src.task_service import TaskService


class SecureTaskApp:
    """Fasad utama aplikasi yang mengintegrasikan Database, AuthService, dan TaskService."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.config = AppConfig()
        self.db = DatabaseManager(db_path)
        self.auth = AuthService(self.db)
        self.tasks = TaskService(self.db)

    def health_check(self) -> Dict[str, Any]:
        """Mengembalikan status kesehatan layanan aplikasi."""
        return {
            "app_name": self.config.APP_NAME,
            "environment": self.config.APP_ENV,
            "status": "healthy",
        }


def run_demo() -> None:
    """Menjalankan simulasi alur aplikasi dari registrasi hingga pengelolaan tugas."""
    app = SecureTaskApp()
    print(f"[*] Menjalankan {app.config.APP_NAME} ({app.config.APP_ENV})")

    user = app.auth.register_user("amir_aqwa", "amir@nurulfikri.ac.id", "StrongPass#2026")
    print(f"[+] Pengguna terdaftar: {user['username']} (ID: {user['id']})")

    session = app.auth.authenticate("amir_aqwa", "StrongPass#2026")
    if session:
        print(f"[+] Login berhasil, token sesi diterbitkan untuk {session['username']}")
        task = app.tasks.create_task(
            owner_id=session["user_id"],
            title="Implementasi Pipeline DevSecOps SAST",
            description="Mengintegrasikan GitHub Actions, Bandit, Semgrep, dan Quality Gate",
            priority="critical",
        )
        print(f"[+] Tugas dibuat: [{task['priority'].upper()}] {task['title']}")
        updated = app.tasks.update_task_status(
            task_id=task["id"],
            new_status="completed",
            requester_id=session["user_id"],
            requester_role=session["role"],
        )
        print(f"[+] Status tugas diperbarui menjadi: {updated['status']}")

    print(f"[*] Total log audit keamanan tercatat: {len(app.db.get_audit_logs())} entri")
    app.db.close()


if __name__ == "__main__":
    run_demo()
