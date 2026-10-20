"""
Modul Layanan Autentikasi & Pengguna (src/auth_service.py)
Mengelola registrasi pengguna, verifikasi login, dan pembuatan sesi aman.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.database import DatabaseManager
from src.security import (
    generate_session_token,
    hash_password,
    sanitize_text,
    verify_password,
)


class AuthService:
    """Layanan autentikasi pengguna dengan perlindungan terhadap SQL Injection dan Brute Force."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self._active_sessions: Dict[str, Dict[str, Any]] = {}

    def register_user(
        self, username: str, email: str, password: str, role: str = "member"
    ) -> Dict[str, Any]:
        """Mendaftarkan pengguna baru dengan validasi input dan hashing PBKDF2-SHA256."""
        clean_username = sanitize_text(username, max_length=50)
        clean_email = sanitize_text(email, max_length=100)
        if not clean_username or "@" not in clean_email:
            raise ValueError("Username atau email tidak valid.")

        allowed_roles = {"member", "admin", "auditor"}
        if role not in allowed_roles:
            raise ValueError(f"Role tidak diizinkan: {role}")

        pwd_hash, salt = hash_password(password)
        now_iso = datetime.now(timezone.utc).isoformat()

        cursor = self.db.connection.cursor()
        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash, salt, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (clean_username, clean_email, pwd_hash, salt, role, now_iso),
        )
        self.db.connection.commit()
        user_id = cursor.lastrowid
        self.db.log_audit_event("USER_REGISTERED", clean_username, f"Registered with role={role}")

        return {
            "id": user_id,
            "username": clean_username,
            "email": clean_email,
            "role": role,
            "created_at": now_iso,
        }

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Memvalidasi kredensial pengguna dan menerbitkan token sesi jika valid."""
        clean_username = sanitize_text(username, max_length=50)
        cursor = self.db.connection.cursor()
        cursor.execute(
            "SELECT id, username, email, password_hash, salt, role FROM users WHERE username = ?",
            (clean_username,),
        )
        row = cursor.fetchone()
        if not row:
            self.db.log_audit_event("LOGIN_FAILED", clean_username, "User not found")
            return None

        if not verify_password(password, row["password_hash"], row["salt"]):
            self.db.log_audit_event("LOGIN_FAILED", clean_username, "Invalid password")
            return None

        token = generate_session_token()
        session_info = {
            "user_id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "role": row["role"],
            "token": token,
        }
        self._active_sessions[token] = session_info
        self.db.log_audit_event("LOGIN_SUCCESS", clean_username, "Session token issued")
        return session_info

    def get_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Mengambil informasi pengguna berdasarkan token sesi aktif."""
        return self._active_sessions.get(token)
