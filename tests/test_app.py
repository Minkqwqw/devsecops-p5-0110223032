"""
Unit Tests untuk Aplikasi SecureTask API (tests/test_app.py)
Menguji modul keamanan, autentikasi, manajemen tugas, dan kontrol akses.
"""

import pytest

from src.app import SecureTaskApp
from src.security import (
    compute_integrity_digest,
    hash_password,
    sanitize_text,
    verify_password,
)


def test_password_hashing_and_verification() -> None:
    """Memastikan PBKDF2-HMAC-SHA256 menghasilkan hash unik dan verifikasi akurat."""
    pwd_hash, salt = hash_password("SecurePass!2026")
    assert len(pwd_hash) == 64
    assert len(salt) == 32
    assert verify_password("SecurePass!2026", pwd_hash, salt) is True
    assert verify_password("WrongPassword123", pwd_hash, salt) is False
    assert len(compute_integrity_digest("payload-integritas")) == 64


def test_short_password_rejected() -> None:
    """Memastikan password kurang dari 8 karakter ditolak."""
    with pytest.raises(ValueError):
        hash_password("short")


def test_input_sanitization() -> None:
    """Memastikan karakter berbahaya (XSS / SQLi) dibersihkan dari input."""
    raw = "  <script>alert('xss');</script>Judul Tugas  "
    cleaned = sanitize_text(raw)
    assert "<" not in cleaned
    assert ">" not in cleaned
    assert "'" not in cleaned
    assert ";" not in cleaned


def test_user_registration_and_login_flow() -> None:
    """Menguji alur registrasi pengguna dan autentikasi sesi."""
    app = SecureTaskApp()
    user = app.auth.register_user("mahasiswa_nf", "mhs@nurulfikri.ac.id", "DevSecOps#2026")
    assert user["username"] == "mahasiswa_nf"
    assert user["role"] == "member"

    session = app.auth.authenticate("mahasiswa_nf", "DevSecOps#2026")
    assert session is not None
    assert "token" in session
    assert app.auth.get_session(session["token"]) is not None

    failed_session = app.auth.authenticate("mahasiswa_nf", "SalahPassword123")
    assert failed_session is None
    app.db.close()


def test_task_lifecycle_and_idor_protection() -> None:
    """Menguji pembuatan tugas dan pencegahan Broken Access Control (IDOR)."""
    app = SecureTaskApp()
    alice = app.auth.register_user("alice", "alice@example.com", "AlicePass#123")
    bob = app.auth.register_user("bob", "bob@example.com", "BobPass#12345")
    admin = app.auth.register_user("admin_sec", "admin@example.com", "AdminPass#123", role="admin")

    task = app.tasks.create_task(
        owner_id=alice["id"],
        title="Konfigurasi GitHub Actions SAST",
        description="Membuat job build dan sast-scan pada runner ubuntu-latest",
        priority="high",
    )
    assert task["status"] == "pending"

    # Bob mencoba mengubah tugas milik Alice -> Harus ditolak (PermissionError)
    with pytest.raises(PermissionError):
        app.tasks.update_task_status(
            task_id=task["id"],
            new_status="completed",
            requester_id=bob["id"],
            requester_role="member",
        )

    # Alice mengubah tugas miliknya sendiri -> Berhasil
    updated = app.tasks.update_task_status(
        task_id=task["id"],
        new_status="in_progress",
        requester_id=alice["id"],
        requester_role="member",
    )
    assert updated["status"] == "in_progress"

    # Admin mengubah status tugas -> Berhasil
    completed = app.tasks.update_task_status(
        task_id=task["id"],
        new_status="completed",
        requester_id=admin["id"],
        requester_role="admin",
    )
    assert completed["status"] == "completed"
    app.db.close()


def test_health_check_and_audit_logs() -> None:
    """Menguji endpoint health check dan pencatatan audit log keamanan."""
    app = SecureTaskApp()
    health = app.health_check()
    assert health["status"] == "healthy"

    app.auth.register_user("auditor1", "audit@example.com", "AuditPass#2026")
    logs = app.db.get_audit_logs()
    assert len(logs) >= 1
    assert logs[0]["event_type"] == "USER_REGISTERED"
    app.db.close()
