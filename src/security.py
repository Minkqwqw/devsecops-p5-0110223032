"""
Modul Utilitas Keamanan & Kriptografi (src/security.py)
Menyediakan fungsi hashing password, pembuatan token sesi, checksum SHA-256, dan sanitasi input.
"""

import hashlib
import hmac
import re
import secrets
from typing import Tuple


def hash_password(password: str, salt: str = "") -> Tuple[str, str]:
    """
    Melakukan hashing kata sandi menggunakan PBKDF2-HMAC-SHA256 (100.000 iterasi).
    Mengembalikan tuple (password_hash, salt).
    """
    if not password or len(password) < 8:
        raise ValueError("Password harus memiliki minimal 8 karakter.")

    if not salt:
        salt = secrets.token_hex(16)

    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=100_000,
    )
    return dk.hex(), salt


def compute_integrity_digest(data: str) -> str:
    """
    [REMEDIATED]: Menggantikan algoritma lemah MD5 (CWE-327) dengan SHA-256 yang aman
    untuk verifikasi integritas data.
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Memverifikasi kecocokan kata sandi dengan hash yang tersimpan secara constant-time."""
    computed_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, stored_hash)


def generate_session_token() -> str:
    """Menghasilkan token sesi acak yang aman secara kriptografis (CSPRNG)."""
    return secrets.token_urlsafe(32)


def sanitize_text(text: str, max_length: int = 255) -> str:
    """Membersihkan input teks dari karakter berbahaya dan membatasi panjang string."""
    if not isinstance(text, str):
        raise TypeError("Input harus berupa string.")
    cleaned = text.strip()
    cleaned = re.sub(r"[<>\"';]", "", cleaned)
    return cleaned[:max_length]
