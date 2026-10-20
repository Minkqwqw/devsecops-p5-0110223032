"""
Modul Konfigurasi Aplikasi (src/config.py)
Mengelola konfigurasi aplikasi dan parameter keamanan berbasis Environment Variables.
"""

import os
import secrets


class AppConfig:
    """Konfigurasi utama untuk layanan SecureTask API (Tanpa Hardcoded Credentials)."""

    APP_NAME: str = os.environ.get("APP_NAME", "SecureTask DevSecOps Service")
    APP_ENV: str = os.environ.get("APP_ENV", "production")
    DATABASE_PATH: str = os.environ.get("DATABASE_PATH", ":memory:")

    # [REMEDIATED]: Mengambil secret dari Environment Variable atau fallback CSPRNG runtime
    SECRET_KEY: str = os.environ.get("APP_SECRET_KEY") or secrets.token_hex(32)
    TOKEN_EXPIRY_SECONDS: int = int(os.environ.get("TOKEN_EXPIRY_SECONDS", "3600"))
    MAX_LOGIN_ATTEMPTS: int = int(os.environ.get("MAX_LOGIN_ATTEMPTS", "5"))

    @classmethod
    def get_database_uri(cls) -> str:
        """Mengembalikan lokasi koneksi database SQLite."""
        return cls.DATABASE_PATH
