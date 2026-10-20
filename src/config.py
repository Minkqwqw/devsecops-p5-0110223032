"""
Modul Konfigurasi Aplikasi (src/config.py)
Mengelola konfigurasi aplikasi dan parameter keamanan.
"""

import os


class AppConfig:
    """Konfigurasi utama untuk layanan SecureTask API."""

    APP_NAME: str = os.environ.get("APP_NAME", "SecureTask DevSecOps Service")
    APP_ENV: str = os.environ.get("APP_ENV", "production")
    DATABASE_PATH: str = os.environ.get("DATABASE_PATH", ":memory:")

    # [VULNERABILITY - COMMIT 1]: Hardcoded secret key & password untuk pengujian SAST Quality Gate
    SECRET_KEY: str = "super_secret_hardcoded_jwt_key_2026_devsecops"
    DEFAULT_ADMIN_PASSWORD: str = "Admin@123!HardcodedSecret"

    TOKEN_EXPIRY_SECONDS: int = int(os.environ.get("TOKEN_EXPIRY_SECONDS", "3600"))
    MAX_LOGIN_ATTEMPTS: int = int(os.environ.get("MAX_LOGIN_ATTEMPTS", "5"))

    @classmethod
    def get_database_uri(cls) -> str:
        """Mengembalikan lokasi koneksi database SQLite."""
        return cls.DATABASE_PATH
