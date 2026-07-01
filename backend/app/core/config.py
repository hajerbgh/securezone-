from pydantic_settings import BaseSettings
from typing import List
import secrets


class Settings(BaseSettings):
    APP_NAME: str = "SecureZone"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = secrets.token_hex(32)
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:5173"
    DATABASE_URL: str = "postgresql+asyncpg://securezone:securezone_secret@localhost:5432/securezone_db"
    REDIS_URL: str = "redis://localhost:6379/0"
    ELASTICSEARCH_URL: str = "http://localhost:9200"
    ELASTICSEARCH_INDEX_PREFIX: str = "securezone"
    WAZUH_MANAGER_URL: str = "https://localhost:55000"
    WAZUH_API_USER: str = "wazuh"
    WAZUH_API_PASSWORD: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    NMAP_PATH: str = "/usr/bin/nmap"
    # OpenVAS / Greenbone GVM
    GVM_HOST: str = "localhost"
    GVM_PORT: int = 9390
    GVM_USERNAME: str = "admin"
    GVM_PASSWORD: str = "admin"
    OPENVAS_URL: str = "http://localhost:9390"  # kept for backward compat
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "securezone@company.local"
    SCAN_SCHEDULER_TIMEZONE: str = "Africa/Tunis"
    # Clé API pour les systèmes d'ingestion automatique (Wazuh, Squid, email GW)
    INGEST_API_KEY: str = "securezone-ingest-2024"
    # Groq API (chatbot SIEM)
    GROQ_API_KEY: str = ""

    @property
    def allowed_origins_list(self) -> List[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


settings = Settings()