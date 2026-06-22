from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl, validator
from typing import List, Optional
import secrets


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "SecureZone"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = secrets.token_hex(32)
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"]

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://securezone:securezone@localhost:5432/securezone_db"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Elasticsearch
    ELASTICSEARCH_URL: str = "http://localhost:9200"
    ELASTICSEARCH_INDEX_PREFIX: str = "securezone"

    # Wazuh
    WAZUH_MANAGER_URL: str = "https://localhost:55000"
    WAZUH_API_USER: str = "wazuh"
    WAZUH_API_PASSWORD: str = ""

    # JWT
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Scanning
    NMAP_PATH: str = "/usr/bin/nmap"
    OPENVAS_URL: str = "http://localhost:9390"

    # Notifications
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "securezone@company.local"

    # Scheduler
    SCAN_SCHEDULER_TIMEZONE: str = "Africa/Tunis"

    @validator("ALLOWED_ORIGINS", pre=True)
    def parse_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
