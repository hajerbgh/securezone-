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
    OPENVAS_URL: str = "http://localhost:9390"
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "securezone@company.local"
    SCAN_SCHEDULER_TIMEZONE: str = "Africa/Tunis"

    @property
    def allowed_origins_list(self) -> List[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


settings = Settings()