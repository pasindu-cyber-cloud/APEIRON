"""Application configuration loaded from environment variables.

All settings are prefixed with ``APEIRON_`` except a handful of well-known
third-party variables (DATABASE_URL, CELERY_*, REDIS_URL).
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Core ---
    env: str = Field("production", alias="APEIRON_ENV")
    secret_key: str = Field("change-me", alias="APEIRON_SECRET_KEY")
    api_host: str = Field("0.0.0.0", alias="APEIRON_API_HOST")
    api_port: int = Field(8000, alias="APEIRON_API_PORT")
    log_level: str = Field("INFO", alias="APEIRON_LOG_LEVEL")
    api_key: str = Field("", alias="APEIRON_API_KEY")

    # --- Database ---
    database_url: str = Field("sqlite:////data/apeiron.sqlite3", alias="DATABASE_URL")

    # --- Broker / queue ---
    redis_url: str = Field("redis://redis:6379/0", alias="REDIS_URL")
    celery_broker_url: str = Field("redis://redis:6379/1", alias="CELERY_BROKER_URL")
    celery_result_backend: str = Field("redis://redis:6379/2", alias="CELERY_RESULT_BACKEND")

    # --- Storage ---
    data_dir: Path = Field(Path("/data"), alias="APEIRON_DATA_DIR")
    upload_dir: Path = Field(Path("/data/uploads"), alias="APEIRON_UPLOAD_DIR")
    dump_dir: Path = Field(Path("/data/dumps"), alias="APEIRON_DUMP_DIR")
    report_dir: Path = Field(Path("/data/reports"), alias="APEIRON_REPORT_DIR")
    rules_dir: Path = Field(Path("/data/rules_generated"), alias="APEIRON_RULES_DIR")
    builtin_rules_dir: Path = Field(Path("/app/rules"), alias="APEIRON_BUILTIN_RULES_DIR")

    # --- Analysis engine ---
    emulation_timeout: int = Field(60, alias="APEIRON_EMULATION_TIMEOUT")
    max_upload_bytes: int = Field(67_108_864, alias="APEIRON_MAX_UPLOAD_BYTES")
    enable_emulation: bool = Field(True, alias="APEIRON_ENABLE_EMULATION")
    qiling_rootfs: Path = Field(Path("/data/rootfs"), alias="APEIRON_QILING_ROOTFS")
    anti_evasion: bool = Field(True, alias="APEIRON_ANTI_EVASION")

    # --- Redis pub/sub channels ---
    trace_channel_prefix: str = "apeiron:trace"
    events_channel: str = "apeiron:events"

    def ensure_dirs(self) -> None:
        for directory in (
            self.data_dir,
            self.upload_dir,
            self.dump_dir,
            self.report_dir,
            self.rules_dir,
        ):
            Path(directory).mkdir(parents=True, exist_ok=True)

    def trace_channel(self, sample_id: str) -> str:
        return f"{self.trace_channel_prefix}:{sample_id}"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
