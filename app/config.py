"""Application settings loaded from environment (fixed upstream only via env)."""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    max_request_bytes: int = Field(default=1_048_576, alias="MAX_REQUEST_BYTES")
    max_json_depth: int = Field(default=32, alias="MAX_JSON_DEPTH")
    forward_upstream_url: str | None = Field(default=None, alias="FORWARD_UPSTREAM_URL")
    forward_timeout_seconds: float = Field(default=5.0, alias="FORWARD_TIMEOUT_SECONDS")
    forward_max_response_bytes: int = Field(default=1_048_576, alias="FORWARD_MAX_RESPONSE_BYTES")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    @field_validator("forward_upstream_url")
    @classmethod
    def strip_upstream(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        return v.strip().rstrip("/")


@lru_cache
def get_settings() -> Settings:
    return Settings()
