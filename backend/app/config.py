from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # LLM configuration
    openai_api_key: Optional[str] = os.getenv("OPENAI_API_KEY")
    llm_provider: str = os.getenv("PHISHING_LLM_PROVIDER", "openai")
    llm_model: str = os.getenv("PHISHING_LLM_MODEL", "gpt-4o-mini")

    # Paths
    project_root: Path = Path(__file__).resolve().parents[2]
    frontend_dir: Path = Path(os.getenv("FRONTEND_DIR", project_root / "frontend"))
    samples_dir: Path = Path(os.getenv("SAMPLES_DIR", project_root / "samples"))

    # Feature flags
    @property
    def llm_enabled(self) -> bool:
        return bool(self.openai_api_key)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
