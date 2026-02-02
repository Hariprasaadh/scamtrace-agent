"""
Configuration management using Pydantic Settings.
"""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    api_key: str = "your-secret-api-key"
    groq_api_key: str = ""
    groq_model: str = "llama-3.1-8b-instant"
    guvi_callback_url: str = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    session_ttl_minutes: int = 30
    rule_high_threshold: float = 0.8
    rule_low_threshold: float = 0.3
    ml_high_threshold: float = 0.6
    ml_low_threshold: float = 0.4
    max_messages_without_intel: int = 5
    min_messages_for_callback: int = 3
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
