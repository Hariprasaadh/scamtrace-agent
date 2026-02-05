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
    
    # LLM context limits (avoid token overflow from long history)
    agent_max_history_messages: int = 10          # max conversation turns sent to honeypot LLM
    agent_max_message_chars: int = 400            # truncate each history/current message to this
    agent_max_system_prompt_chars: int = 2500    # cap system prompt (persona + intel + goals)
    llm_detector_max_history_messages: int = 5   # max turns sent to detection LLM
    llm_detector_max_message_chars: int = 300   # truncate each history message to this
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
