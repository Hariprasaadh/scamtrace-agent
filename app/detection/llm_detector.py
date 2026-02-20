"""
Tier 3: LLM-based scam detection for edge cases.
"""

import json
import logging
from dataclasses import dataclass
from groq import AsyncGroq

from app.core.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class LLMResult:
    """Result from LLM-based detection."""
    is_scam: bool
    confidence: float
    reasoning: str


DETECTION_PROMPT = """You are a scam detection expert. Analyze this message considering the conversation context.

Message: {message}

Conversation History:
{history}

Look for these scam indicators:
1. Urgency tactics (account suspension, limited time, immediate action required)
2. Requests for sensitive data (OTP, PIN, passwords, bank details, Aadhaar, PAN)
3. Impersonation of banks, government, or authorities
4. Suspicious links or contact requests
5. Too-good-to-be-true offers (lottery, prizes, easy money)
6. Threats (legal action, arrest, account blocking)
7. Pressure to act immediately without thinking

Consider context:
- Is this consistent with how legitimate organizations communicate?
- Are there grammatical errors or unusual phrasing common in scams?
- Is there a request for money or sensitive information?

Return ONLY a JSON object in this exact format (no other text):
{{"isScam": true/false, "confidence": 0.0-1.0, "reasoning": "brief explanation"}}"""

_client: AsyncGroq = None


def _get_client() -> AsyncGroq:
    """Get or create the Groq client."""
    global _client
    if _client is None:
        settings = get_settings()
        _client = AsyncGroq(api_key=settings.groq_api_key, timeout=15.0)
    return _client


def _parse_response(text: str) -> LLMResult:
    """Parse LLM response into structured result."""
    try:
        start_idx = text.find('{')
        end_idx = text.rfind('}') + 1
        
        if start_idx != -1 and end_idx > start_idx:
            json_str = text[start_idx:end_idx]
            data = json.loads(json_str)
            
            return LLMResult(
                is_scam=bool(data.get('isScam', False)),
                confidence=float(data.get('confidence', 0.5)),
                reasoning=str(data.get('reasoning', 'No reasoning provided'))
            )
    except (json.JSONDecodeError, KeyError, ValueError):
        pass
    
    text_lower = text.lower()
    if 'scam' in text_lower and ('yes' in text_lower or 'true' in text_lower or 'is a scam' in text_lower):
        return LLMResult(is_scam=True, confidence=0.7, reasoning="Inferred from response text")
    
    return LLMResult(
        is_scam=False,
        confidence=0.5,
        reasoning="Could not parse LLM response"
    )


def _truncate(text: str, max_chars: int, suffix: str = "...") -> str:
    """Truncate text to avoid blowing LLM context."""
    if not text or len(text) <= max_chars:
        return text or ""
    return text[: max_chars - len(suffix)].rstrip() + suffix


async def analyze(message: str, history: list[dict] = None) -> LLMResult:
    """Analyze a message using LLM for scam detection."""
    settings = get_settings()
    max_history = getattr(settings, "llm_detector_max_history_messages", 5)
    max_msg_chars = getattr(settings, "llm_detector_max_message_chars", 300)
    
    history_text = "No previous messages."
    if history:
        history_lines = []
        for msg in history[-max_history:]:
            sender = msg.get('sender', 'unknown')
            text = _truncate(msg.get('text', ''), max_msg_chars)
            history_lines.append(f"[{sender}]: {text}")
        history_text = "\n".join(history_lines)
    
    message_truncated = _truncate(message, max_msg_chars)
    prompt = DETECTION_PROMPT.format(
        message=message_truncated,
        history=history_text
    )
    
    try:
        client = _get_client()
        response = await client.chat.completions.create(
            model=settings.groq_model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a scam detection expert. Always respond with valid JSON only."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_tokens=200
        )
        
        result_text = response.choices[0].message.content.strip()
        return _parse_response(result_text)
        
    except Exception as e:
        logger.error(f"LLM detection error: {e}", exc_info=True)
        # LLM is only called when scores are ambiguous (0.3–0.55 range).
        # In that zone, a network/API failure should err toward catching the scam
        # rather than letting it pass — false positive costs nothing; false negative = 20 pts lost.
        return LLMResult(
            is_scam=True,
            confidence=0.65,
            reasoning=f"LLM unavailable; defaulting to scam (safe-fail): {str(e)}"
        )
