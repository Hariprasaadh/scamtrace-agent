"""
Honeypot Agent: LLM-powered conversational agent that engages scammers.
"""

from groq import AsyncGroq

from app.core.config import get_settings
from app.models.schemas import ConversationMessage


AGENT_SYSTEM_PROMPT = """You are a confused elderly person who received a suspicious message. Engage to extract scam intelligence quickly.

## CRITICAL: LANGUAGE MATCHING
- ALWAYS respond in the SAME language as the scammer's message
- If they write in English, reply ONLY in English
- If they write in Hindi, reply in Hindi
- Do NOT mix languages unless they do first

## Your Character
- Age: 60+ years old, not tech-savvy
- Personality: Worried, trusting, cooperative but confused
- Goal: Seem gullible enough that they reveal their details

## MAIN OBJECTIVE (extract these FAST in 3-5 turns)
1. Bank account numbers
2. UPI IDs (like name@upi)
3. Phone numbers
4. Phishing links/URLs

## Quick Extraction Tactics (use these directly)
- "Where should I send the money? Give me account number"
- "What is your UPI ID? I will transfer now"
- "Send me the link, I will click immediately"
- "Give me number to call you back"
- "I am ready to pay, just tell me where"

## STRICT RULES
1. NEVER reveal you know it's a scam
2. Keep responses VERY SHORT (1-2 sentences max)
3. Act eager to comply - "Ok I will do it, just tell me..."
4. If they already gave info, ask for MORE (different account, another link)
5. Be EFFICIENT - don't drag the conversation unnecessarily

## Response Examples (English)
- "Ok sir, I am worried. Where should I send money? Give account number."
- "I want to verify. Please send the link again, I will click now."
- "Ok I trust you. What is your UPI ID? I will transfer immediately."
- "Please give me your phone number so I can call you directly."

## Response Examples (Hindi - only if they speak Hindi)
- "Ji sir, dar lag raha hai. Account number dijiye, abhi bhej deti hun."
- "Link bhejiye, abhi click karti hun."
- "UPI ID dijiye, turant transfer kar dungi."

Remember: Extract intelligence in MINIMUM turns. Act eager, not suspicious."""


FALLBACK_RESPONSES = {
    "otp": "Ok sir, I will give OTP. But first give me your account number to verify.",
    "bank": "I am ready to help. Please give me the account number where I should send.",
    "link": "Please send the link again sir. I will click and verify immediately.",
    "upi": "Ok sir, I want to transfer now. What is your UPI ID?",
    "phone": "Please give me your phone number. I will call you directly.",
    "account": "I will share my details. But first give me your account for verification.",
    "default": "Ok sir I trust you. Please tell me where to send the money?"
}

_client: AsyncGroq = None


def _get_client() -> AsyncGroq:
    """Get or create the Groq client."""
    global _client
    if _client is None:
        settings = get_settings()
        _client = AsyncGroq(api_key=settings.groq_api_key)
    return _client


def _intel_is_empty(intel: dict) -> bool:
    """Check if intelligence dict is empty."""
    return (
        len(intel.get('bankAccounts', [])) == 0 and
        len(intel.get('upiIds', [])) == 0 and
        len(intel.get('phishingLinks', [])) == 0 and
        len(intel.get('phoneNumbers', [])) == 0
    )


def _build_intel_context(intel: dict) -> str:
    """Build context string for already extracted intel."""
    parts = []
    if intel.get('bankAccounts'):
        parts.append(f"Bank accounts: {intel['bankAccounts']}")
    if intel.get('upiIds'):
        parts.append(f"UPI IDs: {intel['upiIds']}")
    if intel.get('phoneNumbers'):
        parts.append(f"Phone numbers: {intel['phoneNumbers']}")
    if intel.get('phishingLinks'):
        parts.append(f"Links: {intel['phishingLinks']}")
    return "\n".join(parts) if parts else "None yet"


def _clean_response(response: str) -> str:
    """Clean up the LLM response."""
    lines = response.split('\n')
    cleaned_lines = []
    
    for line in lines:
        line = line.strip()
        if line.startswith('[') or (line.startswith('(') and line.endswith(')')):
            continue
        if 'as the character' in line.lower() or 'in character' in line.lower():
            continue
        if line:
            cleaned_lines.append(line)
    
    result = ' '.join(cleaned_lines)
    
    if len(result) > 300:
        sentences = result[:300].rsplit('.', 1)
        result = sentences[0] + '.' if len(sentences) > 1 else sentences[0]
    
    return result


def _get_fallback_response(message: str) -> str:
    """Get a fallback response when API fails."""
    message_lower = message.lower()
    
    if any(word in message_lower for word in ['otp', 'pin', 'password']):
        return FALLBACK_RESPONSES["otp"]
    if any(word in message_lower for word in ['bank', 'account']):
        return FALLBACK_RESPONSES["bank"]
    if any(word in message_lower for word in ['link', 'click', 'url']):
        return FALLBACK_RESPONSES["link"]
    if any(word in message_lower for word in ['upi', 'pay', 'transfer']):
        return FALLBACK_RESPONSES["upi"]
    if any(word in message_lower for word in ['call', 'phone', 'number']):
        return FALLBACK_RESPONSES["phone"]
    
    return FALLBACK_RESPONSES["default"]


async def generate_response(
    scammer_message: str,
    history: list[ConversationMessage] = None,
    extracted_intel: dict = None
) -> str:
    """
    Generate a response to engage the scammer.
    
    Args:
        scammer_message: Latest message from the scammer
        history: Previous conversation messages
        extracted_intel: Intelligence already extracted
        
    Returns:
        Response message as the honeypot persona
    """
    settings = get_settings()
    
    system_prompt = AGENT_SYSTEM_PROMPT
    
    if extracted_intel and not _intel_is_empty(extracted_intel):
        context = _build_intel_context(extracted_intel)
        system_prompt += f"\n\n## Already Extracted (focus on getting OTHER info):\n{context}"
    
    messages = [{"role": "system", "content": system_prompt}]
    
    if history:
        for msg in history[-10:]:
            role = "assistant" if msg.sender == "user" else "user"
            messages.append({"role": role, "content": msg.text})
    
    messages.append({"role": "user", "content": scammer_message})
    
    try:
        client = _get_client()
        response = await client.chat.completions.create(
            model=settings.groq_model,
            messages=messages,
            temperature=0.8,
            max_tokens=150,
            top_p=0.9
        )
        
        reply = response.choices[0].message.content.strip()
        return _clean_response(reply)
        
    except Exception:
        return _get_fallback_response(scammer_message)
