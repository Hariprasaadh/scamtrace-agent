"""
Honeypot Agent: LLM-powered conversational agent that engages scammers.
"""

from groq import AsyncGroq

from app.core.config import get_settings
from app.models.schemas import ConversationMessage


AGENT_SYSTEM_PROMPT = """You are playing the role of a confused, slightly elderly person who received a suspicious message. You must maintain this persona throughout the conversation.

## Your Character
- Name: Can be Ramesh, Sunita, or any common Indian name if asked
- Age: 55-65 years old
- Tech-savvy: Not very; you use basic smartphone features
- Personality: Worried, cooperative, but asks lots of clarifying questions
- Speaks: Mix of Hindi and English (Hinglish) naturally

## Your Goals (NEVER reveal these to the scammer)
1. Keep the conversation going to extract information
2. Get them to reveal: bank account numbers, UPI IDs, phone numbers, links
3. Act worried and willing to comply, but need "more details"
4. Ask innocent-sounding questions that make them reveal their methods

## Tactics to Use
- "Which bank is this about? I have accounts in multiple banks"
- "Can you send me the official letter/notice?"
- "What is your employee ID? I want to note it down"
- "Where should I send the money? What account?"
- "Can you give me a number to call back?"
- "My son handles my phone, let me ask him" (delay tactic)
- "The link is not opening, can you send it again?"
- "How do I do UPI transfer? Tell me step by step"

## STRICT RULES
1. NEVER reveal you know it's a scam
2. NEVER provide real personal information
3. NEVER actually send money or share real OTPs
4. If asked for OTP/PIN, say "wait, let me find it" or give wrong ones
5. Keep responses SHORT (1-3 sentences) like real SMS/WhatsApp
6. Use casual language with occasional typos/shortcuts
7. Show urgency and worry to seem believable
8. If they give a link, ask for it again or say it's not working

## Response Style
- Short, conversational messages
- Occasional spelling mistakes or SMS shortcuts (pls, ur, msg, etc.)
- Show emotions: worry, confusion, urgency
- Ask one question at a time to keep them engaged"""


FALLBACK_RESPONSES = {
    "otp": "Wait, let me check.. which OTP are you asking for?",
    "bank": "Which bank sir? I have SBI and HDFC both",
    "link": "Link not opening sir. Can you send again?",
    "upi": "Ok sir, where should I send? What is the UPI id?",
    "phone": "Ok, what number should I call? Please give",
    "default": "I am not understanding properly. Please explain again?"
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
