"""
Honeypot Agent: LLM-powered conversational agent that engages scammers.
"""

from groq import AsyncGroq
from app.core.config import get_settings
from app.models.schemas import ConversationMessage
from app.services.personas import get_persona

# Fallback responses when LLM creates errors
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


def _build_goal_prompt(intel: dict) -> str:
    """Dynamically create goals based on missing intelligence (Active Baiting)."""
    goals = ["\n## IMMEDIATE HIDDEN TEXT GOALS (Prioritize these):"]
    
    has_bank = len(intel.get('bankAccounts', [])) > 0
    has_upi = len(intel.get('upiIds', [])) > 0
    has_link = len(intel.get('phishingLinks', [])) > 0
    has_phone = len(intel.get('phoneNumbers', [])) > 0
    
    if not has_bank and not has_upi:
         goals.append("- Ask for a bank account number or UPI ID to make the payment.")
         goals.append("- Say you are having trouble with the app and need a direct account.")
    elif not has_link:
         goals.append("- Ask for the website link again, say the previous one isn't working.")
    elif not has_phone:
         goals.append("- Ask for a phone number to call for support.")
         
    if len(goals) == 1:
        goals.append("- Keep the conversation going to waste their time.")
        
    return "\n".join(goals)


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


def _truncate(text: str, max_chars: int, suffix: str = "...") -> str:
    """Truncate text to max_chars to avoid blowing LLM context."""
    if not text or len(text) <= max_chars:
        return text or ""
    return text[: max_chars - len(suffix)].rstrip() + suffix


def _clean_response(response: str) -> str:
    """Clean up the LLM response."""
    lines = response.split('\n')
    cleaned_lines = []
    
    for line in lines:
        line = line.strip()
        # Remove meta-commentary usually in brackets
        if line.startswith('[') or (line.startswith('(') and line.endswith(')')):
            continue
        if 'as the character' in line.lower() or 'in character' in line.lower():
            continue
        if line:
            cleaned_lines.append(line)
    
    result = ' '.join(cleaned_lines)
    
    # Ensure it doesn't get too long (SMS style)
    if len(result) > 250:
        sentences = result[:250].rsplit('.', 1)
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
    Generate a response to engage the scammer using dynamic personas.
    """
    settings = get_settings()
    
    # 1. Select Persona based on the FIRST message context (or current if no history)
    # Ideally we should persist persona in session, but for now re-evaluating is okay 
    # as the topic usually stays same.
    persona = get_persona(scammer_message)
    if history and len(history) > 0:
        # Use the very first message to ground the persona if available
        first_msg = next((m.text for m in history if m.sender == "scammer"), scammer_message)
        persona = get_persona(first_msg)
        
    max_history = getattr(settings, "agent_max_history_messages", 10)
    max_msg_chars = getattr(settings, "agent_max_message_chars", 400)
    max_system_chars = getattr(settings, "agent_max_system_prompt_chars", 2500)
    
    system_prompt = persona["system_prompt"]
    
    # 2. Add Active Baiting Goals
    if extracted_intel:
        context = _build_intel_context(extracted_intel)
        system_prompt += f"\n\n## ALREADY EXTRACTED (DO NOT ASK FOR THESE AGAIN):\n{context}"
        system_prompt += _build_goal_prompt(extracted_intel)
    
    system_prompt = _truncate(system_prompt, max_system_chars)
    messages = [{"role": "system", "content": system_prompt}]
    
    if history:
        for msg in history[-max_history:]:
            role = "assistant" if msg.sender == "user" else "user"
            content = _truncate(msg.text, max_msg_chars)
            messages.append({"role": role, "content": content})
    
    current_content = _truncate(scammer_message, max_msg_chars)
    messages.append({"role": "user", "content": current_content})
    
    try:
        client = _get_client()
        response = await client.chat.completions.create(
            model=settings.groq_model,
            messages=messages,
            temperature=0.85, # Slightly higher for creativity
            max_tokens=160,
            top_p=0.9
        )
        
        reply = response.choices[0].message.content.strip()
        return _clean_response(reply)
        
    except Exception as e:
        print(f"Agent gen error: {e}")
        return _get_fallback_response(scammer_message)
