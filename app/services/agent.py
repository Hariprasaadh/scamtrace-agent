"""
Honeypot Agent: LLM-powered conversational agent that engages scammers.
"""

import logging

from groq import AsyncGroq
from app.core.config import get_settings
from app.models.schemas import ConversationMessage
from app.services.personas import get_persona, PERSONAS

logger = logging.getLogger(__name__)

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
        len(intel.get('phoneNumbers', [])) == 0 and
        len(intel.get('emailAddresses', [])) == 0 and
        len(intel.get('caseIds', [])) == 0 and
        len(intel.get('policyNumbers', [])) == 0 and
        len(intel.get('orderNumbers', [])) == 0
    )


def _build_goal_prompt(intel: dict) -> str:
    """Dynamically create goals based on missing intelligence (Active Baiting)."""
    goals = ["\n## PRIORITY ACTIONS THIS TURN (do at least 2 of these):"]

    has_bank = len(intel.get('bankAccounts', [])) > 0
    has_upi = len(intel.get('upiIds', [])) > 0
    has_link = len(intel.get('phishingLinks', [])) > 0
    has_phone = len(intel.get('phoneNumbers', [])) > 0
    has_email = len(intel.get('emailAddresses', [])) > 0
    has_case = len(intel.get('caseIds', [])) > 0
    has_policy = len(intel.get('policyNumbers', [])) > 0
    has_order = len(intel.get('orderNumbers', [])) > 0

    if not has_bank and not has_upi:
        goals.append("- ELICIT PAYMENT: Ask for bank account number + IFSC, OR their UPI ID.")
        goals.append("  Say you prefer to do it via direct transfer — which account should you use?")
    if not has_link:
        goals.append("- ELICIT LINK: Ask for their official website URL.")
        goals.append("  Say the previous link didn't open properly — can they resend it?")
    if not has_phone:
        goals.append("- ELICIT PHONE: Ask for a callback number, saying you may lose network.")
        goals.append("  'What number can I call you back on if we get disconnected?'")
    if not has_email:
        goals.append("- ELICIT EMAIL: Ask them to email the documents/details.")
        goals.append("  'Can you send the official letter to my email? What is your email ID?'")
    if not has_case:
        goals.append("- ELICIT CASE ID: Ask for a complaint/case/reference number for your records.")
        goals.append("  'What is the FIR number or case reference so I can note it down?'")
    if not has_policy:
        goals.append("- ELICIT POLICY: Ask for the policy number if insurance/refund context.")
    if not has_order:
        goals.append("- ELICIT ORDER ID: Ask for the order ID / booking reference.")

    goals.append("- INVESTIGATE (every turn): Ask for employee/officer ID AND official website/toll-free number.")
    goals.append("  'What is your employee ID / badge number? And the official website where I can verify you?'")
    goals.append("- RED FLAGS (every turn): Point out one suspicious thing in character:")
    goals.append("  urgency, OTP request, upfront fees, unrecognised link, pressure tactics, etc.")

    if len([g for g in goals if g.startswith('-')]) <= 2:
        goals.append("- DELAY: Say you need to check with family / go to bank branch — extend the conversation.")
        goals.append("- ASK: Their supervisor name, branch address, and registered company phone number.")

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
        # Remove pure meta-commentary: a line that is entirely bracketed, e.g. [as the character]
        # but NOT a line that starts with [ and contains actual reply text after the bracket
        if line.startswith('[') and line.endswith(']') and len(line) < 80:
            continue
        if line.startswith('(') and line.endswith(')') and len(line) < 80:
            continue
        if 'as the character' in line.lower() or 'in character' in line.lower():
            continue
        if line:
            cleaned_lines.append(line)
    
    result = ' '.join(cleaned_lines)

    # Keep replies concise: red flag + question + elicitation
    if len(result) > 320:
        sentences = result[:320].rsplit('.', 1)
        result = sentences[0] + '.' if len(sentences) > 1 else result[:320]

    return result


def _detect_language(text: str) -> str:
    """Detect if scammer message is primarily English or Hinglish/Hindi."""
    hindi_markers = {
        'hai', 'hain', 'kya', 'aap', 'mera', 'tera', 'yeh', 'toh', 'accha',
        'theek', 'nahi', 'kar', 'hua', 'hoga', 'bhi', 'aur', 'ya', 'se',
        'ko', 'mein', 'ka', 'ki', 'ke', 'ji', 'sahib', 'bhai', 'didi',
        'rupaye', 'paisa', 'bank', 'khata', 'paise', 'lakh', 'crore',
    }
    words = set(text.lower().split())
    hindi_count = len(words & hindi_markers)
    return 'hinglish' if hindi_count >= 2 else 'english'


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
    extracted_intel: dict = None,
    session_id: str = None
) -> str:
    """
    Generate a response to engage the scammer using dynamic personas.
    Persona is persisted for the entire session (locked on first call).
    """
    settings = get_settings()

    from app.core import session as session_store

    persona = None
    if session_id:
        sess = await session_store.get(session_id)
        if sess and sess.persona_name:
            persona = PERSONAS.get(sess.persona_name, PERSONAS["default"])

    if persona is None:
        # First call for this session: pick persona from earliest scammer message
        first_msg = scammer_message
        if history:
            first_scammer = next((m.text for m in history if m.sender == "scammer"), None)
            if first_scammer:
                first_msg = first_scammer
        persona = get_persona(first_msg)
        # Persist for future turns so persona never switches mid-conversation
        if session_id:
            await session_store.set_persona(session_id, persona["key"])

    max_history = getattr(settings, "agent_max_history_messages", 12)
    max_msg_chars = getattr(settings, "agent_max_message_chars", 400)
    max_system_chars = getattr(settings, "agent_max_system_prompt_chars", 3000)

    system_prompt = persona["system_prompt"]

    # Mirror scammer's language so the reply sounds natural to them
    lang = _detect_language(scammer_message)
    if lang == 'english':
        system_prompt += (
            "\n\n## LANGUAGE RULE\n"
            "The scammer is writing in English. "
            "You MUST reply in plain English ONLY. Do NOT use any Hindi or Hinglish words."
        )
    else:
        system_prompt += (
            "\n\n## LANGUAGE RULE\n"
            "Match the scammer's Hinglish style. Mix Hindi and English naturally."
        )

    # 2. Add Active Baiting Goals
    if extracted_intel:
        context = _build_intel_context(extracted_intel)
        system_prompt += f"\n\n## ALREADY EXTRACTED (DO NOT ASK FOR THESE AGAIN):\n{context}"
        system_prompt += _build_goal_prompt(extracted_intel)
    else:
        # No intel yet — all goals active
        system_prompt += _build_goal_prompt({})

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
            temperature=0.85,
            max_tokens=220,   # concise: reaction + red-flag + 2 questions
            top_p=0.9
        )

        reply = response.choices[0].message.content.strip()
        return _clean_response(reply)

    except Exception as e:
        logger.error(f"Agent generation error: {e}", exc_info=True)
        return _get_fallback_response(scammer_message)
