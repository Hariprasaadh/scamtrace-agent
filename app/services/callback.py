"""
GUVI Callback Handler: Sends final results to the evaluation endpoint.
"""

import asyncio
import httpx
from datetime import datetime, timezone

from app.core.config import get_settings
from app.models.schemas import SessionState, FinalResultPayload, ExtractedIntelligence


_client: httpx.AsyncClient = None


async def _get_client() -> httpx.AsyncClient:
    """Get or create async HTTP client."""
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(timeout=10.0)
    return _client


async def close_client() -> None:
    """Close the HTTP client."""
    global _client
    if _client and not _client.is_closed:
        await _client.aclose()
        _client = None


def _summarize_notes(session: SessionState, intel: ExtractedIntelligence) -> str:
    """
    Create a short, natural-language summary for immediate action.
    Focus on what happened and what was extracted so someone can act on it.
    """
    parts = []
    
    # What tactics were used (no need to mention detection tier/confidence)
    if session.detection_result and session.detection_result.indicators:
        ind = session.detection_result.indicators[:6]
        if any("urgency" in i for i in ind) or any("urgent" in i.lower() for i in ind):
            parts.append("Scammer used urgency tactics (block/suspend/immediate action).")
        if any("sensitive" in i for i in ind) or any("otp" in i.lower() for i in ind):
            parts.append("Sensitive data requested (OTP, account number, etc.).")
        if any("impersonation" in i for i in ind):
            parts.append("Impersonation of bank/authority.")
        if any("action_requests" in i for i in ind):
            parts.append("Payment or data redirection requested.")
    
    # Extracted intelligence in actionable form (for immediate action)
    if intel.phishingLinks:
        parts.append("Phishing link(s) shared: " + "; ".join(intel.phishingLinks[:3]) + ".")
    if intel.upiIds:
        parts.append("UPI ID(s) for payments: " + ", ".join(intel.upiIds[:5]) + ".")
    if intel.bankAccounts:
        parts.append("Bank account(s) mentioned: " + ", ".join(intel.bankAccounts[:5]) + ".")
    if intel.phoneNumbers:
        parts.append("Contact number(s) shared: " + ", ".join(intel.phoneNumbers[:5]) + ".")
    if intel.emailAddresses:
        parts.append("Email address(es) shared: " + ", ".join(intel.emailAddresses[:5]) + ".")
    if intel.caseIds:
        parts.append("Case/Reference ID(s): " + ", ".join(intel.caseIds[:5]) + ".")
    if intel.policyNumbers:
        parts.append("Policy number(s): " + ", ".join(intel.policyNumbers[:5]) + ".")
    if intel.orderNumbers:
        parts.append("Order/Booking ID(s): " + ", ".join(intel.orderNumbers[:5]) + ".")
    
    return " ".join(parts) if parts else "Engagement completed."


def _intel_for_callback(session: SessionState) -> ExtractedIntelligence:
    """
    Get extracted intelligence for callback. Re-runs extraction on full
    conversation history so we don't miss phishing links or UPI from any message.
    """
    from app.services.extractor import extract_from_conversation
    base = ExtractedIntelligence(**session.intelligence.model_dump())
    history = getattr(session, "conversation_history", None) or []
    if not history:
        return base
    # Final sweep: extract from all scammer messages again and merge
    combined = extract_from_conversation(history, None)
    base.merge(combined)
    return base


def _infer_scam_type(session: SessionState) -> str:
    """
    Infer the type of scam based on detection indicators and conversation content.
    Returns one of: bank_fraud, upi_fraud, phishing, job_scam, investment_scam,
    tech_support_scam, lottery_scam, or unknown.
    """
    indicators_text = ""
    if session.detection_result and session.detection_result.indicators:
        indicators_text = " ".join(session.detection_result.indicators).lower()
    
    # Also scan conversation history for more context
    history_text = ""
    for msg in (session.conversation_history or []):
        if msg.sender == "scammer":
            history_text += " " + msg.text.lower()
    
    combined = indicators_text + " " + history_text
    
    # Check for phishing links first (highest priority if links are present)
    intel = session.intelligence
    if intel.phishingLinks:
        return "phishing"
    
    # UPI fraud
    if any(kw in combined for kw in ['upi', 'gpay', 'phonepe', 'paytm', 'cashback', 'upi_request']):
        return "upi_fraud"
    
    # Bank fraud
    if any(kw in combined for kw in ['bank', 'account', 'kyc', 'otp', 'blocked', 'suspended', 'sbi', 'hdfc', 'icici']):
        return "bank_fraud"
    
    # Job scam
    if any(kw in combined for kw in ['job', 'hiring', 'salary', 'wfh', 'part time', 'work from home', 'registration fee']):
        return "job_scam"
    
    # Investment scam
    if any(kw in combined for kw in ['investment', 'profit', 'return', 'crypto', 'bitcoin', 'double your money']):
        return "investment_scam"
    
    # Lottery/prize scam
    if any(kw in combined for kw in ['lottery', 'prize', 'winner', 'congratulations', 'won', 'jackpot']):
        return "lottery_scam"
    
    # Tech support scam
    if any(kw in combined for kw in ['customer care', 'support team', 'refund', 'delivery', 'service']):
        return "tech_support_scam"
    
    return "unknown"


def _compute_engagement_duration(session: SessionState) -> int:
    """Compute engagement duration in seconds from session timestamps."""
    try:
        now = datetime.utcnow()
        delta = now - session.created_at
        return max(int(delta.total_seconds()), 0)
    except Exception:
        return 0


def _build_payload(session: SessionState) -> FinalResultPayload:
    """Build the callback payload from session state."""
    intel = _intel_for_callback(session)
    intelligence_dict = {
        "bankAccounts": intel.bankAccounts,
        "upiIds": intel.upiIds,
        "phishingLinks": intel.phishingLinks,
        "phoneNumbers": intel.phoneNumbers,
        "suspiciousKeywords": intel.suspiciousKeywords,
        "emailAddresses": intel.emailAddresses,
        "caseIds": intel.caseIds,
        "policyNumbers": intel.policyNumbers,
        "orderNumbers": intel.orderNumbers,
    }
    
    # Compute engagement metrics
    engagement_duration = _compute_engagement_duration(session)
    scam_type = _infer_scam_type(session)
    confidence = 0.0
    if session.detection_result:
        confidence = session.detection_result.confidence
    
    return FinalResultPayload(
        sessionId=session.session_id,
        scamDetected=session.scam_detected,
        totalMessagesExchanged=session.messages_exchanged,
        engagementDurationSeconds=engagement_duration,
        extractedIntelligence=intelligence_dict,
        agentNotes=_summarize_notes(session, intel),
        scamType=scam_type,
        confidenceLevel=confidence,
    )


async def send_final_result(session: SessionState, max_retries: int = 3) -> bool:
    """Send final result to GUVI callback endpoint."""
    settings = get_settings()
    payload = _build_payload(session)
    
    client = await _get_client()
    last_error = None
    
    for attempt in range(max_retries):
        try:
            response = await client.post(
                settings.guvi_callback_url,
                json=payload.model_dump(),
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code in [200, 201, 202]:
                return True
            
            last_error = f"HTTP {response.status_code}: {response.text}"
            
        except httpx.TimeoutException:
            last_error = "Request timeout"
        except httpx.RequestError as e:
            last_error = f"Request error: {str(e)}"
        except Exception as e:
            last_error = f"Unexpected error: {str(e)}"
        
        if attempt < max_retries - 1:
            await asyncio.sleep(2 ** attempt)
    
    print(f"Callback failed after {max_retries} attempts: {last_error}")
    return False


def should_send_callback(session: SessionState) -> bool:
    """Send callback only after max_conversation_messages (5), so we return final extraction once."""
    if not session.scam_detected:
        return False
    if session.callback_sent:
        return False
    from app.core.config import get_settings
    max_conversations = getattr(get_settings(), "max_conversation_messages", 7)
    return session.messages_exchanged >= max_conversations
