"""
GUVI Callback Handler: Sends final results to the evaluation endpoint.
"""

import asyncio
import logging
import httpx
from datetime import datetime, timezone

from app.core.config import get_settings
from app.models.schemas import SessionState, FinalResultPayload, ExtractedIntelligence

logger = logging.getLogger(__name__)


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


def _build_agent_notes(session: SessionState, intel: ExtractedIntelligence) -> list[str]:
    """
    Build the full agentNotes list sent to the evaluator.
    Contains three sections:
      1. Per-turn operational notes (detection events, extraction events)
      2. Tactic analysis (what the scammer did)
      3. Intel summary (what was extracted)
    """
    notes: list[str] = []

    # --- Section 1: per-turn operational timeline from session.agent_notes ---
    for raw_note in (session.agent_notes or []):
        notes.append(raw_note)

    # Include LLM detection reasoning if available
    if session.detection_result:
        dr = session.detection_result
        notes.append(
            f"[Detection] tier={dr.tier} scamDetected={dr.is_scam} "
            f"confidence={dr.confidence:.2f} indicators={dr.indicators}"
        )

    # --- Section 2: tactic analysis ---
    if session.detection_result and session.detection_result.indicators:
        ind = session.detection_result.indicators
        if any("urgency" in i for i in ind) or any("urgent" in i.lower() for i in ind):
            notes.append("[Tactic] Urgency pressure used: block/suspend/immediate action threatened.")
        if any("sensitive" in i for i in ind) or any("otp" in i.lower() for i in ind):
            notes.append("[Tactic] Sensitive data solicited: OTP, account credentials, or personal info.")
        if any("impersonation" in i for i in ind):
            notes.append("[Tactic] Impersonation detected: posed as bank, TRAI, police, or courier.")
        if any("action_requests" in i for i in ind):
            notes.append("[Tactic] Payment or data redirection requested.")
        if any("fee" in i for i in ind):
            notes.append("[Tactic] Advance fee / processing fee demanded.")

    # --- Section 3: extracted intelligence summary ---
    if intel.phishingLinks:
        notes.append("[Intel] Phishing link(s): " + "; ".join(intel.phishingLinks[:5]))
    if intel.upiIds:
        notes.append("[Intel] UPI ID(s): " + ", ".join(intel.upiIds[:10]))
    if intel.bankAccounts:
        notes.append("[Intel] Bank account(s): " + ", ".join(intel.bankAccounts[:10]))
    if intel.phoneNumbers:
        notes.append("[Intel] Phone number(s): " + ", ".join(intel.phoneNumbers[:10]))
    if intel.emailAddresses:
        notes.append("[Intel] Email address(es): " + ", ".join(intel.emailAddresses[:10]))
    if intel.caseIds:
        notes.append("[Intel] Case/Reference ID(s): " + ", ".join(intel.caseIds[:10]))
    if intel.policyNumbers:
        notes.append("[Intel] Policy number(s): " + ", ".join(intel.policyNumbers[:5]))
    if intel.orderNumbers:
        notes.append("[Intel] Order/Booking ID(s): " + ", ".join(intel.orderNumbers[:5]))
    if intel.suspiciousKeywords:
        notes.append("[Intel] Suspicious keywords: " + ", ".join(sorted(set(intel.suspiciousKeywords))[:20]))

    if not notes:
        notes.append("Engagement completed — no scam indicators found.")

    return notes


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
    Infer the type of scam based on detection indicators, IOC data, and conversation content.
    Priority order: IOC hard evidence first, then keyword matching.
    Returns one of: bank_fraud, upi_fraud, phishing, job_scam, investment_scam,
    tech_support_scam, lottery_scam, kyc_fraud, sim_swap_scam, courier_scam, or unknown.
    """
    indicators_text = ""
    if session.detection_result and session.detection_result.indicators:
        indicators_text = " ".join(session.detection_result.indicators).lower()

    # Include accumulated indicators from multi-turn scoring
    if session.accumulated_indicators:
        indicators_text += " " + " ".join(session.accumulated_indicators).lower()

    # Scan all scammer messages for richer context
    history_text = ""
    for msg in (session.conversation_history or []):
        if msg.sender == "scammer":
            history_text += " " + msg.text.lower()

    combined = indicators_text + " " + history_text
    intel = session.intelligence

    # --- Hard IOC evidence first (highest confidence) ---
    if intel.phishingLinks:
        return "phishing"
    if intel.upiIds:
        return "upi_fraud"
    if intel.bankAccounts:
        return "bank_fraud"

    # --- Keyword matching on combined text ---
    if any(kw in combined for kw in ['upi', 'gpay', 'phonepe', 'paytm', 'cashback', 'upi_request', 'scanner', 'qr code']):
        return "upi_fraud"

    if any(kw in combined for kw in ['kyc', 'know your customer', 'aadhar', 'pan card', 'video kyc']):
        return "kyc_fraud"

    if any(kw in combined for kw in ['sim', 'trai', 'telecom', 'mobile number', 'sim block', 'sim swap', 'dnd']):
        return "sim_swap_scam"

    if any(kw in combined for kw in ['courier', 'parcel', 'package', 'customs', 'fedex', 'dhl', 'narcotics']):
        return "courier_scam"

    if any(kw in combined for kw in ['bank', 'account', 'otp', 'blocked', 'suspended', 'sbi', 'hdfc', 'icici', 'neft', 'rtgs', 'ifsc']):
        return "bank_fraud"

    if any(kw in combined for kw in ['job', 'hiring', 'salary', 'wfh', 'part time', 'work from home', 'registration fee', 'task', 'youtube like']):
        return "job_scam"

    if any(kw in combined for kw in ['investment', 'profit', 'return', 'crypto', 'bitcoin', 'trading', 'stock', 'double your money', 'guaranteed return']):
        return "investment_scam"

    if any(kw in combined for kw in ['lottery', 'prize', 'winner', 'congratulations', 'won', 'jackpot', 'lucky draw', 'kbc']):
        return "lottery_scam"

    if any(kw in combined for kw in ['customer care', 'support team', 'refund', 'delivery', 'amazon', 'flipkart', 'remote access', 'anydesk', 'teamviewer']):
        return "tech_support_scam"

    if any(kw in combined for kw in ['epf', 'pf', 'pension', 'insurance', 'policy', 'claim', 'pm kisan', 'government']):
        return "government_scheme_fraud"

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
        agentNotes=_build_agent_notes(session, intel),
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
    
        logger.warning(f"Callback failed after {max_retries} attempts: {last_error}")
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
