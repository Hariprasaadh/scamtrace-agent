"""
GUVI Callback Handler: Sends final results to the evaluation endpoint.
"""

import asyncio
import httpx

from app.core.config import get_settings
from app.models.schemas import SessionState, FinalResultPayload


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


def _summarize_notes(session: SessionState) -> str:
    """Create a summary of agent notes."""
    notes = []
    
    if session.detection_result:
        notes.append(
            f"Scam detected via {session.detection_result.tier} "
            f"(confidence: {session.detection_result.confidence:.2f})"
        )
        if session.detection_result.indicators:
            notes.append(f"Indicators: {', '.join(session.detection_result.indicators[:5])}")
    
    if session.agent_notes:
        notes.extend(session.agent_notes[-3:])
    
    intel = session.intelligence
    if intel.bankAccounts:
        notes.append(f"Extracted {len(intel.bankAccounts)} bank account(s)")
    if intel.upiIds:
        notes.append(f"Extracted {len(intel.upiIds)} UPI ID(s)")
    if intel.phishingLinks:
        notes.append(f"Extracted {len(intel.phishingLinks)} phishing link(s)")
    if intel.phoneNumbers:
        notes.append(f"Extracted {len(intel.phoneNumbers)} phone number(s)")
    
    return " | ".join(notes) if notes else "Engagement completed"


def _build_payload(session: SessionState) -> FinalResultPayload:
    """Build the callback payload from session state."""
    intelligence_dict = {
        "bankAccounts": session.intelligence.bankAccounts,
        "upiIds": session.intelligence.upiIds,
        "phishingLinks": session.intelligence.phishingLinks,
        "phoneNumbers": session.intelligence.phoneNumbers,
        "suspiciousKeywords": session.intelligence.suspiciousKeywords
    }
    
    return FinalResultPayload(
        sessionId=session.session_id,
        scamDetected=session.scam_detected,
        totalMessagesExchanged=session.messages_exchanged,
        extractedIntelligence=intelligence_dict,
        agentNotes=_summarize_notes(session)
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
    """Determine if callback should be sent for this session."""
    settings = get_settings()
    
    if not session.scam_detected:
        return False
    
    if session.callback_sent:
        return False
    
    if not session.intelligence.is_empty():
        return True
    
    if session.messages_since_intel >= settings.max_messages_without_intel:
        return True
    
    return False
