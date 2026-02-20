"""
ScamTrace Agent - Main FastAPI Application
"""

import logging
from contextlib import asynccontextmanager
import asyncio
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.core.config import get_settings
from app.core import session
from app.models import (
    RequestPayload,
    ResponsePayload,
    ErrorResponse,
    DetectionResult as DetectionResultModel
)
from app.detection import detect
from app.services import agent, extractor, callback

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    await session.start_cleanup_task()
    yield
    await session.stop_cleanup_task()
    await callback.close_client()


app = FastAPI(
    title="ScamTrace Agent",
    description=(
        "AI-powered honeypot API for scam detection and intelligence extraction. "
        "Uses a 3-tier detection system (rules → ML → LLM) and engages scammers "
        "through believable personas to extract bank accounts, UPI IDs, and phishing links."
    ),
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors with detailed response."""
    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "message": "Invalid request body",
            "details": exc.errors()
        }
    )


# Placeholder values that indicate auth is not configured — bypass validation for these
_UNCONFIGURED_KEY_PLACEHOLDERS = {"your-secret-api-key", "", "changeme"}


async def verify_api_key(
    request: Request,
    x_api_key: str = Header(None, description="API key in header")
) -> str:
    """Verify the API key from headers or query parameter.

    Auth is OPTIONAL: if the configured api_key is a placeholder/empty, all
    requests are allowed through regardless of what key (or no key) is sent.
    When a real key is configured, the provided key must match exactly.
    """
    settings = get_settings()

    # If no real key is configured, skip auth entirely
    if settings.api_key.strip() in _UNCONFIGURED_KEY_PLACEHOLDERS:
        return ""

    key = x_api_key
    if not key:
        key = request.query_params.get("x-api-key", "")

    # Key is configured but not supplied → reject
    if not key:
        raise HTTPException(
            status_code=401,
            detail="API key required in header (x-api-key) or query parameter"
        )

    if key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return key


def _summarize_intel(intel) -> str:
    """Create a brief summary of extracted intelligence."""
    parts = []
    if intel.bankAccounts:
        parts.append(f"{len(intel.bankAccounts)} bank acc")
    if intel.upiIds:
        parts.append(f"{len(intel.upiIds)} UPI")
    if intel.phishingLinks:
        parts.append(f"{len(intel.phishingLinks)} links")
    if intel.phoneNumbers:
        parts.append(f"{len(intel.phoneNumbers)} phones")
    if intel.emailAddresses:
        parts.append(f"{len(intel.emailAddresses)} emails")
    if intel.caseIds:
        parts.append(f"{len(intel.caseIds)} caseIDs")
    if intel.policyNumbers:
        parts.append(f"{len(intel.policyNumbers)} policies")
    if intel.orderNumbers:
        parts.append(f"{len(intel.orderNumbers)} orders")
    return ", ".join(parts) if parts else "none"


def _generate_neutral_response(message: str) -> str:
    """Generate a neutral response for non-scam messages."""
    message_lower = message.lower()
    
    if any(word in message_lower for word in ['hello', 'hi', 'hey']):
        return "Hello! How can I help you?"
    if any(word in message_lower for word in ['thanks', 'thank you']):
        return "You're welcome!"
    if '?' in message:
        return "I'm not sure I understand. Could you please clarify?"
    
    return "I received your message. Is there anything specific you need help with?"


@app.get("/", tags=["Health"])
async def root():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "ScamTrace Agent",
        "version": "1.0.0"
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Detailed health check."""
    return {
        "status": "healthy",
        "components": {
            "api": "ok",
            "session_manager": "ok",
            "detection": "ok"
        }
    }


@app.post(
    "/api/message",
    responses={
        401: {"model": ErrorResponse, "description": "Invalid API key"},
        422: {"model": ErrorResponse, "description": "Invalid request body"},
        500: {"model": ErrorResponse, "description": "Internal server error"}
    },
    tags=["Honeypot"]
)
async def process_message(
    request: Request,
    api_key: str = Depends(verify_api_key)
):
    """
    Process an incoming message from the Mock Scammer API.
    Detects scam intent, engages with honeypot agent, extracts intelligence.
    """
    try:
        try:
            body = await request.json()
        except:
            body = {}
        
        if not body or not body.get("message"):
            return ResponsePayload(
                status="success",
                reply="Hello! I received your message. How can I help you?",
                extractedIntelligence=None
            )
        
        try:
            payload = RequestPayload(**body)
        except Exception as e:
            payload = RequestPayload(
                sessionId=body.get("sessionId", "default-session"),
                message=None,
                conversationHistory=[],
                metadata=None
            )
        
        current_session = await session.get_or_create(payload.sessionId)
        await session.increment_messages(payload.sessionId)
        current_session = await session.get(payload.sessionId)
        settings = get_settings()
        max_conversations = getattr(settings, "max_conversation_messages", 7)
        
        message = payload.get_message()
        
        if body.get("message", {}).get("text"):
            from app.models import MessageInput
            message = MessageInput(
                sender=body["message"].get("sender", "scammer"),
                text=body["message"]["text"],
                timestamp=body["message"].get("timestamp")
            )
        
        history_dicts = [
            {"sender": msg.sender, "text": msg.text, "timestamp": str(msg.timestamp)}
            for msg in (payload.conversationHistory or [])]
        
        # Scam Detection
        if not current_session.scam_detected:
            server_history = [
                {"sender": m.sender, "text": m.text}
                for m in (current_session.conversation_history or [])
            ]
            combined_history = server_history if server_history else history_dicts

            detection_result = await detect(
                message=message.text,
                history=combined_history,
                accumulated_score=current_session.accumulated_rule_score,
                accumulated_indicators=current_session.accumulated_indicators
            )

            await session.update_accumulated_score(
                payload.sessionId,
                detection_result.confidence if not detection_result.is_scam else 0.0,
                detection_result.indicators
            )

            if detection_result.is_scam:
                detection_model = DetectionResultModel(
                    is_scam=detection_result.is_scam,
                    confidence=detection_result.confidence,
                    tier=detection_result.tier,
                    indicators=detection_result.indicators
                )
                await session.mark_scam_detected(payload.sessionId, detection_model)
                current_session.scam_detected = True
                current_session.detection_result = detection_model

                await session.add_agent_note(
                    payload.sessionId,
                    f"Scam detected via {detection_result.tier} (conf: {detection_result.confidence:.2f})"
                )
        
        history = (current_session.conversation_history or []) if current_session else []

        if not current_session.scam_detected:
            quick_intel = extractor.extract_from_message(message.text)
            _ioc_found = (
                quick_intel.upiIds
                or quick_intel.bankAccounts
                or quick_intel.phishingLinks
                or quick_intel.phoneNumbers
            )
            if _ioc_found:
                _force_model = DetectionResultModel(
                    is_scam=True,
                    confidence=0.90,
                    tier="ioc",
                    indicators=["IOC-based: hard intelligence artefact found in message"]
                )
                await session.mark_scam_detected(payload.sessionId, _force_model)
                current_session.scam_detected = True
                current_session.detection_result = _force_model
                await session.add_agent_note(
                    payload.sessionId,
                    f"Scam force-detected via IOC (upi={bool(quick_intel.upiIds)}, "
                    f"bank={bool(quick_intel.bankAccounts)}, link={bool(quick_intel.phishingLinks)}, "
                    f"phone={bool(quick_intel.phoneNumbers)})"
                )

        if current_session.scam_detected:
            intel = extractor.extract_from_conversation(history, message.text)
            if not intel.is_empty():
                await session.add_intelligence(payload.sessionId, intel)
                await session.add_agent_note(
                    payload.sessionId,
                    f"Extracted: {_summarize_intel(intel)}"
                )

        if current_session.scam_detected:
            # Always keep engaging with LLM for full conversation quality score.
            # past_cap is only a safety guard for runaway sessions beyond max_conversation_messages.
            past_cap = current_session and current_session.messages_exchanged > max_conversations

            if past_cap:
                # Session is well past the cap — give a brief holding reply to avoid LLM cost
                reply = "I'm feeling worried and confused about this — it seems suspicious. Can you give me your employee ID and official website so I can verify this is legitimate?"
            else:
                reply = await agent.generate_response(
                    scammer_message=message.text,
                    history=history,
                    extracted_intel=current_session.intelligence.model_dump() if current_session else None,
                    session_id=payload.sessionId
                )
            
            await session.append_to_conversation(payload.sessionId, "scammer", message.text)
            await session.append_to_conversation(payload.sessionId, "user", reply)
            
            current_session = await session.get(payload.sessionId)
            if current_session and callback.should_send_callback(current_session):
                # Fire-and-forget: don't block the honeypot reply on callback latency
                asyncio.create_task(callback.send_final_result(current_session))
        else:
            reply = _generate_neutral_response(message.text)

        # Attach extracted intelligence to every response so callers can see it immediately
        intel_dict = None
        if current_session and current_session.scam_detected:
            current_session = await session.get(payload.sessionId)
            if current_session and not current_session.intelligence.is_empty():
                intel_dict = current_session.intelligence.model_dump()

        return ResponsePayload(status="success", reply=reply, extractedIntelligence=intel_dict)
    
    except Exception as e:
        logger.error(f"Error processing message: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/api/session/{session_id}", tags=["Debug"])
async def get_session_info(
    session_id: str,
    api_key: str = Depends(verify_api_key)
):
    """Get information about a session (for debugging)."""
    current_session = await session.get(session_id)
    if not current_session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        "session_id": current_session.session_id,
        "scam_detected": current_session.scam_detected,
        "messages_exchanged": current_session.messages_exchanged,
        "messages_since_intel": current_session.messages_since_intel,
        "intelligence": current_session.intelligence.model_dump(),
        "callback_sent": current_session.callback_sent,
        "created_at": str(current_session.created_at),
        "updated_at": str(current_session.updated_at)
    }


@app.post("/api/test/detect", tags=["Debug"])
async def test_detection(
    message: str,
    api_key: str = Depends(verify_api_key)
):
    """Test the scam detection system on a single message."""
    result = await detect(message)
    return {
        "message": message,
        "is_scam": result.is_scam,
        "confidence": result.confidence,
        "tier": result.tier,
        "indicators": result.indicators,
        "reasoning": result.reasoning
    }


@app.post("/api/test/extract", tags=["Debug"])
async def test_extraction(
    message: str,
    api_key: str = Depends(verify_api_key)
):
    """Test the intelligence extraction on a single message."""
    intel = extractor.extract_from_message(message)
    return {
        "message": message,
        "intelligence": intel.model_dump()
    }


# ── Endpoint aliases ─────────────────────────────────────────────────────────
# The evaluation platform example URLs use /detect and /honeypot.
# Route them to the same handler without duplication.

@app.post(
    "/detect",
    include_in_schema=False,
)
async def detect_alias(request: Request, api_key: str = Depends(verify_api_key)):
    """Alias for /api/message (evaluation-friendly path)."""
    return await process_message(request, api_key)


@app.post(
    "/honeypot",
    include_in_schema=False,
)
async def honeypot_alias(request: Request, api_key: str = Depends(verify_api_key)):
    """Alias for /api/message (evaluation-friendly path)."""
    return await process_message(request, api_key)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
