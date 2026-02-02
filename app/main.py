"""
ScamTrace Agent - Main FastAPI Application
"""

from contextlib import asynccontextmanager
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


async def verify_api_key(
    request: Request,
    x_api_key: str = Header(None, description="API key in header")
) -> str:
    """Verify the API key from headers or query parameter."""
    settings = get_settings()
    
    # Check header first
    key = x_api_key
    
    # Then check query parameter
    if not key:
        key = request.query_params.get("x-api-key")
    
    if not key:
        raise HTTPException(status_code=401, detail="API key required in header (x-api-key) or query parameter")
    
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


@app.get("/api/message", tags=["Honeypot"])
async def message_info():
    """Info about the message endpoint (POST required)."""
    return {
        "status": "info",
        "message": "This endpoint accepts POST requests only",
        "method": "POST",
        "endpoint": "/api/message",
        "required_header": "x-api-key"
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
        # Parse request body flexibly
        try:
            body = await request.json()
        except:
            body = {}
        
        # Handle empty or test requests
        if not body or not body.get("message"):
            return ResponsePayload(
                status="success",
                reply="Hello! I received your message. How can I help you?"
            )
        
        # Parse into our model
        try:
            payload = RequestPayload(**body)
        except Exception as e:
            # If parsing fails, create minimal payload
            payload = RequestPayload(
                sessionId=body.get("sessionId", "default-session"),
                message=None,
                conversationHistory=[],
                metadata=None
            )
        
        current_session = await session.get_or_create(payload.sessionId)
        await session.increment_messages(payload.sessionId)
        
        message = payload.get_message()
        
        # Override with raw body if available
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
            detection_result = await detect(
                message=message.text,
                history=history_dicts
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
        
        # Generate Response
        if current_session.scam_detected:
            intel = extractor.extract_from_message(message.text)
            if not intel.is_empty():
                await session.add_intelligence(payload.sessionId, intel)
                await session.add_agent_note(
                    payload.sessionId,
                    f"Extracted: {_summarize_intel(intel)}"
                )
            
            current_session = await session.get(payload.sessionId)
            
            reply = await agent.generate_response(
                scammer_message=message.text,
                history=payload.conversationHistory or [],
                extracted_intel=current_session.intelligence.model_dump() if current_session else None
            )
            
            # Check if we should send callback
            current_session = await session.get(payload.sessionId)
            if current_session and callback.should_send_callback(current_session):
                success = await callback.send_final_result(current_session)
                if success:
                    await session.mark_callback_sent(payload.sessionId)
        else:
            reply = _generate_neutral_response(message.text)
        
        return ResponsePayload(status="success", reply=reply)
    
    except Exception as e:
        print(f"Error processing message: {e}")
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
