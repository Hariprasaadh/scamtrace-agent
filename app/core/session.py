"""
In-memory session management with TTL-based cleanup.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Optional

from app.models.schemas import SessionState, ExtractedIntelligence, DetectionResult
from app.core.config import get_settings


_sessions: dict[str, SessionState] = {}
_lock: asyncio.Lock = None
_cleanup_task: Optional[asyncio.Task] = None


def _get_lock() -> asyncio.Lock:
    """Get or create the asyncio lock."""
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


async def start_cleanup_task() -> None:
    """Start the background cleanup task."""
    global _cleanup_task
    if _cleanup_task is None:
        _cleanup_task = asyncio.create_task(_cleanup_loop())


async def stop_cleanup_task() -> None:
    """Stop the background cleanup task."""
    global _cleanup_task
    if _cleanup_task:
        _cleanup_task.cancel()
        try:
            await _cleanup_task
        except asyncio.CancelledError:
            pass
        _cleanup_task = None


async def _cleanup_loop() -> None:
    """Periodically clean up expired sessions."""
    settings = get_settings()
    ttl = timedelta(minutes=settings.session_ttl_minutes)
    
    while True:
        await asyncio.sleep(60)
        await _cleanup_expired(ttl)


async def _cleanup_expired(ttl: timedelta) -> None:
    """Remove sessions that have exceeded TTL."""
    now = datetime.utcnow()
    lock = _get_lock()
    
    async with lock:
        expired = [
            sid for sid, session in _sessions.items()
            if now - session.updated_at > ttl
        ]
        for sid in expired:
            del _sessions[sid]


async def get_or_create(session_id: str) -> SessionState:
    """Get existing session or create a new one."""
    lock = _get_lock()
    
    async with lock:
        if session_id not in _sessions:
            _sessions[session_id] = SessionState(session_id=session_id)
        return _sessions[session_id]


async def get(session_id: str) -> Optional[SessionState]:
    """Get a session by ID."""
    lock = _get_lock()
    
    async with lock:
        return _sessions.get(session_id)


async def update(session: SessionState) -> None:
    """Update a session."""
    lock = _get_lock()
    session.updated_at = datetime.utcnow()
    
    async with lock:
        _sessions[session.session_id] = session


async def mark_scam_detected(
    session_id: str,
    detection_result: DetectionResult
) -> Optional[SessionState]:
    """Mark a session as having detected scam."""
    lock = _get_lock()
    
    async with lock:
        session = _sessions.get(session_id)
        if session:
            session.scam_detected = True
            session.detection_result = detection_result
            session.updated_at = datetime.utcnow()
        return session


async def increment_messages(session_id: str) -> Optional[SessionState]:
    """Increment message count for a session."""
    lock = _get_lock()
    
    async with lock:
        session = _sessions.get(session_id)
        if session:
            session.messages_exchanged += 1
            session.messages_since_intel += 1
            session.updated_at = datetime.utcnow()
        return session


async def add_intelligence(
    session_id: str,
    intelligence: ExtractedIntelligence
) -> Optional[SessionState]:
    """Add extracted intelligence to a session."""
    lock = _get_lock()
    
    async with lock:
        session = _sessions.get(session_id)
        if session:
            old_intel = session.intelligence.model_dump()
            session.intelligence.merge(intelligence)
            new_intel = session.intelligence.model_dump()
            if old_intel != new_intel:
                session.messages_since_intel = 0
            session.updated_at = datetime.utcnow()
        return session


async def add_agent_note(session_id: str, note: str) -> Optional[SessionState]:
    """Add an agent note to the session."""
    lock = _get_lock()
    
    async with lock:
        session = _sessions.get(session_id)
        if session:
            session.agent_notes.append(note)
            session.updated_at = datetime.utcnow()
        return session


async def mark_callback_sent(session_id: str) -> Optional[SessionState]:
    """Mark that callback has been sent for this session."""
    lock = _get_lock()
    
    async with lock:
        session = _sessions.get(session_id)
        if session:
            session.callback_sent = True
            session.updated_at = datetime.utcnow()
        return session


async def delete(session_id: str) -> None:
    """Delete a session."""
    lock = _get_lock()
    
    async with lock:
        if session_id in _sessions:
            del _sessions[session_id]
