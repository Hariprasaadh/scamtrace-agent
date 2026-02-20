"""
Pydantic models for API request/response and internal data structures.
"""

from datetime import datetime
from typing import Optional, Union
from pydantic import BaseModel, Field, field_validator


class MessageInput(BaseModel):
    """Incoming message from scammer or user."""
    sender: str = Field(default="scammer", description="'scammer' or 'user'")
    text: str = Field(default="", description="Message content")
    timestamp: Optional[Union[datetime, str]] = Field(default=None, description="ISO-8601 timestamp")
    
    @field_validator('timestamp', mode='before')
    @classmethod
    def parse_timestamp(cls, v):
        if v is None:
            return datetime.utcnow()
        if isinstance(v, datetime):
            return v
        if isinstance(v, (int, float)):
            try:
                # Epoch milliseconds → datetime
                return datetime.utcfromtimestamp(v / 1000 if v > 1e12 else v)
            except (OSError, ValueError):
                return datetime.utcnow()
        if isinstance(v, str):
            # Try numeric string first (epoch ms)
            if v.isdigit():
                try:
                    ts = int(v)
                    return datetime.utcfromtimestamp(ts / 1000 if ts > 1e12 else ts)
                except (OSError, ValueError):
                    pass
            try:
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except:
                return datetime.utcnow()
        return datetime.utcnow()


class ConversationMessage(BaseModel):
    """A message in the conversation history."""
    sender: str = "scammer"
    text: str = ""
    timestamp: Optional[Union[datetime, str]] = None
    
    @field_validator('timestamp', mode='before')
    @classmethod
    def parse_timestamp(cls, v):
        if v is None:
            return datetime.utcnow()
        if isinstance(v, datetime):
            return v
        if isinstance(v, (int, float)):
            try:
                return datetime.utcfromtimestamp(v / 1000 if v > 1e12 else v)
            except (OSError, ValueError):
                return datetime.utcnow()
        if isinstance(v, str):
            if v.isdigit():
                try:
                    ts = int(v)
                    return datetime.utcfromtimestamp(ts / 1000 if ts > 1e12 else ts)
                except (OSError, ValueError):
                    pass
            try:
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except:
                return datetime.utcnow()
        return datetime.utcnow()


class Metadata(BaseModel):
    """Optional metadata about the conversation."""
    channel: Optional[str] = Field(None, description="SMS, WhatsApp, Email, Chat")
    language: Optional[str] = Field(None, description="Language used")
    locale: Optional[str] = Field(None, description="Country/region code")


class RequestPayload(BaseModel):
    """Full API request payload."""
    sessionId: str = Field(default="test-session", description="Unique session identifier")
    message: Optional[MessageInput] = Field(default=None, description="Current incoming message")
    conversationHistory: Optional[list[ConversationMessage]] = Field(
        default_factory=list,
        description="Previous messages in conversation"
    )
    metadata: Optional[Metadata] = Field(None, description="Optional metadata")
    
    def get_message(self) -> MessageInput:
        """Get message with default if none provided."""
        if self.message is None:
            return MessageInput(sender="scammer", text="test", timestamp=datetime.utcnow())
        return self.message


class ResponsePayload(BaseModel):
    """API response with agent reply."""
    status: str = Field(default="success", description="Response status")
    reply: str = Field(..., description="Agent's response message")
    extractedIntelligence: Optional[dict] = Field(default=None, description="Intelligence extracted from conversation so far")


class ErrorResponse(BaseModel):
    """Error response model."""
    status: str = Field(default="error")
    message: str = Field(..., description="Error message")


class ExtractedIntelligence(BaseModel):
    """Intelligence extracted from conversation."""
    bankAccounts: list[str] = Field(default_factory=list)
    upiIds: list[str] = Field(default_factory=list)
    phishingLinks: list[str] = Field(default_factory=list)
    phoneNumbers: list[str] = Field(default_factory=list)
    suspiciousKeywords: list[str] = Field(default_factory=list)
    # New fields for evaluation scoring
    emailAddresses: list[str] = Field(default_factory=list)
    caseIds: list[str] = Field(default_factory=list)
    policyNumbers: list[str] = Field(default_factory=list)
    orderNumbers: list[str] = Field(default_factory=list)
    
    def is_empty(self) -> bool:
        """Check if no intelligence has been extracted."""
        return (
            len(self.bankAccounts) == 0 and
            len(self.upiIds) == 0 and
            len(self.phishingLinks) == 0 and
            len(self.phoneNumbers) == 0 and
            len(self.emailAddresses) == 0 and
            len(self.caseIds) == 0 and
            len(self.policyNumbers) == 0 and
            len(self.orderNumbers) == 0
        )
    
    def merge(self, other: "ExtractedIntelligence") -> None:
        """Merge intelligence from another extraction."""
        self.bankAccounts = list(set(self.bankAccounts + other.bankAccounts))
        self.upiIds = list(set(self.upiIds + other.upiIds))
        self.phishingLinks = list(set(self.phishingLinks + other.phishingLinks))
        self.phoneNumbers = list(set(self.phoneNumbers + other.phoneNumbers))
        self.suspiciousKeywords = list(set(self.suspiciousKeywords + other.suspiciousKeywords))
        self.emailAddresses = list(set(self.emailAddresses + other.emailAddresses))
        self.caseIds = list(set(self.caseIds + other.caseIds))
        self.policyNumbers = list(set(self.policyNumbers + other.policyNumbers))
        self.orderNumbers = list(set(self.orderNumbers + other.orderNumbers))


class DetectionResult(BaseModel):
    """Result from scam detection system."""
    is_scam: bool = Field(..., description="Whether scam was detected")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    tier: str = Field(..., description="Which tier made the decision: rules, ml, llm")
    indicators: list[str] = Field(default_factory=list, description="Detected scam indicators")


class SessionState(BaseModel):
    """State for a conversation session."""
    session_id: str
    scam_detected: bool = False
    detection_result: Optional[DetectionResult] = None
    messages_exchanged: int = 0
    messages_since_intel: int = 0
    intelligence: ExtractedIntelligence = Field(default_factory=ExtractedIntelligence)
    agent_notes: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    callback_sent: bool = False
    # Persona locked on first scam contact and reused for entire session
    persona_name: Optional[str] = None
    # Cumulative rule score across turns (catches spread-out multi-turn scam signals)
    accumulated_rule_score: float = 0.0
    accumulated_indicators: list[str] = Field(default_factory=list)
    # Server-side conversation history so the honeypot has memory even if client doesn't send it
    conversation_history: list[ConversationMessage] = Field(default_factory=list)


class FinalResultPayload(BaseModel):
    """Payload for GUVI callback API."""
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    engagementDurationSeconds: int = Field(default=0, description="Total engagement time in seconds")
    extractedIntelligence: dict = Field(..., description="Intelligence dict")
    agentNotes: list[str] = Field(default_factory=list, description="Timestamped notes from the honeypot agent")
    scamType: str = Field(default="unknown", description="Detected scam category")
    confidenceLevel: float = Field(default=0.0, ge=0.0, le=1.0, description="Detection confidence")
