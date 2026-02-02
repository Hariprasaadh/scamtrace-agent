"""
Pydantic models for API request/response and internal data structures.
"""

from datetime import datetime
from typing import Optional, Union
from pydantic import BaseModel, Field, field_validator


class MessageInput(BaseModel):
    """Incoming message from scammer or user."""
    sender: str = Field(..., description="'scammer' or 'user'")
    text: str = Field(..., description="Message content")
    timestamp: Union[datetime, str] = Field(..., description="ISO-8601 timestamp")
    
    @field_validator('timestamp', mode='before')
    @classmethod
    def parse_timestamp(cls, v):
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except:
                return datetime.utcnow()
        return datetime.utcnow()


class ConversationMessage(BaseModel):
    """A message in the conversation history."""
    sender: str
    text: str
    timestamp: Union[datetime, str]
    
    @field_validator('timestamp', mode='before')
    @classmethod
    def parse_timestamp(cls, v):
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
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
    sessionId: str = Field(..., description="Unique session identifier")
    message: MessageInput = Field(..., description="Current incoming message")
    conversationHistory: Optional[list[ConversationMessage]] = Field(
        default_factory=list,
        description="Previous messages in conversation"
    )
    metadata: Optional[Metadata] = Field(None, description="Optional metadata")


class ResponsePayload(BaseModel):
    """API response with agent reply."""
    status: str = Field(default="success", description="Response status")
    reply: str = Field(..., description="Agent's response message")


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
    
    def is_empty(self) -> bool:
        """Check if no intelligence has been extracted."""
        return (
            len(self.bankAccounts) == 0 and
            len(self.upiIds) == 0 and
            len(self.phishingLinks) == 0 and
            len(self.phoneNumbers) == 0
        )
    
    def merge(self, other: "ExtractedIntelligence") -> None:
        """Merge intelligence from another extraction."""
        self.bankAccounts = list(set(self.bankAccounts + other.bankAccounts))
        self.upiIds = list(set(self.upiIds + other.upiIds))
        self.phishingLinks = list(set(self.phishingLinks + other.phishingLinks))
        self.phoneNumbers = list(set(self.phoneNumbers + other.phoneNumbers))
        self.suspiciousKeywords = list(set(self.suspiciousKeywords + other.suspiciousKeywords))


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


class FinalResultPayload(BaseModel):
    """Payload for GUVI callback API."""
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: dict = Field(..., description="Intelligence dict")
    agentNotes: str = Field(..., description="Summary of engagement")
