"""
Tier 1: Rule-based scam detection using keyword matching and pattern detection.
"""

import re
from dataclasses import dataclass


@dataclass
class RuleResult:
    """Result from rule-based detection."""
    score: float
    indicators: list[str]


KEYWORDS = {
    "urgency": {
        "weight": 0.3,
        "terms": [
            "urgent", "immediately", "blocked", "suspended", "expire",
            "within 24 hours", "within 2 hours", "right now", "asap",
            "time sensitive", "act now", "hurry", "deadline", "last chance",
            "limited time", "expires today", "final notice", "immediate action"
        ]
    },
    "sensitive_data": {
        "weight": 0.4,
        "terms": [
            "otp", "pin", "password", "cvv", "bank details", "account number",
            "card number", "credit card", "debit card", "atm pin", "security code",
            "secret code", "verification code", "aadhaar", "pan card", "pan number",
            "login credentials", "net banking", "internet banking password"
        ]
    },
    "impersonation": {
        "weight": 0.25,
        "terms": [
            "rbi", "reserve bank", "bank manager", "government", "sbi",
            "hdfc", "icici", "axis bank", "pnb", "customer care", "support team",
            "official", "authorized", "central bank", "income tax", "it department",
            "police", "cyber cell", "ministry", "executive", "officer"
        ]
    },
    "threats": {
        "weight": 0.3,
        "terms": [
            "legal action", "police complaint", "arrest", "fir", "court",
            "lawsuit", "penalty", "fine", "prosecution", "jail", "prison",
            "warrant", "summons", "investigation", "criminal case", "freeze account"
        ]
    },
    "offers": {
        "weight": 0.25,
        "terms": [
            "lottery", "won", "winner", "prize", "cashback", "refund", "reward",
            "jackpot", "lucky", "selected", "congratulations", "claim your",
            "free gift", "bonus", "discount", "offer", "deal"
        ]
    },
    "action_requests": {
        "weight": 0.35,
        "terms": [
            "click here", "click the link", "click below", "verify now",
            "update kyc", "link aadhaar", "confirm your", "share your",
            "send your", "provide your", "enter your", "submit your",
            "transfer to", "pay to", "send money", "download app"
        ]
    }
}

URL_PATTERNS = [
    re.compile(r'bit\.ly/\w+', re.IGNORECASE),
    re.compile(r'tinyurl\.com/\w+', re.IGNORECASE),
    re.compile(r'goo\.gl/\w+', re.IGNORECASE),
    re.compile(r't\.co/\w+', re.IGNORECASE),
    re.compile(r'is\.gd/\w+', re.IGNORECASE),
    re.compile(r'rb\.gy/\w+', re.IGNORECASE),
    re.compile(r'\w+\.(tk|ml|ga|cf|gq)/', re.IGNORECASE),
    re.compile(r'https?://\d+\.\d+\.\d+\.\d+', re.IGNORECASE),
]

UPI_PATTERNS = [
    re.compile(r'send\s+(?:to\s+)?[\w.-]+@[\w]+', re.IGNORECASE),
    re.compile(r'pay\s+(?:to\s+)?[\w.-]+@[\w]+', re.IGNORECASE),
    re.compile(r'transfer\s+(?:to\s+)?[\w.-]+@[\w]+', re.IGNORECASE),
    re.compile(r'upi\s*:?\s*[\w.-]+@[\w]+', re.IGNORECASE),
]

PHONE_PATTERNS = [
    re.compile(r'call\s+(?:us\s+)?(?:on\s+)?(?:at\s+)?\+?\d{10,}', re.IGNORECASE),
    re.compile(r'whatsapp\s+(?:us\s+)?(?:on\s+)?(?:at\s+)?\+?\d{10,}', re.IGNORECASE),
    re.compile(r'contact\s+(?:us\s+)?(?:on\s+)?(?:at\s+)?\+?\d{10,}', re.IGNORECASE),
    re.compile(r'reach\s+(?:us\s+)?(?:on\s+)?(?:at\s+)?\+?\d{10,}', re.IGNORECASE),
]

MONEY_PATTERNS = [
    re.compile(r'(?:rs\.?|₹|inr)\s*\d+', re.IGNORECASE),
    re.compile(r'\d+\s*(?:rs\.?|₹|rupees?)', re.IGNORECASE),
    re.compile(r'\d+,\d{3}', re.IGNORECASE),
]


def _has_money_amount(message: str) -> bool:
    """Check if message contains money amounts."""
    for pattern in MONEY_PATTERNS:
        if pattern.search(message):
            return True
    return False


def analyze(message: str) -> RuleResult:
    """Analyze a message for scam indicators using rules."""
    message_lower = message.lower()
    total_score = 0.0
    indicators = []
    
    for category, config in KEYWORDS.items():
        weight = config["weight"]
        terms = config["terms"]
        
        matched_terms = []
        for term in terms:
            if term in message_lower:
                matched_terms.append(term)
        
        if matched_terms:
            total_score += weight
            indicators.append(f"{category}: {', '.join(matched_terms[:3])}")
    
    for pattern in URL_PATTERNS:
        if pattern.search(message):
            total_score += 0.35
            indicators.append("suspicious_url: shortened/suspicious link detected")
            break
    
    for pattern in UPI_PATTERNS:
        if pattern.search(message):
            total_score += 0.3
            indicators.append("upi_request: UPI payment request detected")
            break
    
    for pattern in PHONE_PATTERNS:
        if pattern.search(message):
            total_score += 0.15
            indicators.append("phone_solicitation: Contact request detected")
            break
    
    if _has_money_amount(message) and any(
        term in message_lower for term in ["send", "transfer", "pay", "deposit"]
    ):
        total_score += 0.2
        indicators.append("money_request: Payment/transfer request with amount")
    
    return RuleResult(score=min(total_score, 1.0), indicators=indicators)
