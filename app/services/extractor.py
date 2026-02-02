"""
Intelligence Extractor: Extracts scam-related intelligence from conversations.
"""

import re

from app.models.schemas import ExtractedIntelligence, ConversationMessage


BANK_ACCOUNT_PATTERNS = [
    re.compile(r'\b\d{9,18}\b'),
    re.compile(r'a/c\s*(?:no\.?|number)?:?\s*(\d{9,18})', re.IGNORECASE),
    re.compile(r'account\s*(?:no\.?|number)?:?\s*(\d{9,18})', re.IGNORECASE),
    re.compile(r'acc\s*(?:no\.?)?:?\s*(\d{9,18})', re.IGNORECASE),
]

UPI_PATTERNS = [
    re.compile(r'[\w.-]+@(?:upi|paytm|ybl|okhdfcbank|okicici|oksbi|apl|axisbank|ibl|ikwik|freecharge|sbi|hdfcbank|icici|axl|indus|kotak|federal|rbl|idbi|yes|citi|hsbc|sc|pnb|bob|boi|cub|kvb|tmb|karb|iob|dcb|jkb|csb|esaf|ujjivan|equitas|bandhan|au|idfc|kbl|sib|lakshmivilas|dlb|nkgsb|cosmos|pmc|apgvb|barb|cnrb|dbs|deutsche|payzapp|pingpay|slice|gpay|phonepe|amazonpay|whatsapp)', re.IGNORECASE),
    re.compile(r'[\w.-]+@[\w]+', re.IGNORECASE),
]

PHONE_PATTERNS = [
    re.compile(r'\+91[-\s]?\d{10}'),
    re.compile(r'\+91\d{10}'),
    re.compile(r'(?<!\d)91\d{10}(?!\d)'),
    re.compile(r'(?<!\d)[6-9]\d{9}(?!\d)'),
    re.compile(r'\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b'),
]

URL_PATTERNS = [
    re.compile(r'https?://[^\s<>"{}|\\^\[\]`]+', re.IGNORECASE),
    re.compile(r'bit\.ly/\w+', re.IGNORECASE),
    re.compile(r'tinyurl\.com/\w+', re.IGNORECASE),
    re.compile(r't\.co/\w+', re.IGNORECASE),
    re.compile(r'goo\.gl/\w+', re.IGNORECASE),
    re.compile(r'[\w-]+\.(?:tk|ml|ga|cf|gq|xyz|top|work|click|link|online)/[\w/-]*', re.IGNORECASE),
]

SUSPICIOUS_KEYWORDS = [
    "urgent", "immediately", "blocked", "suspended", "verify",
    "otp", "pin", "password", "cvv", "atm",
    "kyc", "aadhaar", "pan card", "bank details",
    "lottery", "prize", "winner", "cashback", "refund",
    "legal action", "police", "arrest", "fir", "court",
    "click here", "transfer", "pay now", "send money",
    "account number", "bank account", "credit card", "debit card",
    "customer care", "support team", "bank manager",
    "expire", "deadline", "last chance", "limited time"
]


def _is_valid_bank_account(account: str) -> bool:
    """Validate if string could be a bank account number."""
    digits = re.sub(r'\D', '', account)
    
    if not (9 <= len(digits) <= 18):
        return False
    if len(set(digits)) == 1:
        return False
    if digits in '0123456789012345678901234567890':
        return False
    if digits.startswith('1234') or digits.startswith('0000'):
        return False
    
    return True


def _is_valid_upi(upi_id: str) -> bool:
    """Validate if string is a valid UPI ID."""
    if '@' not in upi_id:
        return False
    
    parts = upi_id.split('@')
    if len(parts) != 2:
        return False
    
    username, provider = parts
    
    if len(username) < 3 or len(username) > 50:
        return False
    if len(provider) < 2:
        return False
    
    email_domains = ['gmail', 'yahoo', 'hotmail', 'outlook', 'mail']
    if any(domain in provider.lower() for domain in email_domains):
        return False
    
    return True


def _clean_phone(phone: str) -> str:
    """Clean phone number to standard format."""
    cleaned = re.sub(r'[^\d+]', '', phone)
    
    if cleaned.startswith('+91'):
        cleaned = cleaned[3:]
    elif cleaned.startswith('91') and len(cleaned) == 12:
        cleaned = cleaned[2:]
    
    return cleaned


def _is_valid_phone(phone: str) -> bool:
    """Validate if string is a valid phone number."""
    digits = re.sub(r'\D', '', phone)
    
    if len(digits) == 10 and digits[0] in '6789':
        return True
    if len(digits) == 12 and digits.startswith('91') and digits[2] in '6789':
        return True
    
    return False


def _is_suspicious_url(url: str) -> bool:
    """Check if URL is suspicious/potentially phishing."""
    url_lower = url.lower()
    
    shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'is.gd', 'rb.gy']
    if any(s in url_lower for s in shorteners):
        return True
    
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']
    if any(url_lower.endswith(tld) or tld + '/' in url_lower for tld in suspicious_tlds):
        return True
    
    if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
        return True
    
    suspicious_words = ['verify', 'secure', 'login', 'update', 'confirm', 'bank', 'kyc']
    if any(word in url_lower for word in suspicious_words):
        return True
    
    return True


def extract_from_message(text: str) -> ExtractedIntelligence:
    """Extract intelligence from a single message."""
    intel = ExtractedIntelligence()
    
    for pattern in BANK_ACCOUNT_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            account = match if isinstance(match, str) else match[0] if match else None
            if account and _is_valid_bank_account(account):
                intel.bankAccounts.append(account)
    
    for pattern in UPI_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            if _is_valid_upi(match):
                intel.upiIds.append(match.lower())
    
    for pattern in PHONE_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            cleaned = _clean_phone(match)
            if cleaned and _is_valid_phone(cleaned):
                intel.phoneNumbers.append(cleaned)
    
    for pattern in URL_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            if _is_suspicious_url(match):
                intel.phishingLinks.append(match)
    
    text_lower = text.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            intel.suspiciousKeywords.append(keyword)
    
    intel.bankAccounts = list(set(intel.bankAccounts))
    intel.upiIds = list(set(intel.upiIds))
    intel.phoneNumbers = list(set(intel.phoneNumbers))
    intel.phishingLinks = list(set(intel.phishingLinks))
    intel.suspiciousKeywords = list(set(intel.suspiciousKeywords))
    
    return intel


def extract_from_conversation(
    history: list[ConversationMessage],
    current_message: str = None
) -> ExtractedIntelligence:
    """Extract intelligence from entire conversation."""
    combined = ExtractedIntelligence()
    
    for msg in history:
        if msg.sender == "scammer":
            msg_intel = extract_from_message(msg.text)
            combined.merge(msg_intel)
    
    if current_message:
        current_intel = extract_from_message(current_message)
        combined.merge(current_intel)
    
    return combined
