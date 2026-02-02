"""
Intelligence Extractor: Extracts scam-related intelligence from conversations.
"""

import re
from app.models.schemas import ExtractedIntelligence, ConversationMessage


# Refined patterns for better precision
BANK_ACCOUNT_PATTERNS = [
    re.compile(r'a/c\s*(?:no\.?|number)?:?\s*(\d{9,18})', re.IGNORECASE),
    re.compile(r'account\s*(?:no\.?|number)?[:\s]+(\d{9,18})', re.IGNORECASE),
    re.compile(r'acc\s*(?:no\.?)?:?\s*(\d{9,18})', re.IGNORECASE),
    re.compile(r'account\s+(?:is\s+)?(\d{11,18})', re.IGNORECASE),
    re.compile(r'\b(\d{11,18})\b'), # Standalone long numbers (often accounts)
]

UPI_PATTERNS = [
    # Standard UPI handle
    re.compile(r'[\w.-]+@(?:upi|paytm|ybl|okhdfcbank|okicici|oksbi|apl|axisbank|ibl|ikwik|freecharge|sbi|hdfcbank|icici|axl|indus|kotak|federal|rbl|idbi|yes|citi|hsbc|sc|pnb|bob|boi|cub|kvb|tmb|karb|iob|dcb|jkb|csb|esaf|ujjivan|equitas|bandhan|au|idfc|kbl|sib|lakshmivilas|dlb|nkgsb|cosmos|pmc|apgvb|barb|cnrb|dbs|deutsche|payzapp|pingpay|slice|gpay|phonepe|amazonpay|whatsapp|postbank)', re.IGNORECASE),
    # Generic handle fallback
    re.compile(r'[a-zA-Z0-9._-]+@[a-zA-Z]{3,}', re.IGNORECASE),
]

PHONE_PATTERNS = [
    re.compile(r'(?:\+91|91)?[-\s]?[6-9]\d{9}\b'),
    re.compile(r'\b[6-9]\d{9}\b'),
    re.compile(r'\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b'), # Generic format
]

URL_PATTERNS = [
    re.compile(r'https?://[^\s<>"{}|\\^\[\]`]+', re.IGNORECASE),
    re.compile(r'www\.[\w.-]+\.(?:com|org|net|in|co\.in|io|info|biz|xyz|online|site|tech|link|click|top|work)(?:/[\w./-]*)?', re.IGNORECASE),
    # Common shorteners and weird TLDs
    re.compile(r'[\w-]+\.(?:tk|ml|ga|cf|gq|xyz|top|work|click|link|online|live|store|shop)/[\w/-]*', re.IGNORECASE),
    re.compile(r'(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|rb\.gy|shorturl\.at|x\.co)/[\w-]+', re.IGNORECASE),
    # IP address URLs
    re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\S*)?'),
]

# New: IFSC Code Pattern
IFSC_PATTERN = re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b')

# New: PAN Pattern
PAN_PATTERN = re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b')


SUSPICIOUS_KEYWORDS = [
    "urgent", "immediately", "blocked", "suspended", "verify",
    "otp", "pin", "password", "cvv", "atm",
    "kyc", "aadhaar", "pan card", "bank details",
    "lottery", "prize", "winner", "cashback", "refund",
    "legal action", "police", "arrest", "fir", "court",
    "click here", "transfer", "pay now", "send money",
    "account number", "bank account", "credit card", "debit card",
    "customer care", "support team", "bank manager",
    "expire", "deadline", "last chance", "limited time",
    "investment", "profit", "return", "crypto", "bitcoin",
    "job", "hiring", "salary", "wfh", "part time" # Added for job scams
]


def _is_valid_bank_account(account: str, phone_numbers: list = None) -> bool:
    """Validate if string could be a bank account number."""
    digits = re.sub(r'\D', '', account)
    
    if not (9 <= len(digits) <= 18):
        return False
    if len(set(digits)) == 1:
        return False
    if digits == '0123456789012345678':
        return False
    
    # Don't count phone numbers as bank accounts
    # Common issue where phone number is detected as account
    if phone_numbers:
        for p in phone_numbers:
            p_digits = re.sub(r'\D', '', p)
            if p_digits in digits or digits in p_digits:
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
    
    # Filter out emails that get caught as UPI
    email_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com']
    if f"{provider.lower()}.com" in email_domains or provider.lower() in ['gmail', 'yahoo', 'hotmail']:
        # But wait, some UPI handles ARE okaxis, oksbi etc.
        # We only want to filter ACTUAL email addresses.
        # UPI handles usually don't end in .com unless it's a custom domain
        if '.' in provider and not provider.endswith('.com'):
            pass # might be valid (e.g. @yes.bank)
        elif provider.lower() in ['gmail', 'yahoo']: # Common email providers are NOT UPI banks usually
             # Wait, GPay uses @okaxis etc.
             # NOT @gmail
             pass
             
    # Strict check: reject if it looks exactly like an email
    if re.match(r'^[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}$', upi_id):
        # It has a .tld, so it's likely an email OR a custom UPI.
        # Most consumer UPIs don't have dots in the provider part (e.g. @oksbi, @Paytm).
        # We will assume it's an email if the provider is a known email host
        if any(d in upi_id.lower() for d in email_domains):
            return False

    return True


def _clean_phone(phone: str) -> str:
    """Clean phone number to standard format."""
    cleaned = re.sub(r'[^\d]', '', phone)
    
    # Remove leading 91 or 0
    if len(cleaned) > 10:
        if cleaned.startswith('91'):
             cleaned = cleaned[2:]
        elif cleaned.startswith('0'):
             cleaned = cleaned[1:]
             
    return cleaned


def _is_valid_phone(phone: str) -> bool:
    """Validate if string is a valid phone number."""
    if len(phone) != 10:
        return False
    
    # Valid Indian mobile start digits
    if phone[0] not in '6789':
        return False
        
    # Check for repeated digits (e.g. 9999999999)
    if len(set(phone)) == 1:
        return False
        
    return True


def _is_suspicious_url(url: str) -> bool:
    """Check if URL is suspicious/potentially phishing."""
    url_lower = url.lower()
    
    # Whitelist some common legit domains if needed, but for now be aggressive
    
    if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
        return True
    
    suspicious_words = ['verify', 'secure', 'login', 'update', 'confirm', 'bank', 'kyc', 'bonus', 'claim']
    if any(word in url_lower for word in suspicious_words):
        return True
        
    return True # In a scam context, almost ANY link is suspicious


def extract_from_message(text: str) -> ExtractedIntelligence:
    """Extract intelligence from a single message."""
    intel = ExtractedIntelligence()
    
    # 1. PHONE NUMBERS (Extract first to help filter bank accounts)
    for pattern in PHONE_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            cleaned = _clean_phone(match)
            if _is_valid_phone(cleaned):
                intel.phoneNumbers.append(cleaned)
    
    # 2. BANK ACCOUNTS
    for pattern in BANK_ACCOUNT_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            # Handle tuple matches from groups
            account = match if isinstance(match, str) else match[0]
            if account and _is_valid_bank_account(account, intel.phoneNumbers):
                intel.bankAccounts.append(account)
    
    # 3. UPI IDs
    for pattern in UPI_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            if _is_valid_upi(match):
                intel.upiIds.append(match.lower())
    
    # 4. URLs
    for pattern in URL_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            # Clean trailing punctuation
            url = match.rstrip('.,;!?')
            if _is_suspicious_url(url):
                intel.phishingLinks.append(url)
    
    # 5. KEYWORDS
    text_lower = text.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            intel.suspiciousKeywords.append(keyword)
            
    # Deduplicate
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
