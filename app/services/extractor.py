"""
Intelligence Extractor: Extracts scam-related intelligence from conversations.
"""

import re
from app.models.schemas import ExtractedIntelligence, ConversationMessage


# Refined patterns for better precision (order matters: more specific first)
BANK_ACCOUNT_PATTERNS = [
    # Explicit "account number" / "account no" with flexible spacing before digits
    re.compile(r'account\s*(?:no\.?|number)?\s*:?\s*(\d{9,18})\b', re.IGNORECASE),
    re.compile(r'(?:your|my)\s+account\s*(?:no\.?|number)?\s*:?\s*(\d{9,18})\b', re.IGNORECASE),
    re.compile(r'(?:confirm|verify|send|share|submit)\s+(?:your\s+)?(?:account\s+)?(?:no\.?|number)?\s*:?\s*(\d{9,18})\b', re.IGNORECASE),
    re.compile(r'a/c\s*(?:no\.?|number)?\s*:?\s*(\d{9,18})\b', re.IGNORECASE),
    re.compile(r'acc\s*(?:no\.?)?\s*:?\s*(\d{9,18})\b', re.IGNORECASE),
    re.compile(r'account\s+(?:is\s+)?(\d{11,18})\b', re.IGNORECASE),
    # 16-digit is very common for Indian bank accounts
    re.compile(r'\b(\d{16})\b'),
    # Other standalone long numbers (12-18 digits; 10 = phone, 11 = ambiguous)
    re.compile(r'\b(\d{12,18})\b'),
]

UPI_PATTERNS = [
    # Standard UPI handle
    re.compile(r'[\w.-]+@(?:upi|paytm|ybl|okhdfcbank|okicici|oksbi|apl|axisbank|ibl|ikwik|freecharge|sbi|hdfcbank|icici|axl|indus|kotak|federal|rbl|idbi|yes|citi|hsbc|sc|pnb|bob|boi|cub|kvb|tmb|karb|iob|dcb|jkb|csb|esaf|ujjivan|equitas|bandhan|au|idfc|kbl|sib|lakshmivilas|dlb|nkgsb|cosmos|pmc|apgvb|barb|cnrb|dbs|deutsche|payzapp|pingpay|slice|gpay|phonepe|amazonpay|whatsapp|postbank)', re.IGNORECASE),
    # Generic handle fallback
    re.compile(r'[a-zA-Z0-9._-]+@[a-zA-Z]{3,}', re.IGNORECASE),
]

# Allow common dashes: ASCII -, en-dash –, em-dash —, minus − (so "+91–9876543210" matches)
_PHONE_SEP = r'[-\s\u2013\u2014\u2212]'
PHONE_PATTERNS = [
    re.compile(r'(?:\+91|91)?' + _PHONE_SEP + r'?[6-9]\d{9}\b'),
    re.compile(r'\b[6-9]\d{9}\b'),
    re.compile(r'\b\d{3}' + _PHONE_SEP + r'?\d{3}' + _PHONE_SEP + r'?\d{4}\b'),  # e.g. 987-654-3210
]

URL_PATTERNS = [
    # Full URL with scheme (catch everything with https?://)
    re.compile(r'https?://[^\s<>"{}|\\^\[\]`]+', re.IGNORECASE),
    # www. domain with path (include = for query params)
    re.compile(r'www\.[\w.-]+\.(?:com|org|net|in|co\.in|io|info|biz|xyz|online|site|tech|link|click|top|work)(?:/[\w./?#&=%-]*)?', re.IGNORECASE),
    # Bare domain with path (no scheme) - e.g. sbi-verify.com/login or securebank.com/verify?acc=...
    re.compile(r'(?:[\w-]+\.)*[\w-]+\.(?:com|org|net|in|co\.in|io|info|biz|xyz|online|site|tech|link|click|top|work)(?:/[\w./?#&=%-]*)?', re.IGNORECASE),
    # Suspicious TLDs (free / often used for phishing)
    re.compile(r'[\w-]+\.(?:tk|ml|ga|cf|gq|xyz|top|work|click|link|online|live|store|shop)(?:/[\w./?#&=%-]*)?', re.IGNORECASE),
    # URL shorteners
    re.compile(r'(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|rb\.gy|shorturl\.at|x\.co|ow\.ly|buff\.ly|adf\.ly)/[\w.-]+', re.IGNORECASE),
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


def _normalize_account(account: str) -> str:
    """Return digits-only form for consistent storage and dedup."""
    return re.sub(r'\D', '', account)


def _is_valid_bank_account(account: str, phone_numbers: list = None) -> bool:
    """Validate if string could be a bank account number."""
    digits = _normalize_account(account)
    
    if not (9 <= len(digits) <= 18):
        return False
    if len(set(digits)) == 1:
        return False
    if digits == '0123456789012345678':
        return False
    
    # Don't count actual phone numbers as bank accounts (exact match only)
    # Do NOT reject a long number just because a 10-digit substring looks like a phone
    # (e.g. 1234567890123456 ends in 7890123456 - still a valid account number)
    if phone_numbers:
        for p in phone_numbers:
            p_digits = re.sub(r'\D', '', p)
            # Reject only if the full account string is exactly this phone or 91+phone
            if digits == p_digits:
                return False
            if len(p_digits) == 10 and digits == '91' + p_digits:
                return False
            if len(digits) == 10 and p_digits == digits:
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


# Domains we never treat as phishing (callbacks, known-good)
PHISHING_WHITELIST_DOMAINS = frozenset([
    "guvi.in", "hackathon.guvi.in", "www.guvi.in", "www.hackathon.guvi.in",
    "localhost", "127.0.0.1", "gov.in", "nic.in",
])

# TLDs commonly used for phishing / free hosting (high risk)
PHISHING_RISK_TLDS = frozenset([
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "online", "live", "store", "shop", "info", "biz", "site", "tech", "pw",
])

# URL shorteners (high risk in scam context)
PHISHING_SHORTENER_DOMAINS = frozenset([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rb.gy",
    "shorturl.at", "x.co", "ow.ly", "buff.ly", "adf.ly",
])

# Path/query words that strongly suggest phishing
PHISHING_URL_KEYWORDS = frozenset([
    "verify", "secure", "login", "signin", "update", "confirm", "validation",
    "bank", "kyc", "bonus", "claim", "password", "otp", "unblock", "suspend",
    "reactivate", "account", "secure-login", "verify-account", "update-kyc",
])


def _get_url_domain(url: str) -> str:
    """Extract lowercase host (domain) from URL for whitelist/risk check."""
    url_lower = url.lower().strip()
    # Strip scheme
    for prefix in ("https://", "http://", "//"):
        if url_lower.startswith(prefix):
            url_lower = url_lower[len(prefix):]
            break
    # Take up to first / or ?
    host = url_lower.split("/")[0].split("?")[0]
    # Remove port if present
    if ":" in host:
        host = host.split(":")[0]
    return host


def _is_suspicious_url(url: str) -> bool:
    """
    Judge if a URL is likely phishing. Used in scam context, so we are strict:
    - Whitelist: known-good domains (e.g. callback URLs) are not flagged.
    - High risk: IP URLs, shorteners, risky TLDs → phishing.
    - Path/query contains phishing keywords → phishing.
    - Otherwise in scam context we still treat as suspicious (any link could be malicious).
    """
    if not url or not url.strip():
        return False
    url_lower = url.lower().strip()
    domain = _get_url_domain(url)

    # 1. Whitelist: never flag these
    if domain in PHISHING_WHITELIST_DOMAINS:
        return False
    if domain.endswith(".gov.in") or domain.endswith(".nic.in"):
        return False
    for w in PHISHING_WHITELIST_DOMAINS:
        if domain == w or domain.endswith("." + w):
            return False

    # 2. IP-based URL → high risk
    if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        return True

    # 3. URL shortener → high risk in scam context
    for short in PHISHING_SHORTENER_DOMAINS:
        if domain == short or domain.endswith("." + short):
            return True

    # 4. Risky TLD (e.g. .tk, .ga, .xyz) → high risk
    tld = domain.split(".")[-1] if "." in domain else ""
    if tld in PHISHING_RISK_TLDS:
        return True

    # 5. Path or query contains phishing-style keywords
    path_query = url_lower
    for prefix in ("https://", "http://", "//"):
        if prefix in path_query:
            idx = path_query.find(prefix)
            path_query = path_query[idx + len(prefix):]
            break
    if "/" in path_query:
        path_query = path_query[path_query.index("/"):]
    if any(kw in path_query for kw in PHISHING_URL_KEYWORDS):
        return True

    # 6. In scam context, any other link is still worth flagging for review
    return True


def _normalize_phishing_url(url: str) -> str:
    """Normalize URL for dedup: lowercase, strip fragment and trailing slash, canonical scheme."""
    if not url:
        return ""
    u = url.strip().lower()
    # Strip fragment
    if "#" in u:
        u = u[: u.index("#")]
    u = u.rstrip("/")
    # Canonical form: prefer https so "https://x.com/path" and "x.com/path" dedupe to one
    if u and not u.startswith("http://") and not u.startswith("https://"):
        u = "https://" + u
    return u


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
    
    # 2. BANK ACCOUNTS (normalize to digits-only for consistency)
    for pattern in BANK_ACCOUNT_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            account = match if isinstance(match, str) else match[0]
            if account and _is_valid_bank_account(account, intel.phoneNumbers):
                intel.bankAccounts.append(_normalize_account(account))
    
    # 3. UPI IDs
    for pattern in UPI_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            if _is_valid_upi(match):
                intel.upiIds.append(match.lower())
    
    # 4. URLs (phishing links)
    for pattern in URL_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            url = (match if isinstance(match, str) else match[0]).rstrip('.,;!?')
            if url and _is_suspicious_url(url):
                intel.phishingLinks.append(url)
    
    # 5. KEYWORDS
    text_lower = text.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            intel.suspiciousKeywords.append(keyword)
    
    # Remove phone numbers that are substrings of extracted bank accounts (false positives)
    if intel.bankAccounts:
        def phone_inside_account(phone: str) -> bool:
            p_d = re.sub(r'\D', '', phone)
            for acc in intel.bankAccounts:
                a_d = _normalize_account(acc)
                if len(a_d) > 10 and p_d in a_d:
                    return True
            return False
        intel.phoneNumbers = [p for p in intel.phoneNumbers if not phone_inside_account(p)]
            
    # Deduplicate phishing links by normalized URL; prefer the https:// version when same
    seen_urls = {}  # norm -> link (keep best, prefer https)
    for link in intel.phishingLinks:
        norm = _normalize_phishing_url(link)
        if not norm:
            continue
        if norm not in seen_urls:
            seen_urls[norm] = link
        elif link.startswith("https://") and not seen_urls[norm].startswith("https://"):
            seen_urls[norm] = link
    intel.phishingLinks = list(seen_urls.values())

    intel.bankAccounts = list(set(intel.bankAccounts))
    intel.upiIds = list(set(intel.upiIds))
    intel.phoneNumbers = list(set(intel.phoneNumbers))
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
