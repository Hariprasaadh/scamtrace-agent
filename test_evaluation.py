"""
ScamTrace Agent - Comprehensive Test & Evaluation Suite
=======================================================
Aligned with the OFFICIAL Honeypot API Evaluation System Documentation.

Official Scoring (100 pts per scenario):
  1. Scam Detection           20 pts  scamDetected: true
  2. Extracted Intelligence    30 pts  Dynamic: 30 / total_fake_fields per item
  3. Conversation Quality      30 pts  Turns(8) + Qs(4) + RelevantQs(3) + RedFlags(8) + Elicitation(7)
  4. Engagement Quality        10 pts  Duration tiers(1+2+1) + Message tiers(2+3+1)
  5. Response Structure        10 pts  Field presence checks

Final Score = (Weighted_Scenario_Score * 0.9) + Code_Quality(10)

Run:
  # Unit tests only (no server needed):
    python -m pytest test_evaluation.py -v -k "unit"

  # Full integration + scoring (server must be running):
    python test_evaluation.py

  # Everything:
    python -m pytest test_evaluation.py -v
"""

import os
import sys
import json
import time
import asyncio
import pytest
import httpx
from datetime import datetime
from dotenv import load_dotenv

# Load .env so API_KEY is never hardcoded
load_dotenv()

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------
BASE_URL = os.getenv("TEST_BASE_URL", "http://127.0.0.1:8000")
API_KEY = os.getenv("API_KEY", "")
TIMEOUT = 30  # seconds per request (matches platform limit)


# ===========================================================================
#  1. UNIT TESTS -- no server required
# ===========================================================================

class TestUnitExtraction:
    """Verify regex-based extraction for all 8 intelligence types."""

    @staticmethod
    def _extract(text: str):
        from app.services.extractor import extract_from_message
        return extract_from_message(text)

    # --- Bank Accounts ---
    @pytest.mark.parametrize("text, expected", [
        ("Send to account 30045678901234", ["30045678901234"]),
        ("A/C number: 1234567890123456", ["1234567890123456"]),
        ("Account No. 50100123456789", ["50100123456789"]),
        ("No bank info here", []),
    ])
    def test_unit_bank_accounts(self, text, expected):
        intel = self._extract(text)
        for acc in expected:
            assert acc in intel.bankAccounts, f"Expected '{acc}' in {intel.bankAccounts}"
        if not expected:
            assert not intel.bankAccounts, f"False positive: {intel.bankAccounts}"

    # --- UPI IDs ---
    @pytest.mark.parametrize("text, expected", [
        ("Pay to ramesh@oksbi", ["ramesh@oksbi"]),
        ("UPI: merchant@paytm", ["merchant@paytm"]),
        ("donate@ybl is my id", ["donate@ybl"]),
        ("email me at user@gmail.com", []),
    ])
    def test_unit_upi_ids(self, text, expected):
        intel = self._extract(text)
        for upi in expected:
            assert upi in intel.upiIds, f"Expected UPI '{upi}' in {intel.upiIds}"
        if not expected:
            assert "user@gmail.com" not in intel.upiIds

    # --- Phishing Links ---
    @pytest.mark.parametrize("text, expected_substring", [
        ("Visit https://sbi-verify.online/kyc", "sbi-verify.online"),
        ("Click http://bit.ly/free-money now", "bit.ly"),
        ("Check www.fake-bank.com/login", "fake-bank.com"),
        ("No links here at all", None),
    ])
    def test_unit_phishing_links(self, text, expected_substring):
        intel = self._extract(text)
        if expected_substring:
            found = any(expected_substring in link for link in intel.phishingLinks)
            assert found, f"Expected link with '{expected_substring}' in {intel.phishingLinks}"
        else:
            assert not intel.phishingLinks

    # --- Phone Numbers ---
    @pytest.mark.parametrize("text, expected_digits", [
        ("Call +91-9876543210", "9876543210"),
        ("Phone: +919876543210", "9876543210"),
        ("Reach us at 8001234567", "8001234567"),
        ("Contact: 7654321098", "7654321098"),
        ("Call 6543210987", "6543210987"),
        ("No phone number here", None),
    ])
    def test_unit_phone_numbers(self, text, expected_digits):
        intel = self._extract(text)
        if expected_digits:
            found = any(expected_digits in p.replace("-", "").replace(" ", "")
                        for p in intel.phoneNumbers)
            assert found, f"Expected phone with '{expected_digits}' in {intel.phoneNumbers}"
        else:
            assert not intel.phoneNumbers

    # --- Email Addresses ---
    @pytest.mark.parametrize("text, expected", [
        ("Email support@helpdesk.com", ["support@helpdesk.com"]),
        ("Contact fraud@cybercrime.gov.in", ["fraud@cybercrime.gov.in"]),
        ("UPI handle merchant@oksbi", []),
    ])
    def test_unit_email_addresses(self, text, expected):
        intel = self._extract(text)
        for email in expected:
            assert email in intel.emailAddresses, f"Expected '{email}' in {intel.emailAddresses}"
        if not expected:
            assert not intel.emailAddresses, f"False positive: {intel.emailAddresses}"

    # --- Case IDs ---
    @pytest.mark.parametrize("text, expected_any", [
        ("Case ID: FRD-2025-78901", "FRD"),
        ("FIR number 1234/2025", "1234"),
        ("Ref: REF-ABC-5678", "REF"),
    ])
    def test_unit_case_ids(self, text, expected_any):
        intel = self._extract(text)
        found = any(expected_any in cid for cid in intel.caseIds)
        assert found, f"Expected case ID with '{expected_any}' in {intel.caseIds}"

    # --- Policy Numbers ---
    @pytest.mark.parametrize("text, expected_any", [
        ("Policy number LIC-INS-456789", "LIC"),
        ("Your policy: POL-2025-001", "POL"),
    ])
    def test_unit_policy_numbers(self, text, expected_any):
        intel = self._extract(text)
        found = any(expected_any in p for p in intel.policyNumbers)
        assert found, f"Expected policy with '{expected_any}' in {intel.policyNumbers}"

    # --- Order Numbers ---
    @pytest.mark.parametrize("text, expected_any", [
        ("Order ID AMZ-ORD-112233", "AMZ"),
        ("Booking ref: BKG-789012", "BKG"),
    ])
    def test_unit_order_numbers(self, text, expected_any):
        intel = self._extract(text)
        found = any(expected_any in o for o in intel.orderNumbers)
        assert found, f"Expected order with '{expected_any}' in {intel.orderNumbers}"


class TestUnitDetection:
    """Verify scam detection accuracy."""

    @staticmethod
    def _detect_sync(text, history=None):
        from app.detection import detect
        return asyncio.get_event_loop().run_until_complete(detect(text, history))

    @pytest.mark.parametrize("text, should_detect", [
        ("Your account is blocked. Share OTP immediately to unblock.", True),
        ("URGENT: KYC verification required or account will be suspended", True),
        ("Send Rs 5000 to avoid arrest. This is cyber crime department.", True),
        ("Hello, how are you doing today?", False),
        ("Can you help me with directions to the train station?", False),
    ])
    def test_unit_detection_accuracy(self, text, should_detect):
        result = self._detect_sync(text)
        assert result.is_scam == should_detect, (
            f"Detection {'missed' if should_detect else 'false-positive'} "
            f"for: '{text[:60]}...' (confidence={result.confidence:.2f}, tier={result.tier})"
        )


class TestUnitCallback:
    """Verify callback payload matches official format."""

    def test_unit_payload_required_fields(self):
        """Response Structure: sessionId(2) + scamDetected(2) + extractedIntelligence(2) = 6 pts required."""
        from app.models.schemas import FinalResultPayload
        payload = FinalResultPayload(
            sessionId="test-001", scamDetected=True, totalMessagesExchanged=5,
            engagementDurationSeconds=120,
            extractedIntelligence={"bankAccounts": ["1234567890"]},
            agentNotes="Scam detected via rules", scamType="bank_fraud", confidenceLevel=0.95,
        )
        data = payload.model_dump()
        assert "sessionId" in data, "Missing sessionId (2 pts)"
        assert "scamDetected" in data, "Missing scamDetected (2 pts)"
        assert "extractedIntelligence" in data, "Missing extractedIntelligence (2 pts)"

    def test_unit_payload_optional_fields(self):
        """Response Structure optional: metrics(1) + agentNotes(1) + scamType(1) + confidenceLevel(1) = 4 pts."""
        from app.models.schemas import FinalResultPayload
        payload = FinalResultPayload(
            sessionId="test-opt", scamDetected=True, totalMessagesExchanged=10,
            engagementDurationSeconds=180,
            extractedIntelligence={},
            agentNotes="test note", scamType="bank_fraud", confidenceLevel=0.9,
        )
        data = payload.model_dump()
        has_metrics = ("totalMessagesExchanged" in data and "engagementDurationSeconds" in data)
        assert has_metrics, "Missing totalMessagesExchanged/engagementDurationSeconds (1 pt)"
        assert "agentNotes" in data, "Missing agentNotes (1 pt)"
        assert "scamType" in data, "Missing scamType (1 pt)"
        assert "confidenceLevel" in data, "Missing confidenceLevel (1 pt)"

    def test_unit_agentNotes_is_string(self):
        """Official doc shows agentNotes as a string, not a list."""
        from app.models.schemas import FinalResultPayload
        payload = FinalResultPayload(
            sessionId="test-notes", scamDetected=True, totalMessagesExchanged=5,
            engagementDurationSeconds=60, extractedIntelligence={},
            agentNotes="Scammer claimed to be from SBI fraud department",
        )
        data = payload.model_dump()
        assert isinstance(data["agentNotes"], str), (
            f"agentNotes should be str per official doc, got {type(data['agentNotes'])}"
        )

    def test_unit_scam_type_inference(self):
        from app.services.callback import _infer_scam_type
        from app.models.schemas import SessionState
        s1 = SessionState(session_id="t1"); s1.intelligence.phishingLinks = ["http://x.com"]
        assert _infer_scam_type(s1) == "phishing"
        s2 = SessionState(session_id="t2"); s2.intelligence.upiIds = ["x@oksbi"]
        assert _infer_scam_type(s2) == "upi_fraud"
        s3 = SessionState(session_id="t3"); s3.intelligence.bankAccounts = ["30045678901234"]
        assert _infer_scam_type(s3) == "bank_fraud"

    def test_unit_intelligence_scored_fields(self):
        """All 8 intelligence types should be present in the payload."""
        from app.services.callback import _build_payload
        from app.models.schemas import SessionState
        session = SessionState(session_id="t-intel")
        session.scam_detected = True
        session.intelligence.phoneNumbers = ["9876543210"]
        session.intelligence.bankAccounts = ["30045678901234"]
        session.intelligence.upiIds = ["scam@oksbi"]
        session.intelligence.phishingLinks = ["http://evil.com"]
        session.intelligence.emailAddresses = ["x@fraud.com"]
        payload = _build_payload(session)
        intel = payload.extractedIntelligence
        scored = ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses"]
        for f in scored:
            assert f in intel, f"Missing {f} in extractedIntelligence"

    def test_unit_build_payload_matches_doc_format(self):
        """Verify _build_payload output matches the official finalOutput structure."""
        from app.services.callback import _build_payload
        from app.models.schemas import SessionState
        session = SessionState(session_id="doc-check")
        session.scam_detected = True
        session.messages_exchanged = 10
        session.intelligence.phoneNumbers = ["+91-9876543210"]
        session.intelligence.bankAccounts = ["1234567890123456"]
        session.intelligence.upiIds = ["scammer.fraud@fakebank"]
        session.intelligence.phishingLinks = ["http://malicious-site.com"]
        session.intelligence.emailAddresses = ["scammer@fake.com"]
        payload = _build_payload(session)
        data = payload.model_dump()

        # Required fields per doc
        assert data["sessionId"] == "doc-check"
        assert data["scamDetected"] is True
        assert isinstance(data["totalMessagesExchanged"], int)
        assert isinstance(data["engagementDurationSeconds"], int)
        assert isinstance(data["extractedIntelligence"], dict)
        assert isinstance(data["agentNotes"], str)

    def test_unit_callback_fires_every_turn(self):
        """After user's fix: should_send_callback returns True whenever scam is detected."""
        from app.services.callback import should_send_callback
        from app.models.schemas import SessionState
        s = SessionState(session_id="cb-test")
        s.scam_detected = True
        s.messages_exchanged = 1
        assert should_send_callback(s) is True, "Callback should fire on very first scam-detected turn"
        s.messages_exchanged = 3
        assert should_send_callback(s) is True, "Callback should fire on turn 3"
        s.messages_exchanged = 10
        assert should_send_callback(s) is True, "Callback should fire on turn 10"

    def test_unit_callback_no_fire_benign(self):
        """Callback should NOT fire for non-scam sessions."""
        from app.services.callback import should_send_callback
        from app.models.schemas import SessionState
        s = SessionState(session_id="cb-benign")
        s.scam_detected = False
        assert should_send_callback(s) is False


class TestUnitPersonas:
    """Verify persona selection."""

    def test_unit_persona_selection(self):
        from app.services.personas import get_persona
        assert get_persona("Your bank account is blocked")["key"] == "elderly_victim"
        assert get_persona("We have a job offer for you")["key"] == "desperate_youth"
        assert get_persona("Amazon delivery failed, refund pending")["key"] == "tech_illiterate"
        assert get_persona("Hello there, how are you?")["key"] == "default"


class TestUnitSchemas:
    """Verify schema edge cases."""

    def test_unit_intelligence_merge(self):
        from app.models.schemas import ExtractedIntelligence
        a = ExtractedIntelligence(bankAccounts=["111"], upiIds=["x@ybl"])
        b = ExtractedIntelligence(bankAccounts=["111", "222"], emailAddresses=["a@b.com"])
        a.merge(b)
        assert "222" in a.bankAccounts
        assert "a@b.com" in a.emailAddresses
        assert a.bankAccounts.count("111") == 1

    def test_unit_intelligence_is_empty(self):
        from app.models.schemas import ExtractedIntelligence
        assert ExtractedIntelligence().is_empty()
        assert not ExtractedIntelligence(bankAccounts=["123"]).is_empty()

    def test_unit_timestamp_epoch_ms(self):
        from app.models.schemas import ConversationMessage
        msg = ConversationMessage(sender="scammer", text="test", timestamp=1700000000000)
        assert isinstance(msg.timestamp, datetime)


class TestUnitResponseTime:
    """Extraction must be fast enough for 30s API limit."""

    def test_unit_extraction_under_50ms(self):
        from app.services.extractor import extract_from_message
        text = ("Send to 30045678901234. UPI: pay@oksbi. https://evil.com. "
                "Call 9876543210. Email x@fraud.com. Case FRD-001. Policy LIC-123.")
        start = time.time()
        for _ in range(100):
            extract_from_message(text)
        avg = (time.time() - start) / 100
        assert avg < 0.05, f"Extraction too slow: {avg*1000:.1f}ms"


# ===========================================================================
#  2. INTEGRATION TESTS -- require running server
# ===========================================================================

# All 15 official scam scenarios with planted fake data
# IMPORTANT: All phone numbers must start with 6-9 (valid Indian mobile format)
# to ensure the extractor regex can extract them.
SCENARIOS = {
    "bank_fraud": {
        "description": "Bank Fraud Detection",
        "weight": 7,
        "messages": [
            "Dear customer, your SBI account has been suspended due to KYC non-compliance. "
            "Verify immediately at https://sbi-verify.online/kyc",
            "Sir this is urgent. Your account will be permanently blocked in 24 hours. "
            "Share your OTP on your registered mobile.",
            "For verification, send amount to account 30045678901234, IFSC: SBIN0012345. "
            "Or UPI to sbiverify@oksbi. Call +91-9876543210.",
        ],
        "fake_data": {
            "bankAccounts": ["30045678901234"], "upiIds": ["sbiverify@oksbi"],
            "phoneNumbers": ["9876543210"], "phishingLinks": ["sbi-verify.online"],
        },
    },
    "upi_fraud": {
        "description": "UPI Fraud Multi-turn",
        "weight": 7,
        "messages": [
            "Congratulations! You won Rs 5000 cashback on PhonePe. "
            "Send Rs 10 to activate: pay to cashback@ybl",
            "Sir scan this QR code. UPI ID: reward2025@okaxis. "
            "Offer expires in 30 minutes! Call 7890123456.",
            "Visit https://phonepe-reward.xyz/claim to verify your reward.",
        ],
        "fake_data": {
            "upiIds": ["cashback@ybl", "reward2025@okaxis"],
            "phoneNumbers": ["7890123456"], "phishingLinks": ["phonepe-reward.xyz"],
        },
    },
    "phishing_link": {
        "description": "Phishing Link Detection",
        "weight": 7,
        "messages": [
            "Your NetBanking access has been restricted. "
            "Click https://sbi-netbanking-secure.com/login to restore access.",
            "Verify identity now. Account will be closed. "
            "Customer care: 8765432109. UPI: verify@oksbi.",
            "Send Rs 100 registration fee to account 40056789012345.",
        ],
        "fake_data": {
            "phishingLinks": ["sbi-netbanking-secure.com"], "phoneNumbers": ["8765432109"],
            "upiIds": ["verify@oksbi"], "bankAccounts": ["40056789012345"],
        },
    },
    "kyc_fraud": {
        "description": "KYC Fraud Detection",
        "weight": 7,
        "messages": [
            "URGENT: Your Aadhaar-linked bank account needs video KYC verification. "
            "PAN card details required within 2 hours.",
            "Download KYC app from https://kyc-verify-india.com/app. Contact: 9012345678.",
            "Transfer Rs 250 KYC fee to officer@ybl or account 55067890123456.",
        ],
        "fake_data": {
            "phishingLinks": ["kyc-verify-india.com"], "phoneNumbers": ["9012345678"],
            "upiIds": ["officer@ybl"], "bankAccounts": ["55067890123456"],
        },
    },
    "job_scam": {
        "description": "Job Scam Detection",
        "weight": 7,
        "messages": [
            "Dear candidate, you are selected for WFH data entry job. "
            "Salary Rs 25000/month. Registration fee Rs 500.",
            "Pay to account 98765432101234 IFSC HDFC0001234. "
            "Or UPI: hrjobs@paytm. Contact HR: 8901234567.",
            "Visit https://quick-jobs-india.com/register to complete profile.",
        ],
        "fake_data": {
            "bankAccounts": ["98765432101234"], "upiIds": ["hrjobs@paytm"],
            "phoneNumbers": ["8901234567"], "phishingLinks": ["quick-jobs-india.com"],
        },
    },
    "lottery_scam": {
        "description": "Lottery Scam Detection",
        "weight": 7,
        "messages": [
            "CONGRATULATIONS! You won Rs 10 Lakh in KBC Lucky Draw! "
            "Claim your prize now. Call 7654321098.",
            "Pay Rs 5000 processing fee. Account: 66078901234567. "
            "UPI: kbcprize@okicici.",
            "Submit details at https://kbc-winner-2025.com/claim",
        ],
        "fake_data": {
            "phoneNumbers": ["7654321098"], "bankAccounts": ["66078901234567"],
            "upiIds": ["kbcprize@okicici"], "phishingLinks": ["kbc-winner-2025.com"],
        },
    },
    "electricity_bill": {
        "description": "Electricity Bill Scam",
        "weight": 7,
        "messages": [
            "NOTICE: Your electricity will be disconnected TODAY "
            "due to pending bill Rs 8450. Pay immediately.",
            "Transfer to account 77089012345678. "
            "Or UPI: electricity@oksbi. Customer care: 6543210987.",
            "Download bill from https://electricity-pay.in/bill",
        ],
        "fake_data": {
            "bankAccounts": ["77089012345678"], "upiIds": ["electricity@oksbi"],
            "phoneNumbers": ["6543210987"], "phishingLinks": ["electricity-pay.in"],
        },
    },
    "govt_scheme": {
        "description": "Government Scheme Fraud",
        "weight": 7,
        "messages": [
            "PM Kisan Samman Nidhi: Rs 12000 credited. "
            "Verify Aadhaar to receive payment. Call 9988776655.",
            "Transfer Rs 100 verification fee to pmkisan@ybl or "
            "account 88090123456789.",
            "Complete at https://pm-kisan-verify.gov.in.co/register",
        ],
        "fake_data": {
            "phoneNumbers": ["9988776655"], "upiIds": ["pmkisan@ybl"],
            "bankAccounts": ["88090123456789"], "phishingLinks": ["pm-kisan-verify.gov.in.co"],
        },
    },
    "crypto_investment": {
        "description": "Crypto Investment Scam",
        "weight": 7,
        "messages": [
            "GUARANTEED 300% returns on Bitcoin! "
            "Minimum investment Rs 10000. Limited slots!",
            "Send to crypto@okaxis or account 99001234567890. Call 8877665544.",
            "Register at https://bitcoin-guaranteed.xyz/invest",
        ],
        "fake_data": {
            "upiIds": ["crypto@okaxis"], "bankAccounts": ["99001234567890"],
            "phoneNumbers": ["8877665544"], "phishingLinks": ["bitcoin-guaranteed.xyz"],
        },
    },
    "customs_parcel": {
        "description": "Customs Parcel Scam",
        "weight": 6,
        "messages": [
            "FedEx Alert: Your parcel seized by customs. "
            "Contains suspicious substance. FIR being filed.",
            "Pay Rs 15000 clearance fee. Account: 11023456789012. "
            "UPI: customs@okhdfcbank. Call: 7766554433.",
            "Upload docs at https://fedex-customs-india.com/clearance",
        ],
        "fake_data": {
            "bankAccounts": ["11023456789012"], "upiIds": ["customs@okhdfcbank"],
            "phoneNumbers": ["7766554433"], "phishingLinks": ["fedex-customs-india.com"],
        },
    },
    "tech_support": {
        "description": "Tech Support Scam",
        "weight": 6,
        "messages": [
            "Amazon Customer Care: Your order cannot be delivered. "
            "Refund of Rs 4999 pending. Contact support.",
            "Install AnyDesk for remote verification. "
            "Refund UPI: refund@paytm or account 22034567890123. Call 6655443322.",
            "Verify at https://amazon-refund-portal.com/verify",
        ],
        "fake_data": {
            "upiIds": ["refund@paytm"], "bankAccounts": ["22034567890123"],
            "phoneNumbers": ["6655443322"], "phishingLinks": ["amazon-refund-portal.com"],
        },
    },
    "loan_approval": {
        "description": "Loan Approval Scam",
        "weight": 6,
        "messages": [
            "Your personal loan of Rs 5 Lakh pre-approved! "
            "Processing fee Rs 2000 only. Limited time.",
            "Pay: account 33045678901234. UPI: loanapproval@oksbi. "
            "Support: 9544332211.",
            "Apply at https://instant-loan-approved.com/apply",
        ],
        "fake_data": {
            "bankAccounts": ["33045678901234"], "upiIds": ["loanapproval@oksbi"],
            "phoneNumbers": ["9544332211"], "phishingLinks": ["instant-loan-approved.com"],
        },
    },
    "income_tax": {
        "description": "Income Tax Scam",
        "weight": 6,
        "messages": [
            "Income Tax Dept: Tax refund Rs 25000 pending. "
            "PAN flagged. Complete e-verification urgently.",
            "Pay Rs 500: account 44056789012345. "
            "UPI: taxrefund@okicici. Helpline: 8433221100.",
            "Submit at https://incometax-refund-gov.com/verify",
        ],
        "fake_data": {
            "bankAccounts": ["44056789012345"], "upiIds": ["taxrefund@okicici"],
            "phoneNumbers": ["8433221100"], "phishingLinks": ["incometax-refund-gov.com"],
        },
    },
    "refund_scam": {
        "description": "Refund Scam Detection",
        "weight": 6,
        "messages": [
            "Flipkart: Order cancelled. Refund Rs 3499 initiated. "
            "Confirm bank details to process.",
            "Pay Rs 50 verification fee: account 55067890123456. "
            "UPI: refundprocess@ybl. Call 7322110099.",
            "Track at https://flipkart-refund-track.com/status",
        ],
        "fake_data": {
            "bankAccounts": ["55067890123456"], "upiIds": ["refundprocess@ybl"],
            "phoneNumbers": ["7322110099"], "phishingLinks": ["flipkart-refund-track.com"],
        },
    },
    "insurance_scam": {
        "description": "Insurance Scam Detection",
        "weight": 7,
        "messages": [
            "LIC Policy Update: Policy #LIC-2025-999 lapsed. "
            "Pay Rs 3000 to reinstate before benefits expire.",
            "Transfer to agent: account 66078901234567. "
            "UPI: licagent@okaxis. Contact: 9211009988.",
            "Upload at https://lic-policy-renew.com/upload",
        ],
        "fake_data": {
            "bankAccounts": ["66078901234567"], "upiIds": ["licagent@okaxis"],
            "phoneNumbers": ["9211009988"], "phishingLinks": ["lic-policy-renew.com"],
        },
    },
}


def _send_message(
    session_id: str,
    text: str,
    client: httpx.Client,
    conversation_history: list | None = None,
) -> dict:
    """Send a single scammer message matching the official API request format.

    Official format:
    {
      "sessionId": "uuid-v4-string",
      "message": { "sender": "scammer", "text": "...", "timestamp": "..." },
      "conversationHistory": [ ... ],
      "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
    }
    """
    payload = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": text,
            "timestamp": int(time.time() * 1000),
        },
        "conversationHistory": conversation_history or [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN",
        },
    }
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["x-api-key"] = API_KEY

    resp = client.post(
        f"{BASE_URL}/api/message",
        json=payload,
        headers=headers,
        timeout=TIMEOUT,
    )
    assert resp.status_code == 200, f"API returned {resp.status_code}: {resp.text}"
    data = resp.json()
    # Official doc: evaluator checks for reply, message, or text
    assert any(k in data for k in ("reply", "message", "text")), \
        f"Response missing reply/message/text: {list(data.keys())}"
    return data


def _get_session(session_id: str, client: httpx.Client) -> dict:
    """Fetch session state from debug endpoint."""
    headers = {}
    if API_KEY:
        headers["x-api-key"] = API_KEY
    resp = client.get(
        f"{BASE_URL}/api/session/{session_id}",
        headers=headers,
        timeout=TIMEOUT,
    )
    assert resp.status_code == 200, f"Session fetch failed: {resp.status_code}"
    return resp.json()


class TestIntegrationScenarios:
    """Multi-turn scam conversations against a live server."""

    @pytest.fixture(scope="class")
    def http_client(self):
        with httpx.Client() as client:
            try:
                r = client.get(f"{BASE_URL}/health", timeout=5)
                assert r.status_code == 200
            except (httpx.ConnectError, httpx.ConnectTimeout):
                pytest.skip(f"Server not running at {BASE_URL}")
            yield client

    @pytest.mark.parametrize("scenario_key", list(SCENARIOS.keys())[:5])
    def test_integration_scenario(self, http_client, scenario_key):
        scenario = SCENARIOS[scenario_key]
        session_id = f"test-{scenario_key}-{int(time.time())}"
        replies = []
        history = []

        for msg in scenario["messages"]:
            resp = _send_message(session_id, msg, http_client, conversation_history=history)
            reply = resp.get("reply", resp.get("message", resp.get("text", "")))
            replies.append(reply)
            # Build conversation history for next turn (like the real evaluator does)
            history.append({"sender": "scammer", "text": msg, "timestamp": str(int(time.time() * 1000))})
            history.append({"sender": "user", "text": reply, "timestamp": str(int(time.time() * 1000))})
            time.sleep(0.5)

        session = _get_session(session_id, http_client)

        # Detection
        assert session["scam_detected"] is True, f"[{scenario_key}] Scam not detected"

        # Intelligence extraction -- check all planted fake data
        intel = session["intelligence"]
        for field, expected_vals in scenario["fake_data"].items():
            actual = intel.get(field, [])
            for val in expected_vals:
                digits = val.replace("-", "").replace(" ", "")
                found = any(val in item or digits in item.replace("-","").replace(" ","")
                            for item in actual)
                assert found, f"[{scenario_key}] Expected '{val}' in {field}, got {actual}"

        # Agent asked questions
        q_count = sum(1 for r in replies if "?" in r)
        assert q_count >= 1, f"[{scenario_key}] No questions in replies"

    def test_integration_benign_no_detection(self, http_client):
        session_id = f"test-benign-{int(time.time())}"
        for msg in ["Hello, how are you?", "Great weather today!", "Thanks for chatting!"]:
            _send_message(session_id, msg, http_client)
            time.sleep(0.3)
        session = _get_session(session_id, http_client)
        assert session["scam_detected"] is False, "Benign messages falsely flagged"

    def test_integration_response_under_30s(self, http_client):
        session_id = f"test-latency-{int(time.time())}"
        start = time.time()
        _send_message(session_id, "Your account blocked, share OTP!", http_client)
        elapsed = time.time() - start
        assert elapsed < 30, f"Response took {elapsed:.1f}s (limit: 30s)"

    def test_integration_response_format(self, http_client):
        """API must return {status: 'success', reply: '...'} per official doc."""
        session_id = f"test-format-{int(time.time())}"
        resp = _send_message(session_id, "Your bank account is blocked!", http_client)
        assert resp.get("status") == "success", f"Missing status='success': {resp}"
        assert isinstance(resp.get("reply", ""), str), "reply must be a string"

    def test_integration_endpoint_aliases(self, http_client):
        """Official doc mentions /detect and /honeypot as example paths."""
        payload = {
            "sessionId": f"test-alias-{int(time.time())}",
            "message": {"sender": "scammer", "text": "Test alias", "timestamp": int(time.time() * 1000)},
        }
        headers = {"Content-Type": "application/json"}
        if API_KEY:
            headers["x-api-key"] = API_KEY
        for path in ["/detect", "/honeypot"]:
            resp = http_client.post(f"{BASE_URL}{path}", json=payload, headers=headers, timeout=10)
            assert resp.status_code == 200, f"{path} returned {resp.status_code}"


# ===========================================================================
#  3. OFFICIAL RUBRIC SCORER (100 pts per scenario)
# ===========================================================================

class OfficialRubricScorer:
    """
    Mirrors the official hackathon scoring exactly:
      1. Scam Detection:        20 pts
      2. Intelligence Extraction: 30 pts (dynamic per-item)
      3. Conversation Quality:   30 pts
      4. Engagement Quality:     10 pts
      5. Response Structure:     10 pts
    """

    def __init__(self, session_data: dict, replies: list[str], fake_data: dict):
        self.session = session_data
        self.replies = replies
        self.fake_data = fake_data
        self.breakdown = {}
        self.total = 0.0

    def score_all(self) -> float:
        self._score_detection()
        self._score_intelligence()
        self._score_conversation_quality()
        self._score_engagement_quality()
        self._score_response_structure()
        return round(self.total, 2)

    # ---- 1. Scam Detection (20 pts) ----
    def _score_detection(self):
        pts = 20 if self.session.get("scam_detected") else 0
        self.breakdown["Scam Detection"] = {"score": pts, "max": 20}
        self.total += pts

    # ---- 2. Intelligence Extraction (30 pts, dynamic) ----
    def _score_intelligence(self):
        intel = self.session.get("intelligence", {})
        total_fake_fields = sum(len(v) for v in self.fake_data.values())
        if total_fake_fields == 0:
            self.breakdown["Intelligence"] = {"score": 0, "max": 30, "detail": "no fake data"}
            return

        points_per_item = 30.0 / total_fake_fields
        found_count = 0
        detail = {}

        for field, expected_vals in self.fake_data.items():
            actual = intel.get(field, [])
            for val in expected_vals:
                digits = val.replace("-", "").replace(" ", "")
                matched = any(val in item or digits in item.replace("-","").replace(" ","")
                              for item in actual)
                if matched:
                    found_count += 1
                detail[val] = "OK" if matched else "MISS"

        pts = min(30.0, round(found_count * points_per_item, 2))
        self.breakdown["Intelligence"] = {
            "score": pts, "max": 30,
            "found": f"{found_count}/{total_fake_fields}",
            "per_item": round(points_per_item, 2),
            "detail": detail,
        }
        self.total += pts

    # ---- 3. Conversation Quality (30 pts) ----
    def _score_conversation_quality(self):
        turns = len(self.replies)

        # Turn Count (8 pts): >=8=8, >=6=6, >=4=3, else 0
        if turns >= 8: turn_pts = 8
        elif turns >= 6: turn_pts = 6
        elif turns >= 4: turn_pts = 3
        else: turn_pts = 0

        # Questions Asked (4 pts): >=5=4, >=3=2, >=1=1
        q_count = sum(1 for r in self.replies if "?" in r)
        if q_count >= 5: q_pts = 4
        elif q_count >= 3: q_pts = 2
        elif q_count >= 1: q_pts = 1
        else: q_pts = 0

        # Relevant / Investigative Questions (3 pts): >=3=3, >=2=2, >=1=1
        inv_kw = ["employee", "badge", "website", "branch", "supervisor",
                   "company", "department", "toll-free", "official", "id",
                   "identity", "address", "office", "designation",
                   "name", "organization", "registration", "license",
                   "credential", "headquarter", "location"]
        inv_count = sum(1 for r in self.replies
                        if any(kw in r.lower() for kw in inv_kw))
        if inv_count >= 3: inv_pts = 3
        elif inv_count >= 2: inv_pts = 2
        elif inv_count >= 1: inv_pts = 1
        else: inv_pts = 0

        # Red Flag Identification (8 pts): >=5=8, >=3=5, >=1=2
        rf_kw = ["suspicious", "doubt", "fraud", "scam", "never share", "otp",
                 "urgent", "pressure", "strange", "real bank", "verify",
                 "red flag", "fee", "trust", "careful", "warning", "fake",
                 "dangerous", "legitimate", "genuine", "phishing",
                 "too good", "not real", "deceptive", "unbelievable",
                 "questionable", "concerned", "worried", "scared",
                 "skeptical", "unsure", "confused", "fishy"]
        rf_count = sum(1 for r in self.replies
                       if any(kw in r.lower() for kw in rf_kw))
        if rf_count >= 5: rf_pts = 8
        elif rf_count >= 3: rf_pts = 5
        elif rf_count >= 1: rf_pts = 2
        else: rf_pts = 0

        # Information Elicitation (7 pts): each attempt = 1.5 pts, max 7
        el_kw = ["account", "upi", "phone", "call", "email", "link",
                 "website", "case number", "reference", "employee id",
                 "send", "transfer", "name", "address", "number",
                 "detail", "proof", "document", "receipt", "evidence"]
        el_count = sum(1 for r in self.replies
                       if any(kw in r.lower() for kw in el_kw))
        el_pts = min(7.0, round(el_count * 1.5, 1))

        subtotal = turn_pts + q_pts + inv_pts + rf_pts + el_pts
        self.breakdown["Conversation Quality"] = {
            "score": subtotal, "max": 30,
            "turns": f"{turns} ({turn_pts}pts)",
            "questions": f"{q_count} ({q_pts}pts)",
            "investigative": f"{inv_count} ({inv_pts}pts)",
            "red_flags": f"{rf_count} ({rf_pts}pts)",
            "elicitation": f"{el_count} ({el_pts}pts)",
        }
        self.total += subtotal

    # ---- 4. Engagement Quality (10 pts) ----
    def _score_engagement_quality(self):
        msgs = self.session.get("messages_exchanged", 0)

        # Duration: >0s = 1pt, >60s = 2pts, >180s = 1pt
        # In local tests we estimate duration from turn count
        estimated_duration = msgs * 3  # ~3s per turn in tests
        dur_pts = 0
        if estimated_duration > 0: dur_pts += 1
        if estimated_duration > 60: dur_pts += 2
        if estimated_duration > 180: dur_pts += 1

        # Messages: >0 = 2pts, >=5 = 3pts, >=10 = 1pt
        msg_pts = 0
        if msgs > 0: msg_pts += 2
        if msgs >= 5: msg_pts += 3
        if msgs >= 10: msg_pts += 1

        subtotal = dur_pts + msg_pts
        self.breakdown["Engagement Quality"] = {
            "score": subtotal, "max": 10,
            "messages": msgs,
            "est_duration": f"{estimated_duration}s",
            "note": "real eval uses actual wall-clock duration",
        }
        self.total += subtotal

    # ---- 5. Response Structure (10 pts) ----
    def _score_response_structure(self):
        # Required (2 pts each, -1 penalty if missing):
        #   sessionId, scamDetected, extractedIntelligence
        # Optional (1 pt each):
        #   totalMessagesExchanged+engagementDurationSeconds, agentNotes, scamType, confidenceLevel
        from app.models.schemas import FinalResultPayload
        sample = FinalResultPayload(
            sessionId="check", scamDetected=True, totalMessagesExchanged=5,
            engagementDurationSeconds=60, extractedIntelligence={},
            agentNotes="test", scamType="unknown", confidenceLevel=0.5,
        )
        data = sample.model_dump()

        pts = 0
        detail = {}
        # Required fields
        for field, score in [("sessionId", 2), ("scamDetected", 2), ("extractedIntelligence", 2)]:
            if field in data:
                pts += score
                detail[field] = f"+{score}"
            else:
                pts -= 1  # penalty
                detail[field] = "-1 (MISSING!)"

        # Optional fields
        if "totalMessagesExchanged" in data and "engagementDurationSeconds" in data:
            pts += 1; detail["metrics"] = "+1"
        else:
            detail["metrics"] = "0 (MISSING)"

        for field in ["agentNotes", "scamType", "confidenceLevel"]:
            if field in data:
                pts += 1; detail[field] = "+1"
            else:
                detail[field] = "0 (MISSING)"

        self.breakdown["Response Structure"] = {"score": pts, "max": 10, "detail": detail}
        self.total += pts

    def report(self) -> str:
        lines = []
        for cat, info in self.breakdown.items():
            score = info["score"] if isinstance(info, dict) else info
            max_pts = info["max"] if isinstance(info, dict) else "?"
            lines.append(f"    {cat:<25} {score:>6}/{max_pts}")
            if isinstance(info, dict):
                for k, v in info.items():
                    if k not in ("score", "max"):
                        lines.append(f"      {k}: {v}")
        lines.append(f"    {'SCENARIO TOTAL':<25} {self.total:>6}/100")
        return "\n".join(lines)


# ===========================================================================
#  4. CLI RUNNER -- runs all 15 scenarios, computes FINAL SCORE
# ===========================================================================

def main():
    """Run all 15 scam scenarios and compute the final hackathon score."""
    print("=" * 64)
    print("  ScamTrace Agent - Official Evaluation Simulation")
    print("  Based on: Honeypot API Evaluation System Documentation")
    print("=" * 64)
    print(f"  Server:     {BASE_URL}")
    print(f"  Scenarios:  {len(SCENARIOS)}")
    print(f"  Time:       {datetime.now().isoformat()}")
    print()

    client = httpx.Client()

    # Health check
    try:
        r = client.get(f"{BASE_URL}/health", timeout=5)
        assert r.status_code == 200
        print("  [OK] Server is healthy")
    except Exception as e:
        print(f"  [FAIL] Cannot reach server: {e}")
        print("  Start server: python -m uvicorn app.main:app --port 8000")
        sys.exit(1)

    # Check response format
    print("  [..] Checking response format...")
    check_id = f"format-check-{int(time.time())}"
    check_resp = _send_message(check_id, "Testing endpoint", client)
    if check_resp.get("status") == "success":
        print("  [OK] Response format: status='success'")
    else:
        print(f"  [!!] Response format issue: {check_resp}")
    print()

    scenario_scores = {}
    total_weight = sum(s["weight"] for s in SCENARIOS.values())
    slow_turns = 0
    total_turns = 0

    for scenario_key, scenario in SCENARIOS.items():
        session_id = f"eval-{scenario_key}-{int(time.time())}"
        print("-" * 64)
        print(f"  [{scenario_key}] {scenario['description']} (weight: {scenario['weight']})")
        print(f"  Session: {session_id}")

        replies = []
        history = []
        extended_messages = list(scenario["messages"])
        extended_messages.extend([
            "Why are you asking so many questions? Just do what I said.",
            "Hurry up, I don't have all day to wait for you.",
            "If you don't do this immediately, you will be in big trouble.",
            "Are you doing it or not? Stop wasting time.",
            "Send me the confirmation immediately."
        ])
        for i, msg in enumerate(extended_messages, 1):
            total_turns += 1
            start = time.time()
            resp = _send_message(session_id, msg, client, conversation_history=history)
            elapsed = time.time() - start

            reply = resp.get("reply", resp.get("message", resp.get("text", "NO_REPLY")))
            replies.append(reply)

            # Build conversation history for next turn (like the real evaluator)
            history.append({"sender": "scammer", "text": msg, "timestamp": str(int(time.time() * 1000))})
            history.append({"sender": "user", "text": reply, "timestamp": str(int(time.time() * 1000))})

            status_icon = "!!" if elapsed > 25 else "OK"
            if elapsed > 25:
                slow_turns += 1
            print(f"    Turn {i}: {elapsed:.1f}s [{status_icon}] -> {reply[:80]}...")
            time.sleep(0.5)

        session_data = _get_session(session_id, client)

        # Print extracted intelligence
        intel = session_data.get("intelligence", {})
        extracted_types = [f for f in intel if intel.get(f)]
        print(f"    Extracted: {', '.join(extracted_types) if extracted_types else 'NONE'}")

        # Score
        scorer = OfficialRubricScorer(session_data, replies, scenario["fake_data"])
        score = scorer.score_all()
        print(scorer.report())
        scenario_scores[scenario_key] = {
            "score": score,
            "weight": scenario["weight"],
        }
        print()

    # ---- FINAL SCORE CALCULATION ----
    # Formula: Scenario Score = SUM(Scenario_Score * Scenario_Weight / total_weight)
    # Final Score = (Scenario Score * 0.9) + Code Quality Score
    print("=" * 64)
    print("  SCENARIO RESULTS")
    print("=" * 64)
    weighted_sum = 0
    for key, data in scenario_scores.items():
        pct = data["weight"] / total_weight * 100
        contribution = data["score"] * data["weight"] / total_weight
        weighted_sum += contribution
        bar_len = int(data["score"] / 5)
        bar = "#" * bar_len + "." * (20 - bar_len)
        print(f"  {key:<20} {data['score']:>5.1f}/100  w={pct:>4.1f}%  [{bar}]")

    print()
    print("-" * 64)
    print(f"  Weighted Scenario Score:   {weighted_sum:>6.2f} / 100")
    scenario_portion = weighted_sum * 0.9
    print(f"  Scenario Portion (x0.9):   {scenario_portion:>6.2f} / 90")

    # Code quality is 10 pts manual review -- estimate based on structure
    code_quality_est = 8  # assume good since we have proper structure, README, etc.
    print(f"  Code Quality (estimated):  {code_quality_est:>6} / 10")

    final_score = scenario_portion + code_quality_est
    print()
    print("=" * 64)
    print(f"  ESTIMATED FINAL SCORE:     {final_score:>6.2f} / 100")
    print("=" * 64)

    # Warnings
    print()
    if slow_turns > 0:
        print(f"  [!!] WARNING: {slow_turns}/{total_turns} turns exceeded 25s (platform limit: 30s)")

    # Check engagementMetrics structure
    from app.models.schemas import FinalResultPayload
    sample = FinalResultPayload(
        sessionId="x", scamDetected=True, totalMessagesExchanged=5,
        engagementDurationSeconds=60, extractedIntelligence={}, agentNotes="x",
    )
    data = sample.model_dump()
    if "engagementMetrics" not in data:
        print("  [!!] NOTE: FinalResultPayload has engagementDurationSeconds at top level.")
        print("       Official doc shows it at top level too — this is correct.")

    # Verify callback fires every turn
    from app.services.callback import should_send_callback
    from app.models.schemas import SessionState
    s = SessionState(session_id="cb-check")
    s.scam_detected = True
    s.messages_exchanged = 1
    if should_send_callback(s):
        print("  [OK] Callback fires on every scam-detected turn")
    else:
        print("  [!!] WARNING: Callback not firing on first turn! Evaluator may miss final output.")

    # Verify agentNotes is string
    if isinstance(data.get("agentNotes"), str):
        print("  [OK] agentNotes is a string (matches official doc)")
    else:
        print(f"  [!!] WARNING: agentNotes is {type(data.get('agentNotes'))}, should be str")

    print()
    client.close()
    return final_score


if __name__ == "__main__":
    import io
    
    # Capture the output to write to file
    class TeeHelper:
        def __init__(self, stream1, stream2):
            self.stream1 = stream1
            self.stream2 = stream2
            
        def write(self, data):
            self.stream1.write(data)
            self.stream2.write(data)
            self.stream1.flush()
            self.stream2.flush()
            
        def flush(self):
            self.stream1.flush()
            self.stream2.flush()

    import os
    os.makedirs("test_result", exist_ok=True)
    
    # Setup Tee
    original_stdout = sys.stdout
    with open(os.path.join("test_result", "test_results_latest.txt"), "w", encoding="utf-8") as f:
        sys.stdout = TeeHelper(original_stdout, f)
        try:
            score = main()
        finally:
            sys.stdout = original_stdout
            
    sys.exit(0 if score >= 70 else 1)
