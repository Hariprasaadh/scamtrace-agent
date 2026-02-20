# ScamTrace Agent 🛡️

AI-powered agentic honeypot API for scam detection and intelligence extraction. Built for the GUVI Hackathon — detects scam intent in real-time, autonomously engages scammers through believable personas, and extracts actionable fraud intelligence across multi-turn conversations.

## Description

ScamTrace Agent acts as an intelligent honeypot that:
- **Detects scams** using a cost-efficient 3-tier detection pipeline (Rules → ML → LLM)
- **Engages scammers** through dynamic victim personas to keep them talking
- **Extracts intelligence** — phone numbers, bank accounts, UPI IDs, phishing links, emails, case IDs, and more
- **Reports findings** automatically to the evaluation endpoint after every detected scam turn

The system is designed to be robust and generic — it handles any scam type without hardcoded responses, using pattern-based detection and LLM-powered conversation.

## Tech Stack

| Layer | Technology |
|---|---|
| **Framework** | FastAPI (Python 3.10+) |
| **LLM Provider** | Groq (LLaMA 3.3 70B Versatile) |
| **ML Classifier** | scikit-learn (TF-IDF + Logistic Regression) |
| **HTTP Client** | httpx (async) |
| **Validation** | Pydantic v2 |
| **Deployment** | Render / any HTTPS host |

## Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/Hariprasaadh/scamtrace-agent.git
cd scamtrace-agent
```

### 2. Install dependencies

```bash
python -m venv venv

# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Set environment variables

```bash
cp .env.example .env
```

Edit `.env` with your actual keys:

```env
API_KEY=your-api-key-here
GROQ_API_KEY=your-groq-api-key-here
GROQ_MODEL=llama-3.3-70b-versatile
GUVI_CALLBACK_URL=https://hackathon.guvi.in/api/updateHoneyPotFinalResult
```

Get a Groq API key at [console.groq.com](https://console.groq.com/).

### 4. Run the application

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Server will be live at `http://localhost:8000`. Interactive API docs at `/docs`.

## API Endpoint

- **URL**: `https://your-deployed-url.com/api/message`
- **Aliases**: `/detect`, `/honeypot` (same handler)
- **Method**: POST
- **Authentication**: `x-api-key` header (optional if not configured)

### Request Format

```json
{
  "sessionId": "uuid-v4-string",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your SBI account has been compromised. Share OTP immediately.",
    "timestamp": "2025-02-11T10:30:00Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

### Response Format

```json
{
  "status": "success",
  "reply": "Oh no, which account sir? I have SBI savings and current both..."
}
```

### Final Output (sent automatically to callback)

```json
{
  "sessionId": "abc123-session-id",
  "scamDetected": true,
  "totalMessagesExchanged": 8,
  "engagementDurationSeconds": 120,
  "extractedIntelligence": {
    "phoneNumbers": ["+91-9876543210"],
    "bankAccounts": ["1234567890123456"],
    "upiIds": ["scammer.fraud@fakebank"],
    "phishingLinks": ["http://malicious-site.com"],
    "emailAddresses": ["scammer@fake.com"]
  },
  "agentNotes": "[Detection] tier=rules scamDetected=True confidence=0.95 | [Intel] UPI ID(s): scammer.fraud@fakebank",
  "scamType": "bank_fraud",
  "confidenceLevel": 0.95
}
```

## Approach

### How We Detect Scams

The system uses a **3-tier cascading detection pipeline** that optimizes for both accuracy and cost:

1. **Tier 1 — Rule-Based** (~70% of messages, <10ms, free)
   - 50+ scam keyword patterns with weighted scoring
   - Urgency phrases, financial terms, impersonation signals
   - High confidence → immediately confirmed; low confidence → pass to Tier 2

2. **Tier 2 — ML Classifier** (~20% of messages, <50ms, free)
   - TF-IDF vectorizer + Logistic Regression trained on scam dataset
   - Handles ambiguous messages that rules can't confidently classify

3. **Tier 3 — LLM Confirmation** (~10% of messages, ~$0.001/msg)
   - Groq-hosted LLaMA 3.3 for final edge-case adjudication
   - Only invoked when Rules + ML disagree or are uncertain

4. **IOC Fallback** — If any hard intelligence artifact (UPI ID, bank account, phishing link) is found in a message, the system force-detects it as a scam even if the detection pipeline was uncertain.

### How We Extract Intelligence

Regex-based extraction engine that captures **8 intelligence types**:

| Data Type | Examples |
|---|---|
| 📞 Phone Numbers | `+91-9876543210`, `8001234567` |
| 🏦 Bank Accounts | `30045678901234`, `A/C 50100123456789` |
| 💳 UPI IDs | `scammer@oksbi`, `pay@ybl` |
| 🔗 Phishing Links | `https://sbi-verify.online`, `bit.ly/x` |
| 📧 Email Addresses | `fraud@cybercrime.gov.in` |
| 🆔 Case/Reference IDs | `FRD-2025-78901`, `FIR 1234/2025` |
| 📋 Policy Numbers | `LIC-INS-456789`, `POL-2025-001` |
| 📦 Order Numbers | `AMZ-ORD-112233`, `BKG-789012` |

Intelligence is extracted from **all messages** (scammer + agent quotes) and accumulated across the full conversation. After every scam-detected turn, the latest cumulative intelligence is pushed to the callback endpoint.

### How We Maintain Engagement

- **Dynamic Personas**: The agent selects a victim persona based on the scam type:
  - `elderly_victim` — confused, trusting, asks for help (bank/financial scams)
  - `desperate_youth` — eager but cautious (job/loan scams)
  - `tech_illiterate` — confused by technology (tech support/refund scams)
  - `default` — neutral, inquisitive

- **LLM-Powered Responses**: Groq LLaMA generates natural, contextual replies that:
  - Ask investigative questions (identity, organization, credentials)
  - Reference red flags without revealing detection
  - Probe for contact details and intelligence artifacts
  - Maintain conversation flow to maximize turn count

- **Progressive Callback**: The final output is sent on **every scam-detected turn** (fire-and-forget), ensuring the evaluator always has the latest intelligence regardless of when the conversation ends.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     API Layer (FastAPI)                      │
│            POST /api/message  /detect  /honeypot             │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  3-Tier Scam Detection                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ Tier 1:     │  │ Tier 2:     │  │ Tier 3:     │         │
│  │ Rules       │──▶│ ML (TF-IDF) │──▶│ LLM (Groq)  │         │
│  │ ~70% msgs   │  │ ~20% msgs   │  │ ~10% msgs   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                          + IOC Fallback                      │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              Honeypot Agent (if scam detected)               │
│  • Dynamic victim persona selection                          │
│  • LLM-powered natural conversation (Groq)                   │
│  • 8-type intelligence extraction (regex)                    │
│  • Multi-turn context tracking                               │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              GUVI Callback (fire-and-forget)                  │
│  Pushes latest finalOutput on every scam-detected turn       │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
scamtrace-agent/
├── app/
│   ├── main.py                 # FastAPI entry point + /api/message handler
│   ├── core/
│   │   ├── config.py           # Settings (Pydantic BaseSettings from .env)
│   │   └── session.py          # In-memory session management
│   ├── models/
│   │   └── schemas.py          # Pydantic models (RequestPayload, FinalResultPayload, etc.)
│   ├── detection/
│   │   ├── orchestrator.py     # 3-tier detection coordinator
│   │   ├── rules.py            # Tier 1: Rule-based keyword scoring
│   │   ├── ml_classifier.py    # Tier 2: TF-IDF + LogisticRegression
│   │   └── llm_detector.py     # Tier 3: LLM via Groq
│   └── services/
│       ├── agent.py            # LLM-powered honeypot agent (Groq)
│       ├── extractor.py        # Regex-based intelligence extraction (8 types)
│       ├── personas.py         # Dynamic victim persona selection
│       └── callback.py         # GUVI callback handler + payload builder
├── data/
│   └── scam_training.json      # Training data for ML classifier
├── models/                     # Trained ML model storage (.pkl files)
├── test_evaluation.py          # Comprehensive test suite (46 unit + integration tests)
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variables template
├── render.yaml                 # Render deployment config
├── Procfile                    # Process file for deployment
└── README.md
```

## Testing

### Unit Tests (no server required)

```bash
python -m pytest test_evaluation.py -k "unit" -v
```

Covers: extraction accuracy (all 8 types), detection precision, callback payload structure, persona selection, schema validation, and response time.

### Full Evaluation (requires running server)

```bash
# Terminal 1: Start server
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Run evaluation
python test_evaluation.py
```

Runs all 15 scam scenarios with the official rubric scoring:

| Category | Max Points |
|---|---|
| Scam Detection | 20 |
| Extracted Intelligence | 30 |
| Conversation Quality | 30 |
| Engagement Quality | 10 |
| Response Structure | 10 |

## Deployment

### Render (Recommended)

1. Push code to GitHub
2. Go to [Render Dashboard](https://dashboard.render.com/) → **New** → **Blueprint**
3. Connect your GitHub repo (auto-detects `render.yaml`)
4. Add environment variables: `API_KEY`, `GROQ_API_KEY`
5. Click **Apply** to deploy

Your API will be available at `https://scamtrace-agent.onrender.com/api/message`

### Any Platform

The only requirements are:
- Python 3.10+ runtime
- Environment variables set (see `.env.example`)
- Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `API_KEY` | Yes | API key for `x-api-key` header authentication |
| `GROQ_API_KEY` | Yes | Groq API key for LLM (detection + agent) |
| `GROQ_MODEL` | No | LLM model name (default: `llama-3.3-70b-versatile`) |
| `GUVI_CALLBACK_URL` | No | Callback endpoint for final results |
| `MAX_CONVERSATION_MESSAGES` | No | Max turns before canned reply (default: 10) |
| `SESSION_TTL_MINUTES` | No | Session expiry time (default: 30) |
