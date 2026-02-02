# ScamTrace Agent

An AI-powered agentic honeypot that detects scam intent, autonomously engages scammers, and extracts actionable fraud intelligence through multi-turn conversations.

## Features

- **3-Tier Scam Detection**: Cost-efficient detection using rules, ML, and LLM
  - Tier 1: Rule-based keyword/pattern matching (free, <10ms)
  - Tier 2: ML classifier with TF-IDF + Logistic Regression (free, <50ms)
  - Tier 3: LLM confirmation via Groq for edge cases (~10% of messages)
  
- **Intelligent Engagement**: LLM-powered agent with a believable victim persona
  - Maintains multi-turn conversations
  - Adapts responses based on scammer tactics
  - Never reveals detection

- **Intelligence Extraction**: Automatically extracts
  - Bank account numbers
  - UPI IDs
  - Phishing links
  - Phone numbers
  - Suspicious keywords

- **GUVI Integration**: Automatic callback to evaluation endpoint

## Quick Start

### Prerequisites

- Python 3.10+
- Groq API key ([Get one here](https://console.groq.com/))

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/scamtrace-agent.git
cd scamtrace-agent

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your settings
# Required: API_KEY, GROQ_API_KEY
```

### Running Locally

```bash
# Start the server
uvicorn app.main:app --reload --port 8000

# Server will be available at http://localhost:8000
# API docs at http://localhost:8000/docs
```

## API Usage

### Authentication

All requests require the `x-api-key` header:

```
x-api-key: your-secret-api-key
Content-Type: application/json
```

### Main Endpoint

**POST** `/api/message`

Process an incoming scam message and get a response.

#### Request Body

```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked. Share OTP immediately.",
    "timestamp": "2026-01-21T10:15:30Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

#### Response

```json
{
  "status": "success",
  "reply": "Which bank sir? I have SBI and HDFC both"
}
```

### Debug Endpoints

- **GET** `/api/session/{session_id}` - Get session information
- **POST** `/api/test/detect` - Test scam detection on a message
- **POST** `/api/test/extract` - Test intelligence extraction on a message

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     API Layer (FastAPI)                      │
│                    POST /api/message                         │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  3-Tier Scam Detection                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ Tier 1:     │  │ Tier 2:     │  │ Tier 3:     │         │
│  │ Rules       │─▶│ ML (TF-IDF) │─▶│ LLM (Groq)  │         │
│  │ ~70% msgs   │  │ ~20% msgs   │  │ ~10% msgs   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              Honeypot Agent (if scam detected)               │
│  • Victim persona (confused elderly person)                  │
│  • Extracts: bank accounts, UPI, links, phones              │
│  • Multi-turn conversation handling                          │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    GUVI Callback                             │
│  POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult│
└─────────────────────────────────────────────────────────────┘
```

## Deployment on Render

### Option 1: Using render.yaml (Recommended)

1. Push code to GitHub

2. Go to [Render Dashboard](https://dashboard.render.com/)

3. Click **New** → **Blueprint**

4. Connect your GitHub repository

5. Render will detect `render.yaml` and configure automatically

6. Add environment variables:
   - `API_KEY` - Your secret API key
   - `GROQ_API_KEY` - Your Groq API key

7. Click **Apply** to deploy

### Option 2: Manual Setup

1. Go to [Render Dashboard](https://dashboard.render.com/)

2. Click **New** → **Web Service**

3. Connect your GitHub repository

4. Configure:
   - **Runtime**: Python
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`

5. Add environment variables:
   - `API_KEY` - Your secret API key
   - `GROQ_API_KEY` - Your Groq API key
   - `GUVI_CALLBACK_URL` - `https://hackathon.guvi.in/api/updateHoneyPotFinalResult`

6. Click **Create Web Service**

Your API will be available at: `https://your-service-name.onrender.com`

## Project Structure

```
scamtrace-agent/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py           # Settings/configuration
│   │   └── session.py          # Session management
│   ├── models/
│   │   ├── __init__.py
│   │   └── schemas.py          # Pydantic models
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── orchestrator.py     # 3-tier coordinator
│   │   ├── rules.py            # Tier 1: Rule-based
│   │   ├── ml_classifier.py    # Tier 2: ML classifier
│   │   └── llm_detector.py     # Tier 3: LLM
│   └── services/
│       ├── __init__.py
│       ├── agent.py            # Honeypot agent
│       ├── extractor.py        # Intelligence extraction
│       └── callback.py         # GUVI callback handler
├── data/
│   └── scam_training.json      # Training data for ML
├── models/
│   └── .gitkeep                # Trained model storage
├── requirements.txt
├── Procfile
├── render.yaml                 # Render deployment config
├── .env.example
└── README.md
```

## Detection Thresholds

| Tier | High Confidence | Low Confidence | Action |
|------|-----------------|----------------|--------|
| Rules | >= 0.8 | < 0.3 | Scam confirmed / Safe |
| ML | >= 0.6 | < 0.4 | Scam confirmed / Safe |
| LLM | - | - | Final decision |

## Cost Optimization

By using the 3-tier approach:
- ~70% of messages resolved by rules (free)
- ~20% resolved by ML (free)
- ~10% need LLM (~$0.001/msg)

**Result**: ~90% cost reduction compared to LLM-only detection.

## License

MIT License

## Acknowledgments

Built for the GUVI Hackathon - Agentic Honey-Pot for Scam Detection & Intelligence Extraction.
