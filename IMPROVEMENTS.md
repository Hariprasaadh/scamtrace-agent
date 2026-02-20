# ScamTrace Agent — Improvement Report

## Overview

This document maps **every gap** in the current codebase against the new **Honeypot API Evaluation System** scoring rubric (100 points total). Items are prioritized by point impact.

---

## Scoring Breakdown vs Current State

| Category | Max Points | Current Est. | Gap |
|---|---|---|---|
| Scam Detection | 20 | ~20 | ✅ Solid |
| Extracted Intelligence | 30 | ~18 | ❌ Missing 4 data types |
| Conversation Quality | 30 | ~10 | ❌ Major tuning needed |
| Engagement Quality | 10 | ~4 | ❌ Missing duration field |
| Response Structure | 10 | ~6 | ❌ Missing 3 optional fields |
| **Total** | **100** | **~58** | **~42 pts recoverable** |

---

## 1. Extracted Intelligence — 30 Points

### Currently Extracted ✅
- Bank account numbers
- UPI IDs
- Phishing links
- Phone numbers
- Suspicious keywords

### Missing Extraction ❌

| Data Type | Points at Risk | File to Change |
|---|---|---|
| `emailAddresses` | Up to 10 pts per scenario | `extractor.py`, `schemas.py` |
| `caseIds` (e.g. "Ref #1234", "Case ID: XYZ-456") | Up to 10 pts per scenario | `extractor.py`, `schemas.py` |
| `policyNumbers` (e.g. "Policy: LIC-12345678") | Up to 10 pts per scenario | `extractor.py`, `schemas.py` |
| `orderNumbers` (e.g. "Order #AMZ-987654") | Up to 10 pts per scenario | `extractor.py`, `schemas.py` |

> **Note:** Points per item = 30 ÷ total fake data fields in scenario. Missing even one field loses significant points.

### Action Items
1. Add email regex pattern: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`
2. Add case/reference ID patterns: `(?:case|ref|reference|complaint)\s*(?:id|no|number|#)?\s*[:#]?\s*([A-Z0-9-]{4,})`
3. Add policy number patterns: `(?:policy|plan)\s*(?:no|number|#)?\s*[:#]?\s*([A-Z0-9-]{4,})`
4. Add order number patterns: `(?:order|booking)\s*(?:id|no|number|#)?\s*[:#]?\s*([A-Z0-9-]{4,})`
5. Update `ExtractedIntelligence` schema to include new fields
6. Update `callback.py` to include new fields in payload

---

## 2. Conversation Quality — 30 Points (Biggest Improvement Area)

### Turn Count — 8 Points

| Current | Required | Status |
|---|---|---|
| `max_conversation_messages = 7` | ≥8 turns for full 8 pts | ❌ **Capped too low** |

**Fix:** Change `max_conversation_messages` in `config.py` from `7` to `12`.

### Questions Asked — 4 Points

| Current | Required | Status |
|---|---|---|
| Agent sometimes asks questions | ≥5 questions for full 4 pts | ⚠️ Not guaranteed |

**Fix:** Add to `BASE_INSTRUCTIONS` in `personas.py`:
```
MANDATORY: Every reply MUST end with a question. Examples:
- "What number should I call you back on?"
- "Can you send me the link again?"
- "What is your employee ID sir?"
```

### Relevant/Investigative Questions — 3 Points

| Current | Required | Status |
|---|---|---|
| Questions are generic | ≥3 investigative questions about identity/company/address | ⚠️ Weak |

**Fix:** Add specific investigative prompts to `BASE_INSTRUCTIONS`:
```
Ask investigative questions like:
- "Which branch are you calling from?"
- "What is your name and designation?"
- "Can I visit your website to check?"
- "What is the reference number for this case?"
```

### Red Flag Identification — 8 Points

| Current | Required | Status |
|---|---|---|
| Agent plays dumb without referencing concerns | ≥5 red flag mentions for 8 pts | ❌ Not implemented |

**Fix:** Instruct agent to subtly reference concerns:
```
Occasionally express mild concern about:
- "This seems very urgent, is everything okay?"
- "Why do you need my OTP? My bank said never to share."
- "This link looks different from the bank website..."
- "Why is there a fee to claim a refund?"
- "I've heard about scams like this on TV..."
```

### Information Elicitation — 7 Points

| Current | Required | Status |
|---|---|---|
| `_build_goal_prompt()` asks for bank/UPI/link/phone | Need more probing attempts (1.5 pts each, max 7) | ⚠️ Needs expansion |

**Fix:** Expand `_build_goal_prompt()` in `agent.py` to also ask for:
- Email address ("Can you email me the details?")
- Case/reference ID ("What is the case number?")
- Company/org name ("Which department are you from?")
- Website URL ("Where can I check this online?")
- Callback phone number ("What number should I call?")

---

## 3. Engagement Quality — 10 Points

### Missing: `engagementDurationSeconds`

| Field | Status | Points |
|---|---|---|
| `engagementDurationSeconds` | ❌ Not tracked | 4 pts |
| `totalMessagesExchanged` | ✅ Tracked | 6 pts |

**Fix:**
1. `SessionState` already has `created_at` — calculate duration as `now - created_at` in seconds
2. Add `engagementDurationSeconds` to `FinalResultPayload` in `schemas.py`
3. Calculate and include in `callback.py` `_build_payload()`

### Message Count Threshold

| Current | Required | Points |
|---|---|---|
| Capped at 7 | ≥10 messages for full 1 pt bonus | ⚠️ |

**Fix:** Already addressed by raising `max_conversation_messages` to 12.

---

## 4. Response Structure — 10 Points

### Currently Present ✅
| Field | Points | Status |
|---|---|---|
| `sessionId` | 2 pts | ✅ |
| `scamDetected` | 2 pts | ✅ |
| `extractedIntelligence` | 2 pts | ✅ |
| `totalMessagesExchanged` | 0.5 pt | ✅ |
| `agentNotes` | 1 pt | ✅ |

### Missing ❌
| Field | Points | Fix |
|---|---|---|
| `engagementDurationSeconds` | 0.5 pt | `schemas.py`, `callback.py` — calculate from session timestamps |
| `scamType` | 1 pt | `schemas.py`, `callback.py` — infer from detection indicators (e.g. "bank_fraud", "upi_fraud", "phishing") |
| `confidenceLevel` | 1 pt | `schemas.py`, `callback.py` — use `detection_result.confidence` |

---

## 5. Scam Detection — 20 Points

| Aspect | Status | Notes |
|---|---|---|
| 3-tier detection (rules → ML → LLM) | ✅ Solid | Works well |
| First-message detection | ✅ | Most scam messages trigger Tier 1 |
| Edge-case handling | ⚠️ | Consider lowering ML threshold slightly for borderline cases |

**No major changes needed.** Minor tweak: ensure `scamDetected: true` is always set in the final callback payload (it currently is).

---

## 6. Callback Timing — CRITICAL

### Current Behavior
- Callback sent **only once**, after `messages_exchanged >= 7`
- If conversation ends before 7 messages → **callback never fires** → **0 points**

### Required Behavior
- Evaluator waits **10 seconds after last turn** for final output
- Up to **10 turns** max

### Fix
**Strategy: Send callback on EVERY turn after scam is detected** (overwrite previous submission with latest cumulative intelligence). This ensures:
- Even short conversations get scored
- Later turns include more extracted data
- No risk of missing the submission window

**Files to change:** `callback.py` → remove the "only send once" check; `main.py` → trigger callback after every scam-detected turn.

---

## 7. API Robustness

| Issue | Risk | Fix |
|---|---|---|
| `timestamp` format — docs show both ISO string AND epoch ms | Request parsing failure | `schemas.py` → ensure `MessageInput.timestamp` accepts both `str` and `int` |
| Groq API slow response | 30-second timeout → 0 pts for that turn | `agent.py` → add 15s timeout to LLM call, fall back immediately |
| Large conversation history | Context overflow | Already handled with truncation ✅ |

---

## 8. Files to Modify (Summary)

| File | Changes |
|---|---|
| `app/models/schemas.py` | Add `emailAddresses`, `caseIds`, `policyNumbers`, `orderNumbers` to `ExtractedIntelligence`; add `engagementDurationSeconds`, `scamType`, `confidenceLevel` to `FinalResultPayload`; fix timestamp type |
| `app/services/extractor.py` | Add regex patterns for emails, case IDs, policy numbers, order numbers |
| `app/services/personas.py` | Rewrite `BASE_INSTRUCTIONS` to mandate questions, red flag mentions, and investigative probing |
| `app/services/agent.py` | Expand `_build_goal_prompt()` with more elicitation targets; add LLM timeout |
| `app/services/callback.py` | Calculate `engagementDurationSeconds`; include `scamType` and `confidenceLevel`; send callback on every turn (not just once) |
| `app/core/config.py` | Increase `max_conversation_messages` to 12 |
| `app/main.py` | Trigger callback on every scam turn, not just at cap |

---

## Priority Order for Implementation

1. 🔴 **CRITICAL** — Increase `max_conversation_messages` to 12 *(lose 8+ pts)*
2. 🔴 **CRITICAL** — Add email/caseId/policy/order extraction *(lose up to 30 pts)*
3. 🔴 **CRITICAL** — Send callback on every turn after detection *(lose ALL pts if missed)*
4. 🔴 **CRITICAL** — Add `engagementDurationSeconds`, `scamType`, `confidenceLevel` *(lose 3 pts)*
5. 🟠 **HIGH** — Rewrite persona prompts: always ask questions, reference red flags, probe for info *(lose up to 22 pts)*
6. 🟠 **HIGH** — Expand `_build_goal_prompt()` elicitation targets *(lose 7 pts)*
7. 🟡 **MEDIUM** — Handle timestamp format flexibility
8. 🟡 **MEDIUM** — Add LLM call timeout (15s)
9. 🟢 **LOW** — Better `agentNotes` summarization
