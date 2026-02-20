"""
Detection Orchestrator: Coordinates the 3-tier scam detection system.
"""

from dataclasses import dataclass, field
from typing import Optional

from app.core.config import get_settings
from app.detection import rules
from app.detection import ml_classifier
from app.detection import llm_detector


@dataclass
class DetectionResult:
    """Final result from the detection system."""
    is_scam: bool
    confidence: float
    tier: str
    indicators: list[str] = field(default_factory=list)
    reasoning: Optional[str] = None


def _build_combined_text(message: str, history: list[dict] | None) -> str:
    """
    Join the most recent scammer messages with the current message into one
    string so Rules/ML can detect spread-out multi-turn signals.
    Up to 4 recent scammer turns + current are combined.
    """
    if not history:
        return message
    scammer_texts = [
        h["text"] for h in history
        if isinstance(h, dict) and h.get("sender", "").lower() == "scammer"
        and h.get("text", "").strip()
    ][-4:]  # last 4 scammer messages
    parts = scammer_texts + [message]
    return " ".join(parts)


async def detect(
    message: str,
    history: list[dict] = None,
    accumulated_score: float = 0.0,
    accumulated_indicators: list[str] = None
) -> DetectionResult:
    """
    Detect if a message is a scam using the 3-tier system.
    
    Tier 0: Accumulated signals — if cross-turn score already high, lock result.
    Tier 1: Rule-based (fast, free) — run on BOTH current message and combined history.
    Tier 2: ML classifier (fast, free).
    Tier 3: LLM confirmation (slower, costs tokens).
    """
    settings = get_settings()
    accumulated_indicators = accumulated_indicators or []

    # ── Tier 0: Cross-turn accumulation ──────────────────────────────────────
    # If previous turns have collectively built up enough signal, trust it now.
    if accumulated_score >= 0.75:
        return DetectionResult(
            is_scam=True,
            confidence=min(accumulated_score, 0.99),
            tier="accumulated",
            indicators=accumulated_indicators,
            reasoning="Cumulative scam signals across multiple turns exceeded threshold"
        )

    # ── Tier 1: Rule-based ───────────────────────────────────────────────────
    # Analyse BOTH the current message alone and the combined conversation.
    # Using the higher of the two scores catches spread-out multi-turn attacks.
    rule_current = rules.analyze(message)
    combined_text = _build_combined_text(message, history)
    rule_combined = rules.analyze(combined_text) if combined_text != message else rule_current

    # Best score wins; merge indicators
    if rule_combined.score > rule_current.score:
        best_rule_score = rule_combined.score
        best_rule_indicators = list({i for i in rule_combined.indicators + rule_current.indicators})
    else:
        best_rule_score = rule_current.score
        best_rule_indicators = rule_current.indicators

    if best_rule_score >= settings.rule_high_threshold:
        return DetectionResult(
            is_scam=True,
            confidence=best_rule_score,
            tier="rules",
            indicators=best_rule_indicators,
            reasoning="High-confidence scam indicators detected by rules"
        )

    if best_rule_score < settings.rule_low_threshold and accumulated_score < 0.3:
        # Only mark safe if accumulated suspicion is also low
        return DetectionResult(
            is_scam=False,
            confidence=1 - best_rule_score,
            tier="rules",
            indicators=best_rule_indicators,
            reasoning="No significant scam indicators detected"
        )

    # ── Tier 2: ML ───────────────────────────────────────────────────────────
    # Run ML on both current message and combined text; take the higher score.
    ml_current = ml_classifier.predict(message)
    ml_combined = ml_classifier.predict(combined_text) if combined_text != message else ml_current
    ml_result = ml_current if ml_current.score >= ml_combined.score else ml_combined
    combined_indicators = best_rule_indicators.copy()

    if ml_result.score >= settings.ml_high_threshold:
        return DetectionResult(
            is_scam=True,
            confidence=ml_result.score,
            tier="ml",
            indicators=combined_indicators,
            reasoning=f"ML classifier confident (score: {ml_result.score:.2f})"
        )

    if ml_result.score < settings.ml_low_threshold and accumulated_score < 0.3:
        return DetectionResult(
            is_scam=False,
            confidence=1 - ml_result.score,
            tier="ml",
            indicators=combined_indicators,
            reasoning=f"ML classifier indicates safe (score: {ml_result.score:.2f})"
        )

    # ── Tier 3: LLM ──────────────────────────────────────────────────────────
    llm_result = await llm_detector.analyze(message, history)

    return DetectionResult(
        is_scam=llm_result.is_scam,
        confidence=llm_result.confidence,
        tier="llm",
        indicators=combined_indicators,
        reasoning=llm_result.reasoning
    )


def get_tier_stats(result: DetectionResult) -> dict:
    """Get statistics about which tier was used."""
    tiers_checked = ["rules"]
    if result.tier in ["ml", "llm"]:
        tiers_checked.append("ml")
    if result.tier == "llm":
        tiers_checked.append("llm")

    cost_saved = {
        "accumulated": "100% (prior signals",
        "rules": "100% (no ML or LLM used)",
        "ml": "~$0.001 (no LLM used)",
        "llm": "$0 (LLM was required)"
    }

    return {
        "tier_used": result.tier,
        "tiers_checked": tiers_checked,
        "cost_saved": cost_saved.get(result.tier, "unknown")
    }
