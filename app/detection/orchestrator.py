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


async def detect(message: str, history: list[dict] = None) -> DetectionResult:
    """
    Detect if a message is a scam using the 3-tier system.
    
    Tier 1: Rule-based (fast, free)
    Tier 2: ML classifier (fast, free)  
    Tier 3: LLM confirmation (slower, costs tokens)
    """
    settings = get_settings()
    
    # Tier 1: Rule-based detection
    rule_result = rules.analyze(message)
    
    if rule_result.score >= settings.rule_high_threshold:
        return DetectionResult(
            is_scam=True,
            confidence=rule_result.score,
            tier="rules",
            indicators=rule_result.indicators,
            reasoning="High-confidence scam indicators detected by rules"
        )
    
    if rule_result.score < settings.rule_low_threshold:
        return DetectionResult(
            is_scam=False,
            confidence=1 - rule_result.score,
            tier="rules",
            indicators=rule_result.indicators,
            reasoning="No significant scam indicators detected"
        )
    
    # Tier 2: ML classification
    ml_result = ml_classifier.predict(message)
    combined_indicators = rule_result.indicators.copy()
    
    if ml_result.score >= settings.ml_high_threshold:
        return DetectionResult(
            is_scam=True,
            confidence=ml_result.score,
            tier="ml",
            indicators=combined_indicators,
            reasoning=f"ML classifier confident (score: {ml_result.score:.2f})"
        )
    
    if ml_result.score < settings.ml_low_threshold:
        return DetectionResult(
            is_scam=False,
            confidence=1 - ml_result.score,
            tier="ml",
            indicators=combined_indicators,
            reasoning=f"ML classifier indicates safe (score: {ml_result.score:.2f})"
        )
    
    # Tier 3: LLM confirmation
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
        "rules": "100% (no ML or LLM used)",
        "ml": "~$0.001 (no LLM used)",
        "llm": "$0 (LLM was required)"
    }
    
    return {
        "tier_used": result.tier,
        "tiers_checked": tiers_checked,
        "cost_saved": cost_saved.get(result.tier, "unknown")
    }
