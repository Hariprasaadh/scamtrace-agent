"""
Tier 2: ML-based scam detection using TF-IDF and Logistic Regression.
"""

import json
from pathlib import Path
from dataclasses import dataclass
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


@dataclass
class MLResult:
    """Result from ML classifier."""
    score: float
    prediction: int


MODEL_PATH = Path("models/scam_classifier.joblib")
DATA_PATH = Path("data/scam_training.json")

_pipeline: Pipeline = None


def _create_fallback_pipeline() -> Pipeline:
    """Create a fallback pipeline when no training data exists."""
    texts = [
        "Your account blocked share OTP immediately",
        "Congratulations you won lottery prize",
        "Hello how are you today",
        "Meeting scheduled for tomorrow",
    ]
    labels = [1, 1, 0, 0]
    
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_features=1000)),
        ('classifier', LogisticRegression(max_iter=500, random_state=42))
    ])
    pipeline.fit(texts, labels)
    return pipeline


def _train() -> Pipeline:
    """Train the classifier on the training data."""
    if not DATA_PATH.exists():
        return _create_fallback_pipeline()
    
    with open(DATA_PATH, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    texts = [item['text'] for item in data]
    labels = [item['label'] for item in data]
    
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=5000,
            min_df=1,
            max_df=0.95,
            lowercase=True,
            strip_accents='unicode'
        )),
        ('classifier', LogisticRegression(
            max_iter=1000,
            class_weight='balanced',
            random_state=42
        ))
    ])
    
    pipeline.fit(texts, labels)
    
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    
    return pipeline


def _load_or_train() -> Pipeline:
    """Load existing model or train a new one."""
    if MODEL_PATH.exists():
        try:
            return joblib.load(MODEL_PATH)
        except Exception:
            pass
    return _train()


def _get_pipeline() -> Pipeline:
    """Get or initialize the ML pipeline."""
    global _pipeline
    if _pipeline is None:
        _pipeline = _load_or_train()
    return _pipeline


def predict(text: str) -> MLResult:
    """Predict if a message is a scam."""
    pipeline = _get_pipeline()
    
    if pipeline is None:
        return MLResult(score=0.5, prediction=0)
    
    proba = pipeline.predict_proba([text])[0]
    scam_probability = proba[1] if len(proba) > 1 else proba[0]
    prediction = int(scam_probability >= 0.5)
    
    return MLResult(score=float(scam_probability), prediction=prediction)


def retrain() -> None:
    """Force retraining of the model."""
    global _pipeline
    _pipeline = _train()


def add_training_example(text: str, label: int) -> None:
    """Add a new training example and retrain."""
    if not DATA_PATH.exists():
        data = []
    else:
        with open(DATA_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
    
    data.append({"text": text, "label": label})
    
    with open(DATA_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    retrain()
