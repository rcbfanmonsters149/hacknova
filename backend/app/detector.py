"""Module C: Local Hybrid ML Classifier Detector.
Provides fast offline probability scores with zero heavy ML dependencies
for serverless deployment, handles graceful degradation,
and never directly authorizes forwarding on its own.
"""

import os
import json
import math
import re
import unicodedata
from typing import Dict, Any, Optional

MODEL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models"
)
LIGHTWEIGHT_MODEL_PATH = os.path.join(MODEL_DIR, "model_lightweight.json")
JOBLIB_MODEL_PATH = os.path.join(MODEL_DIR, "classifier.joblib")
META_PATH = os.path.join(MODEL_DIR, "metadata.json")

TOKEN_PATTERN = re.compile(r"(?u)\b\w\w+\b")

class MLClassifierDetector:
    def __init__(self):
        self.lightweight_model = None
        self.pipeline = None
        self.metadata = {
            "model_version": "v1.2-hybrid-offline",
            "status": "uninitialized"
        }
        self.load_model()

    def load_model(self):
        # 1. Prefer lightweight pure-Python model (zero dependencies, ~98KB, serverless-optimized)
        if os.path.exists(LIGHTWEIGHT_MODEL_PATH):
            try:
                with open(LIGHTWEIGHT_MODEL_PATH, "r", encoding="utf-8") as f:
                    self.lightweight_model = json.load(f)
                if os.path.exists(META_PATH):
                    with open(META_PATH, "r", encoding="utf-8") as mf:
                        self.metadata = json.load(mf)
                else:
                    self.metadata["status"] = "ready"
                return
            except Exception as e:
                self.lightweight_model = None

        # 2. Fallback to joblib pipeline if installed locally
        if os.path.exists(JOBLIB_MODEL_PATH):
            try:
                import joblib
                self.pipeline = joblib.load(JOBLIB_MODEL_PATH)
                if os.path.exists(META_PATH):
                    with open(META_PATH, "r", encoding="utf-8") as f:
                        self.metadata = json.load(f)
                else:
                    self.metadata["status"] = "ready"
                return
            except Exception as e:
                self.pipeline = None
                self.metadata["status"] = "degraded"
                self.metadata["error"] = str(e)
                return

        self.metadata["status"] = "model_not_found"

    def _predict_pure_python(self, text: str) -> float:
        """Computes exact TF-IDF + Logistic Regression probability using pure Python math."""
        # Strip unicode accents (matching sklearn strip_accents='unicode')
        norm_text = unicodedata.normalize("NFKD", text)
        norm_text = "".join(c for c in norm_text if not unicodedata.combining(c)).lower()

        tokens = TOKEN_PATTERN.findall(norm_text)
        if not tokens:
            z = self.lightweight_model["intercept"]
            return 1.0 / (1.0 + math.exp(-z))

        # Build unigrams + bigrams
        ngrams = list(tokens)
        for i in range(len(tokens) - 1):
            ngrams.append(f"{tokens[i]} {tokens[i+1]}")

        counts = {}
        for ng in ngrams:
            counts[ng] = counts.get(ng, 0) + 1

        terms = self.lightweight_model["terms"]

        # Sublinear TF: 1 + ln(count)
        tf_idf = {}
        for ng, cnt in counts.items():
            if ng in terms:
                tf = 1.0 + math.log(cnt)
                idf = terms[ng][0]
                tf_idf[ng] = tf * idf

        if not tf_idf:
            z = self.lightweight_model["intercept"]
        else:
            norm = math.sqrt(sum(v * v for v in tf_idf.values()))
            z = self.lightweight_model["intercept"]
            for ng, val in tf_idf.items():
                unit_val = val / norm
                coef = terms[ng][1]
                z += unit_val * coef

        return 1.0 / (1.0 + math.exp(-z))

    def predict(self, text: str, task: str = "", source_type: str = "User Prompt", force_degraded: bool = False) -> Dict[str, Any]:
        """Runs offline prediction. If degraded, enters conservative mode."""
        is_ready = (self.lightweight_model is not None or self.pipeline is not None) and self.metadata.get("status") == "ready"
        if force_degraded or not is_ready:
            # Conservative degraded mode: Does NOT assume text is benign!
            return {
                "attack_probability": 0.50,
                "predicted_label": 1,  # Treat with caution
                "confidence_level": "degraded_uncertain",
                "model_version": self.metadata.get("model_version", "v1.2-hybrid-offline"),
                "status": "degraded",
                "degraded_reason": "ML classifier unavailable or simulation active. Conservative fallback engaged."
            }

        try:
            if self.lightweight_model is not None:
                proba = self._predict_pure_python(text)
                label = 1 if proba >= 0.5 else 0
            else:
                proba = float(self.pipeline.predict_proba([text])[0][1])
                label = int(self.pipeline.predict([text])[0])

            confidence = "high" if (proba > 0.75 or proba < 0.25) else "moderate"

            return {
                "attack_probability": round(proba, 4),
                "predicted_label": label,
                "confidence_level": confidence,
                "model_version": self.metadata.get("model_version", "v1.2-hybrid-offline"),
                "status": "ready"
            }
        except Exception as e:
            # Fallback to conservative mode on runtime exception
            return {
                "attack_probability": 0.50,
                "predicted_label": 1,
                "confidence_level": "error_fallback",
                "model_version": self.metadata.get("model_version", "v1.2-hybrid-offline"),
                "status": "degraded",
                "degraded_reason": f"Inference exception: {str(e)}"
            }

_detector_instance = None

def get_detector() -> MLClassifierDetector:
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = MLClassifierDetector()
    return _detector_instance
