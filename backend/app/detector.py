"""Module C: Local Scikit-Learn TF-IDF + Logistic Regression Detector.
Provides offline probability scores, handles graceful degradation,
and never directly authorizes forwarding on its own.
"""

import os
import json
import joblib
from typing import Dict, Any, Optional

MODEL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models"
)
MODEL_PATH = os.path.join(MODEL_DIR, "classifier.joblib")
META_PATH = os.path.join(MODEL_DIR, "metadata.json")

class MLClassifierDetector:
    def __init__(self):
        self.pipeline = None
        self.metadata = {
            "model_version": "v1.2-hybrid-offline",
            "status": "uninitialized"
        }
        self.load_model()

    def load_model(self):
        if os.path.exists(MODEL_PATH):
            try:
                self.pipeline = joblib.load(MODEL_PATH)
                if os.path.exists(META_PATH):
                    with open(META_PATH, "r", encoding="utf-8") as f:
                        self.metadata = json.load(f)
                else:
                    self.metadata["status"] = "ready"
            except Exception as e:
                self.pipeline = None
                self.metadata["status"] = "degraded"
                self.metadata["error"] = str(e)
        else:
            self.pipeline = None
            self.metadata["status"] = "model_not_found"

    def predict(self, text: str, task: str = "", source_type: str = "User Prompt", force_degraded: bool = False) -> Dict[str, Any]:
        """Runs offline prediction. If degraded, enters conservative mode."""
        if force_degraded or self.pipeline is None or self.metadata.get("status") != "ready":
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
