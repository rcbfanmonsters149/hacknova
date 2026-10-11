"""Evaluation runner for PromptShield X.
Evaluates held-out dataset, calculates actual precision, recall, false positive rate,
average latency, and compares Rule-Only versus Hybrid Detection.
Stores results in the local SQLite database.
"""

import json
import os
import sys
import time

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.app.schemas import InspectRequest
from backend.app.pipeline import run_inspection_pipeline
from backend.app.rules import evaluate_rules
from backend.app.normalization import normalize_text
from backend.app.storage import save_evaluation, init_db

def run_evaluation():
    init_db()
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    eval_file = os.path.join(base_dir, "data", "evaluation_data.json")

    with open(eval_file, "r", encoding="utf-8") as f:
        test_cases = json.load(f)

    print(f"Loaded {len(test_cases)} held-out evaluation test cases.\n")

    latencies = []
    hybrid_results = []
    rule_only_results = []

    # 1. Evaluate Hybrid Detection (Full Pipeline)
    for tc in test_cases:
        req = InspectRequest(
            task=tc["task"],
            content=tc["text"],
            source_type=tc["source"]
        )

        t0 = time.time()
        resp = run_inspection_pipeline(req)
        lat = (time.time() - t0) * 1000.0
        latencies.append(lat)

        # Binary attack prediction: 1 if BLOCK or SANITIZE or ESCALATE, 0 if ALLOW
        predicted_attack = 1 if resp.decision in ["BLOCK", "SANITIZE", "ESCALATE"] else 0
        is_attack = tc["expected_label"] == 1

        hybrid_results.append({
            "id": tc["id"],
            "name": tc["name"],
            "attack_family": tc["attack_family"],
            "expected_decision": tc["expected_decision"],
            "actual_decision": resp.decision,
            "forwarding_permitted": resp.forwarding_permitted,
            "latency_ms": round(lat, 2),
            "expected_label": tc["expected_label"],
            "predicted_attack": predicted_attack,
            "passed_expected_decision": resp.decision == tc["expected_decision"]
        })

    # 2. Evaluate Rule-Only Detection (Baseline)
    for tc in test_cases:
        norm = normalize_text(tc["text"])
        rules = evaluate_rules(norm.normalized_text, norm.decoded_payloads)
        rule_attack = 1 if len(rules) > 0 else 0
        rule_only_results.append({
            "id": tc["id"],
            "expected_label": tc["expected_label"],
            "predicted_attack": rule_attack
        })

    # Calculate metrics for Hybrid Pipeline
    total = len(test_cases)
    tp = sum(1 for r in hybrid_results if r["expected_label"] == 1 and r["predicted_attack"] == 1)
    fn = sum(1 for r in hybrid_results if r["expected_label"] == 1 and r["predicted_attack"] == 0)
    fp = sum(1 for r in hybrid_results if r["expected_label"] == 0 and r["predicted_attack"] == 1 and r["actual_decision"] != "ESCALATE")
    tn = sum(1 for r in hybrid_results if r["expected_label"] == 0 and r["actual_decision"] == "ALLOW")
    held_reviews = sum(1 for r in hybrid_results if r["actual_decision"] == "ESCALATE")

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 1.0
    avg_latency = round(sum(latencies) / len(latencies), 2)

    # Calculate metrics for Rule-Only
    r_tp = sum(1 for r in rule_only_results if r["expected_label"] == 1 and r["predicted_attack"] == 1)
    r_fn = sum(1 for r in rule_only_results if r["expected_label"] == 1 and r["predicted_attack"] == 0)
    r_fp = sum(1 for r in rule_only_results if r["expected_label"] == 0 and r["predicted_attack"] == 1)
    r_tn = sum(1 for r in rule_only_results if r["expected_label"] == 0 and r["predicted_attack"] == 0)
    r_prec = round(r_tp / (r_tp + r_fp), 4) if (r_tp + r_fp) > 0 else 1.0
    r_rec = round(r_tp / (r_tp + r_fn), 4) if (r_tp + r_fn) > 0 else 1.0
    r_f1 = round(2 * (r_prec * r_rec) / (r_prec + r_rec), 4) if (r_prec + r_rec) > 0 else 0.0

    eval_payload = {
        "total_cases": total,
        "attacks_detected": tp,
        "missed_attacks": fn,
        "false_positives": fp,
        "correct_benign": tn,
        "reviews_held": held_reviews,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": fpr,
        "f1_score": f1,
        "average_latency_ms": avg_latency,
        "rule_only_metrics": {
            "precision": r_prec,
            "recall": r_rec,
            "f1_score": r_f1,
            "attacks_detected": r_tp,
            "missed_attacks": r_fn
        },
        "hybrid_metrics": {
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "attacks_detected": tp,
            "missed_attacks": fn
        },
        "test_cases": hybrid_results,
        "evaluated_at": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
    }

    save_evaluation(eval_payload)

    print("=======================================================")
    print("           PROMPTSHIELD X EVALUATION REPORT            ")
    print("=======================================================")
    print(f"Total Evaluated Test Cases : {total}")
    print(f"Correctly Detected Attacks : {tp}/{tp + fn}")
    print(f"Missed Attacks             : {fn}")
    print(f"False Positives (Benign)   : {fp}")
    print(f"Reviews Held for Escalate  : {held_reviews}")
    print(f"Hybrid Precision           : {precision * 100:.1f}%")
    print(f"Hybrid Recall              : {recall * 100:.1f}%")
    print(f"False Positive Rate        : {fpr * 100:.1f}%")
    print(f"F1 Score                   : {f1 * 100:.1f}%")
    print(f"Average Inspection Latency : {avg_latency} ms")
    print("-------------------------------------------------------")
    print(f"Rule-Only F1 Score         : {r_f1 * 100:.1f}%")
    print(f"Hybrid F1 Score            : {f1 * 100:.1f}% (+{(f1 - r_f1)*100:.1f}%)")
    print("=======================================================\n")

if __name__ == "__main__":
    run_evaluation()
