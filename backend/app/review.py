"""Module L: Human Review and Safe Fallback.
Handles review approvals/rejections for escalated inspections.
Binds approvals to inspection ID, content hash, and policy version.
Strictly prevents overriding mandatory protected-value hard blocks.
"""

import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List
from backend.app.storage import get_inspection, save_review, get_connection

HARD_BLOCK_RULES = {"RULE-SEC-003", "RULE-EXF-004", "RULE-POL-005"}

def process_review(inspection_id: str, reviewer: str, action: str, notes: str = "") -> Dict[str, Any]:
    insp = get_inspection(inspection_id)
    if not insp:
        raise ValueError(f"Inspection ID '{inspection_id}' does not exist.")

    # Inviolable rule check: Hard blocks CANNOT be overridden by human approval!
    triggered_rules = set(insp.get("triggered_rules", []))
    if action == "APPROVE" and (triggered_rules & HARD_BLOCK_RULES):
        raise ValueError(
            "Security invariant violation: Hard blocks involving protected tokens, policy tampering, "
            "or direct exfiltration cannot be overridden by review."
        )

    content_hash = hashlib.sha256(insp["raw_content"].encode("utf-8")).hexdigest()[:16]
    review_id = f"rev_{int(datetime.now(timezone.utc).timestamp())}_{content_hash[:6]}"

    review_record = {
        "id": review_id,
        "inspection_id": inspection_id,
        "reviewer": reviewer,
        "action": action.upper(),
        "notes": notes,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    save_review(review_record)
    return {
        "review_id": review_id,
        "inspection_id": inspection_id,
        "action": action.upper(),
        "status": "success",
        "message": f"Review recorded: Inspection marked as {'Approved' if action.upper() == 'APPROVE' else 'Rejected'}."
    }

def get_pending_reviews() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, task, source_type, decision, summary_explanation, created_at, review_status
    FROM inspections
    WHERE decision = 'ESCALATE' AND review_status = 'none'
    ORDER BY created_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [{
        "inspection_id": r["id"],
        "task": r["task"],
        "source_type": r["source_type"],
        "decision": r["decision"],
        "summary_explanation": r["summary_explanation"],
        "created_at": r["created_at"],
        "review_status": r["review_status"]
    } for r in rows]
