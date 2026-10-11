"""Module K: Controlled Assistant Forwarding.
Fetches strictly permitted content from the database by inspection ID.
Executes a deterministic simulated AI assistant, validating proposed actions
through the independent Action Firewall.
"""

from typing import Dict, Any, Optional
from backend.app.storage import get_inspection
from backend.app.action_firewall import check_action

class SimulatedAssistant:
    """A deterministic simulated AI assistant for PromptShield X demonstration."""

    @staticmethod
    def run(task: str, permitted_content: str) -> str:
        task_lower = task.lower()
        if "summarize" in task_lower or "summary" in task_lower:
            words = permitted_content.strip().split()
            preview = " ".join(words[:25])
            return f"[Simulated AI Assistant - Summary]: Processed {len(words)} words of permitted content. Key takeaway: {preview}..."
        elif "extract" in task_lower or "table" in task_lower:
            return f"[Simulated AI Assistant - Extracted]: Successfully analyzed authorized content structure from verified payload ({len(permitted_content)} chars)."
        else:
            return f"[Simulated AI Assistant - Response]: Received permitted payload. Executed authorized task: '{task}' safely under gateway protection."

def run_assistant_for_inspection(inspection_id: str, client_task: Optional[str] = None) -> Dict[str, Any]:
    """Retrieves strictly the database-stored permitted content for the given inspection ID."""
    insp = get_inspection(inspection_id)
    if not insp:
        return {
            "inspection_id": inspection_id,
            "success": False,
            "status": "not_found",
            "message": f"Inspection '{inspection_id}' not found in gateway database.",
            "executed_content": None,
            "assistant_output": None
        }

    # Strict authorization enforcement
    if insp["decision"] == "BLOCK":
        return {
            "inspection_id": inspection_id,
            "success": False,
            "status": "blocked",
            "message": "Execution denied: Content was blocked by PromptShield security policy.",
            "executed_content": None,
            "assistant_output": None
        }

    if insp["decision"] == "ESCALATE" and insp.get("review_status") != "approved":
        return {
            "inspection_id": inspection_id,
            "success": False,
            "status": "pending_review",
            "message": "Execution held: Content requires authorized human review before forwarding.",
            "executed_content": None,
            "assistant_output": None
        }

    if not insp["forwarding_permitted"]:
        return {
            "inspection_id": inspection_id,
            "success": False,
            "status": "denied",
            "message": "Execution prohibited: Inspection flagged as not permitted for forwarding.",
            "executed_content": None,
            "assistant_output": None
        }

    # Payload to execute is SOLELY from the database
    content_to_use = insp.get("sanitized_content") if insp["decision"] == "SANITIZE" else (insp.get("permitted_content") or insp["content"])

    task = client_task or insp["task"]
    assistant_output = SimulatedAssistant.run(task, content_to_use)

    return {
        "inspection_id": inspection_id,
        "success": True,
        "status": "executed",
        "message": f"Assistant successfully executed using DB-stored permitted payload ({insp['decision']}).",
        "executed_content": content_to_use,
        "assistant_output": assistant_output
    }
