"""FastAPI router and endpoints for PromptShield X."""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional, Dict, Any

from backend.app.schemas import (
    InspectRequest, InspectResponse,
    ActionCheckRequest, ActionCheckResponse,
    AssistantRunRequest, AssistantRunResponse,
    ReviewActionRequest, PolicyUpdateRequest,
    PolicyConfigResponse, PolicyItem,
    EscalateIncidentRequest, EscalateIncidentResponse,
    GeminiVerifyRequest, GeminiVerificationResult, GeminiConfigUpdate,
    IncidentUpdateRequest, AuthorityStatsResponse
)
from backend.app.pipeline import run_inspection_pipeline
from backend.app.action_firewall import check_action
from backend.app.forwarding import run_assistant_for_inspection
from backend.app.review import process_review, get_pending_reviews
from backend.app.policy_engine import get_active_policies_list, get_active_settings
from backend.app.storage import (
    list_inspections, get_inspection,
    update_policy_settings, get_latest_evaluation,
    save_incident, list_incidents, update_incident,
    get_authority_prompts, get_authority_stats
)
from backend.app.gemini_verifier import verify_with_gemini, get_effective_gemini_api_key

router = APIRouter()

@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "PromptShield X Security Gateway",
        "engine": "offline-hybrid",
        "version": "2.1.0"
    }

@router.post("/inspect", response_model=InspectResponse)
def inspect_content(req: InspectRequest):
    try:
        return run_inspection_pipeline(req)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inspection pipeline failure: {str(e)}")

@router.get("/policies", response_model=PolicyConfigResponse)
def get_policies_endpoint():
    policies = get_active_policies_list()
    settings = get_active_settings()
    return PolicyConfigResponse(
        version=settings.get("policy_version", "v2.1"),
        last_updated="2026-10-11T00:00:00Z",
        policies=[PolicyItem(**p) for p in policies],
        settings=settings
    )

@router.put("/policies")
def update_policies_endpoint(req: PolicyUpdateRequest):
    # Untrusted content must never be able to modify policies
    try:
        update_policy_settings(req.settings)
        return {
            "status": "success",
            "message": "Security policy settings successfully updated.",
            "version": req.version
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update policies: {str(e)}")

@router.get("/history")
def get_history_endpoint(
    limit: int = Query(50, ge=1, le=200),
    search: Optional[str] = None,
    decision: Optional[str] = None
):
    return list_inspections(limit=limit, search=search, decision_filter=decision)

@router.get("/inspections/{inspection_id}")
def get_inspection_endpoint(inspection_id: str):
    record = get_inspection(inspection_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Inspection ID '{inspection_id}' not found.")
    return record

@router.get("/reviews")
def get_reviews_endpoint():
    return get_pending_reviews()

@router.post("/review")
def review_action_endpoint(req: ReviewActionRequest):
    try:
        result = process_review(
            inspection_id=req.inspection_id,
            reviewer=req.reviewer,
            action=req.action,
            notes=req.notes or ""
        )
        return result
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/assistant/run", response_model=AssistantRunResponse)
def assistant_run_endpoint(req: AssistantRunRequest):
    result = run_assistant_for_inspection(req.inspection_id, req.task)
    return AssistantRunResponse(**result)

@router.post("/actions/check", response_model=ActionCheckResponse)
def actions_check_endpoint(req: ActionCheckRequest):
    result = check_action(
        tool_name=req.tool_name,
        tool_args=req.tool_args,
        inspection_id=req.inspection_id,
        authorized_task=req.authorized_task,
        target_destination=req.target_destination
    )
    return ActionCheckResponse(**result)

@router.get("/evaluation/latest")
def get_evaluation_endpoint():
    res = get_latest_evaluation()
    if not res:
        return {"status": "none", "message": "No evaluation results available."}
    return res

@router.post("/incidents/escalate", response_model=EscalateIncidentResponse)
def escalate_incident_endpoint(req: EscalateIncidentRequest):
    import uuid
    from datetime import datetime, timezone
    
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()
    
    incident_data = {
        "id": incident_id,
        "inspection_id": req.inspection_id,
        "person_name": req.person.name,
        "person_email": req.person.email,
        "person_id": req.person.employee_id,
        "person_department": req.person.department,
        "client_ip": req.person.client_ip,
        "client_workstation": req.person.workstation,
        "malicious_text": req.malicious_text,
        "violating_rules": req.violating_rules,
        "severity": req.severity,
        "complete_prompt": req.complete_prompt,
        "authorized_task": req.authorized_task,
        "decision": req.decision,
        "risk_priority": req.risk_priority,
        "higher_authority": req.higher_authority,
        "notes": req.notes,
        "status": "TRANSFERRED_FOR_INVESTIGATION",
        "created_at": timestamp
    }
    
    save_incident(incident_data)
    
    return EscalateIncidentResponse(
        success=True,
        incident_id=incident_id,
        status="TRANSFERRED_FOR_INVESTIGATION",
        transferred_to=req.higher_authority or "Chief Information Security Officer (CISO) & SecOps Incident Response",
        timestamp=timestamp,
        message=f"Incident {incident_id} successfully dispatched to {req.higher_authority}. User identity and complete prompt sealed for higher authority investigation.",
        dossier=incident_data
    )

@router.get("/incidents")
def get_incidents_endpoint(limit: int = Query(50, ge=1, le=100)):
    return list_incidents(limit=limit)

@router.post("/gemini/verify", response_model=GeminiVerificationResult)
def gemini_verify_endpoint(req: GeminiVerifyRequest):
    result = verify_with_gemini(
        content=req.content,
        task=req.task or "",
        api_key=req.api_key,
        allow_simulation=bool(req.allow_simulation)
    )
    return GeminiVerificationResult(**result)

@router.get("/gemini/config")
def gemini_config_endpoint():
    key = get_effective_gemini_api_key()
    has_key = bool(key and len(key) > 5)
    masked = f"{key[:4]}...{key[-4:]}" if has_key else None
    return {
        "has_api_key": has_key,
        "masked_key": masked,
        "model": "gemini-3.5-flash",
        "cloud_provider": "Google Generative AI (Gemini)"
    }

@router.post("/gemini/config")
def gemini_update_config_endpoint(req: GeminiConfigUpdate):
    if not req.api_key or not req.api_key.strip():
        raise HTTPException(status_code=400, detail="Gemini API Key cannot be empty.")
    update_policy_settings({"gemini_api_key": req.api_key.strip()})
    return {
        "status": "success",
        "message": "Gemini API key saved successfully.",
        "has_api_key": True
    }

@router.get("/authority/prompts")
def get_authority_prompts_endpoint(
    limit: int = Query(100, ge=1, le=200),
    department: Optional[str] = None,
    decision: Optional[str] = None,
    search: Optional[str] = None
):
    prompts = get_authority_prompts(limit=limit, department=department, decision=decision, search=search)
    stats = get_authority_stats()
    return {
        "prompts": prompts,
        "stats": stats
    }

@router.get("/authority/stats")
def get_authority_stats_endpoint():
    return get_authority_stats()

@router.patch("/incidents/{incident_id}")
def update_incident_endpoint(incident_id: str, req: IncidentUpdateRequest):
    updated = update_incident(
        incident_id,
        status=req.status,
        notes=req.notes,
        investigator=req.investigator
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return {
        "success": True,
        "incident": updated,
        "message": f"Incident {incident_id} successfully updated."
    }



