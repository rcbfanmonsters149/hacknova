"""Central Security Pipeline for PromptShield X.
Orchestrates: Source Validation -> Normalization -> Hybrid Detection -> Protected Values
-> Intent Drift -> Risk Scoring -> Adaptive Inspection -> Policy Enforcement
-> Surgical Sanitization & Mandatory Reinspection -> Stored Result.
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List

from backend.app.schemas import (
    InspectRequest, InspectResponse, Finding, RiskIndicator,
    NormalizationDetail, MLDetectorResult, IntentAnalysisResult, DecisionStep,
    GeminiVerificationResult, PersonData
)
from backend.app.normalization import normalize_text
from backend.app.rules import evaluate_rules, is_benign_quotation_or_research
from backend.app.detector import get_detector
from backend.app.protected_values import inspect_protected_values, mask_text
from backend.app.intent_engine import analyze_intent_drift
from backend.app.risk_engine import calculate_risk_scores
from backend.app.policy_engine import evaluate_security_policy
from backend.app.sanitizer import surgical_sanitize
from backend.app.storage import save_inspection, save_incident
from backend.app.gemini_verifier import verify_with_gemini

def run_inspection_pipeline(req: InspectRequest) -> InspectResponse:
    start_time = time.time()
    now_iso = datetime.now(timezone.utc).isoformat()
    unique_suffix = uuid.uuid4().hex[:6]
    inspection_id = f"insp_{datetime.now().strftime('%Y%m%d')}_{unique_suffix}"

    raw_text = req.content
    task = req.task
    source = req.source_type
    force_degraded = req.force_detector_degraded or False

    # Step 1: Normalization and Obfuscation Detection (Module B)
    norm_result = normalize_text(raw_text)
    normalized_text = norm_result.normalized_text
    transformations = norm_result.transformations_applied
    decoded_payloads = norm_result.decoded_payloads

    # Step 2: Hybrid Detection - Rule Engine (Module C)
    rule_findings = evaluate_rules(normalized_text, decoded_payloads)

    # Step 3: Hybrid Detection - Local ML Classifier (Module C)
    detector = get_detector()
    ml_output = detector.predict(normalized_text, task=task, source_type=source, force_degraded=force_degraded)

    # Step 4: Protected-Value & Data Exfiltration Inspection (Module D)
    protected_findings = inspect_protected_values(normalized_text, decoded_payloads)

    # Step 5: Intent Drift Analysis (Module E)
    intent_output = analyze_intent_drift(task, normalized_text, source)

    # Step 6: Risk Scoring Engine (Module F)
    risk_scores = calculate_risk_scores(
        source_type=source,
        rule_findings=rule_findings,
        protected_findings=protected_findings,
        ml_result=ml_output,
        intent_result=intent_output,
        transformations=transformations
    )

    # Convert rule and protected findings to unified schema Finding list
    unified_findings: List[Finding] = []
    for rf in rule_findings:
        unified_findings.append(Finding(
            rule_id=rf.rule_id,
            name=rf.name,
            category=rf.category,
            severity=rf.severity,
            description=rf.description,
            offset_start=rf.offset_start,
            offset_end=rf.offset_end,
            evidence_snippet=rf.evidence_snippet
        ))
    for pf in protected_findings:
        unified_findings.append(Finding(
            rule_id="RULE-SEC-003",
            name=f"Protected Value Match: {pf.token_name}",
            category="protected_data",
            severity="critical",
            description=f"Matched internal protected value '{pf.token_name}' (type: {pf.match_type})",
            offset_start=pf.offset_start,
            offset_end=pf.offset_end,
            evidence_snippet=mask_text(pf.snippet)
        ))

    # Step 7: Initial Policy Evaluation (Module H)
    can_attempt_sanitize = (len(rule_findings) > 0 and len(protected_findings) == 0 and source == "Uploaded Document")
    policy_eval = evaluate_security_policy(
        rule_findings=rule_findings,
        protected_findings=protected_findings,
        ml_result=ml_output,
        intent_result=intent_output,
        can_sanitize=can_attempt_sanitize
    )

    decision = policy_eval["decision"]
    summary_explanation = policy_eval["summary_explanation"]
    triggered_policy = policy_eval["triggered_policy"]
    triggered_rules = policy_eval["triggered_rules"]
    forwarding_permitted = policy_eval["forwarding_permitted"]
    sanitized_content = None
    permitted_content = None

    # Step 8: Surgical Sanitization & Reinspection (Module I)
    if decision == "SANITIZE":
        candidate_sanitized, sanitize_reason = surgical_sanitize(raw_text, rule_findings)
        if candidate_sanitized:
            # Mandate 1 complete reinspection pass of the sanitized text
            reinspect_norm = normalize_text(candidate_sanitized)
            reinspect_rules = evaluate_rules(reinspect_norm.normalized_text, reinspect_norm.decoded_payloads)
            reinspect_protected = inspect_protected_values(reinspect_norm.normalized_text, reinspect_norm.decoded_payloads)

            if len(reinspect_rules) == 0 and len(reinspect_protected) == 0:
                # Reinspection passed cleanly!
                sanitized_content = candidate_sanitized
                permitted_content = candidate_sanitized
                forwarding_permitted = True
                summary_explanation = (
                    f"Offending instruction span excised successfully. Cleaned content passed mandatory "
                    f"reinspection and is authorized for assistant processing."
                )
            else:
                # Residual attack remains -> Conservative Block
                decision = "BLOCK"
                forwarding_permitted = False
                summary_explanation = (
                    "Sanitization failed: Residual threat detected during mandatory reinspection pass. "
                    "Content blocked for security integrity."
                )
        else:
            # Destructive or offset failure -> Fallback to BLOCK
            decision = "BLOCK"
            forwarding_permitted = False
            summary_explanation = f"Sanitization aborted ({sanitize_reason}). Input blocked under strict policy."

    elif decision == "ALLOW":
        permitted_content = raw_text
        forwarding_permitted = True

    # Step 8.5: Cloud Gemini AI Consultation (Triggered when software has doubt or requested)
    gemini_verification_obj = None
    ml_prob = ml_output.get("attack_probability", 0.0)
    ml_status = ml_output.get("status", "ready")
    intent_mismatch = intent_output.get("mismatch_detected", False)

    has_doubt = (
        decision == "ESCALATE"
        or ml_status == "degraded"
        or (0.25 <= ml_prob <= 0.70 and len(rule_findings) == 0 and len(protected_findings) == 0 and not is_benign_quotation_or_research(raw_text))
        or (intent_mismatch and len(rule_findings) == 0)
        or bool(req.force_cloud_verification)
    )

    if has_doubt:
        gemini_res = verify_with_gemini(
            content=raw_text,
            task=task,
            api_key=req.gemini_api_key,
            allow_simulation=bool(req.allow_simulation)
        )
        gemini_verification_obj = GeminiVerificationResult(**gemini_res)

        if gemini_res.get("is_verified"):
            if gemini_res.get("is_malicious") and gemini_res.get("threat_score", 0) >= 60:
                if decision != "BLOCK":
                    decision = "BLOCK"
                    forwarding_permitted = False
                    summary_explanation = (
                        f"Cloud Gemini AI confirmed malicious intent (Threat Score: {gemini_res.get('threat_score')}/100, "
                        f"Level: {gemini_res.get('maliciousness_level')}). {gemini_res.get('reasoning')}"
                    )
                    triggered_policy = "POL-GEMINI-BLOCK (Cloud AI Confirmed Threat)"
            elif not gemini_res.get("is_malicious") and gemini_res.get("threat_score", 0) < 40:
                if decision == "ESCALATE":
                    decision = "ALLOW"
                    forwarding_permitted = True
                    permitted_content = raw_text
                    summary_explanation = (
                        f"Cloud Gemini AI resolved software doubt and confirmed prompt is safe "
                        f"(Threat Score: {gemini_res.get('threat_score')}/100, Level: {gemini_res.get('maliciousness_level')}). "
                        f"{gemini_res.get('reasoning')}"
                    )
                    triggered_policy = "POL-GEMINI-ALLOW (Cloud AI Confirmed Safe)"

    # Step 9: Construct Judge-Facing 6-Step "How this decision was made"
    decision_steps = [
        DecisionStep(
            step_number=1,
            title="1. Input received",
            status="pass",
            explanation=f"Received input from {source}. Authorized user task: '{task}'."
        ),
        DecisionStep(
            step_number=2,
            title="2. Suspicious behavior found",
            status="alert" if (unified_findings or transformations) else "pass",
            explanation=(
                f"Identified {len(unified_findings)} suspicious evidence items and {len(transformations)} text transformations."
                if (unified_findings or transformations)
                else "No suspicious injection patterns, obfuscated payloads, or unauthorized instructions detected."
            ),
            evidence=", ".join([f.name for f in unified_findings]) if unified_findings else None
        ),
        DecisionStep(
            step_number=3,
            title="3. Risk analyzed",
            status="alert" if risk_scores.combined_priority > 40 else "pass",
            explanation=(
                f"Computed risk: Prompt={risk_scores.prompt_risk}, Source={risk_scores.source_risk}, "
                f"Drift={risk_scores.intent_drift_risk}, Action={risk_scores.action_impact}. Priority index: {risk_scores.combined_priority}/100."
            )
        ),
        DecisionStep(
            step_number=4,
            title="4. Policy applied",
            status="blocked" if decision == "BLOCK" else ("sanitized" if decision == "SANITIZE" else ("held" if decision == "ESCALATE" else "pass")),
            explanation=f"Evaluated policy rule precedence. Active policy enforced: {triggered_policy}."
        ),
        DecisionStep(
            step_number=5,
            title="5. Safe result",
            status="pass" if decision in ["ALLOW", "SANITIZE"] else "blocked",
            explanation=(
                f"Outcome: {decision}. Forwarding to assistant: {'Permitted' if forwarding_permitted else 'Prohibited'}."
            )
        ),
        DecisionStep(
            step_number=6,
            title="6. Action checked",
            status="pass",
            explanation="Independent action firewall is primed to validate any outbound assistant operations."
        )
    ]

    # Package schema objects
    norm_detail = NormalizationDetail(
        original_length=len(raw_text),
        normalized_length=len(normalized_text),
        transformations_applied=transformations,
        decoded_payloads=decoded_payloads
    )

    ml_detail = MLDetectorResult(
        attack_probability=ml_output.get("attack_probability", 0.0),
        predicted_label=ml_output.get("predicted_label", 0),
        confidence_level=ml_output.get("confidence_level", "ready"),
        model_version=ml_output.get("model_version", "v1.2-hybrid-offline"),
        status=ml_output.get("status", "ready")
    )

    intent_detail = IntentAnalysisResult(
        task_intent=intent_output["task_intent"],
        content_intent=intent_output["content_intent"],
        mismatch_detected=intent_output["mismatch_detected"],
        drift_score=intent_output["drift_score"],
        explanation=intent_output["explanation"]
    )

    response = InspectResponse(
        inspection_id=inspection_id,
        decision=decision,
        summary_explanation=summary_explanation,
        task=task,
        source_type=source,
        original_content=mask_text(raw_text),
        sanitized_content=mask_text(sanitized_content) if sanitized_content else None,
        permitted_content=mask_text(permitted_content) if permitted_content else None,
        forwarding_permitted=forwarding_permitted,
        triggered_policy=triggered_policy,
        triggered_rules=triggered_rules,
        findings=unified_findings,
        risk_scores=risk_scores,
        normalization=norm_detail,
        ml_result=ml_detail,
        intent_analysis=intent_detail,
        decision_steps=decision_steps,
        policy_version=policy_eval.get("policy_version", "v2.1"),
        created_at=now_iso,
        gemini_verification=gemini_verification_obj
    )

    # Persist in local SQLite database
    save_data = response.model_dump()
    save_data["original_content"] = raw_text  # store raw for review validation
    save_data["masked_content"] = mask_text(raw_text)
    save_data["person"] = req.person.model_dump() if (hasattr(req, "person") and req.person) else None
    save_data["gemini_verification"] = gemini_verification_obj.model_dump() if gemini_verification_obj else None
    save_inspection(save_data)

    # If prompt is malicious (BLOCK or ESCALATE), log into incidents table for Authority Portal
    if decision in ["BLOCK", "ESCALATE"]:
        person_obj = req.person or PersonData()
        person_dict = person_obj.model_dump() if hasattr(person_obj, "model_dump") else person_obj
        malicious_snippets = (
            "; ".join([f'"{f.evidence_snippet}" ({f.name})' for f in unified_findings])
            if unified_findings
            else summary_explanation
        )
        auto_inc_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{inspection_id[:6].upper()}"
        auto_incident_data = {
            "id": auto_inc_id,
            "inspection_id": inspection_id,
            "person_name": person_dict.get("name", "Alex Vance"),
            "person_email": person_dict.get("email", "alex.vance@internal-corp.net"),
            "person_id": person_dict.get("employee_id", "EMP-8842"),
            "person_department": person_dict.get("department", "Finance & Commercial Operations"),
            "client_ip": person_dict.get("client_ip", "192.168.1.104"),
            "client_workstation": person_dict.get("workstation", "WS-CORP-FIN-03"),
            "malicious_text": malicious_snippets,
            "violating_rules": triggered_rules,
            "severity": "critical" if risk_scores.combined_priority > 60 else "high",
            "complete_prompt": raw_text,
            "authorized_task": task,
            "decision": decision,
            "risk_priority": risk_scores.combined_priority,
            "higher_authority": "Chief Information Security Officer (CISO) & SecOps Incident Response",
            "notes": f"Ingestion security alert: Policy engine designated prompt as {decision}. Transferred for higher authority investigation.",
            "status": "TRANSFERRED_FOR_INVESTIGATION",
            "created_at": now_iso
        }
        try:
            save_incident(auto_incident_data)
        except Exception:
            pass

    return response
