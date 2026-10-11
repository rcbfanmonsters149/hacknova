"""Pydantic schemas for PromptShield X API contracts."""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class SourceTypeEnum:
    USER_PROMPT = "User Prompt"
    UPLOADED_DOCUMENT = "Uploaded Document"
    WEBSITE_CONTENT = "Website Content"
    TOOL_OUTPUT = "Tool Output"

class PolicyDecisionEnum:
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    SANITIZE = "SANITIZE"
    ESCALATE = "ESCALATE"

class PersonData(BaseModel):
    name: str = Field(default="Alex Vance")
    email: str = Field(default="alex.vance@internal-enterprise.com")
    employee_id: str = Field(default="EMP-8842")
    department: str = Field(default="Finance & Commercial Ops")
    client_ip: str = Field(default="192.168.1.104")
    workstation: str = Field(default="WS-CORP-FIN-03")

# --- Request Schemas ---

class InspectRequest(BaseModel):
    task: str = Field(..., description="The legitimate authorized user task", min_length=1)
    content: str = Field(..., description="Incoming content to inspect", min_length=1)
    source_type: str = Field(default="User Prompt", description="Source of content")
    source_metadata: Optional[Dict[str, Any]] = Field(default=None, description="Optional metadata e.g. URL or filename")
    inspection_level: Optional[str] = Field(default="adaptive", description="standard, enhanced, deep, or adaptive")
    force_detector_degraded: Optional[bool] = Field(default=False, description="Simulate AI classifier failure for demo")
    gemini_api_key: Optional[str] = Field(default=None, description="Optional Gemini API key for cloud confirmation")
    force_cloud_verification: Optional[bool] = Field(default=False, description="Force consult Gemini cloud AI")
    allow_simulation: Optional[bool] = Field(default=False, description="Allow offline simulated Gemini assessment")
    person: Optional[PersonData] = Field(default=None, description="Employee or user identity metadata")

class ActionCheckRequest(BaseModel):
    inspection_id: Optional[str] = Field(default=None, description="Bound inspection ID")
    tool_name: str = Field(..., description="Name of the tool the AI proposes to execute")
    tool_args: Dict[str, Any] = Field(default_factory=dict, description="Arguments proposed for the tool")
    authorized_task: Optional[str] = Field(default="", description="Original user task context")
    target_destination: Optional[str] = Field(default=None, description="Target URL or domain if external")

class AssistantRunRequest(BaseModel):
    inspection_id: str = Field(..., description="Stored inspection ID to retrieve permitted content")
    task: Optional[str] = Field(default="", description="Task context")

class ReviewActionRequest(BaseModel):
    inspection_id: str = Field(...)
    reviewer: str = Field(default="admin_reviewer")
    action: str = Field(..., description="APPROVE or REJECT")
    notes: Optional[str] = Field(default="")

class PolicyUpdateRequest(BaseModel):
    version: str = Field(default="v2.1")
    settings: Dict[str, Any] = Field(..., description="Key-value security policy toggles and thresholds")

# --- Response Schemas ---

class Finding(BaseModel):
    rule_id: str
    name: str
    category: str
    severity: str  # critical, high, medium, low
    description: str
    offset_start: int
    offset_end: int
    evidence_snippet: str

class RiskIndicator(BaseModel):
    prompt_risk: int = Field(ge=0, le=100)
    source_risk: int = Field(ge=0, le=100)
    intent_drift_risk: int = Field(ge=0, le=100)
    action_impact: int = Field(ge=0, le=100)
    combined_priority: int = Field(ge=0, le=100)
    factors: List[str] = Field(default_factory=list)

class DecisionStep(BaseModel):
    step_number: int
    title: str
    status: str  # pass, alert, blocked, sanitized, held
    explanation: str
    evidence: Optional[str] = None

class NormalizationDetail(BaseModel):
    original_length: int
    normalized_length: int
    transformations_applied: List[str]
    decoded_payloads: List[str] = Field(default_factory=list)

class MLDetectorResult(BaseModel):
    attack_probability: float
    predicted_label: int
    confidence_level: str
    model_version: str
    status: str  # ready, degraded, fallback

class IntentAnalysisResult(BaseModel):
    task_intent: str
    content_intent: str
    mismatch_detected: bool
    drift_score: int
    explanation: str

class GeminiVerificationResult(BaseModel):
    is_verified: bool = False
    status: str = "none"  # "verified", "no_key", "error", "doubt_resolved"
    message: Optional[str] = None
    is_malicious: Optional[bool] = None
    maliciousness_level: Optional[str] = None  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    threat_score: Optional[int] = None  # 0 - 100
    confidence: Optional[str] = None  # high, medium, low
    reasoning: Optional[str] = None
    detected_tactics: List[str] = Field(default_factory=list)
    recommendation: Optional[str] = None  # ALLOW, BLOCK, SANITIZE, ESCALATE
    model: str = "gemini-3.5-flash"
    timestamp: Optional[str] = None
    error: Optional[str] = None

class InspectResponse(BaseModel):
    inspection_id: str
    decision: str  # ALLOW, BLOCK, SANITIZE, ESCALATE
    summary_explanation: str
    task: str
    source_type: str
    original_content: str
    sanitized_content: Optional[str] = None
    permitted_content: Optional[str] = None
    forwarding_permitted: bool
    triggered_policy: str
    triggered_rules: List[str]
    findings: List[Finding]
    risk_scores: RiskIndicator
    normalization: NormalizationDetail
    ml_result: MLDetectorResult
    intent_analysis: IntentAnalysisResult
    decision_steps: List[DecisionStep]
    policy_version: str
    created_at: str
    gemini_verification: Optional[GeminiVerificationResult] = None


class ActionCheckResponse(BaseModel):
    action_allowed: bool
    decision: str  # ALLOW or BLOCK
    reason: str
    violating_rule: Optional[str] = None
    firewall_checks: Dict[str, Any]
    target_destination: Optional[str] = None
    timestamp: str

class AssistantRunResponse(BaseModel):
    inspection_id: str
    success: bool
    status: str  # executed, blocked, rejected
    message: str
    executed_content: Optional[str] = None
    assistant_output: Optional[str] = None
    proposed_action: Optional[Dict[str, Any]] = None
    action_firewall_verdict: Optional[ActionCheckResponse] = None

class PolicyItem(BaseModel):
    id: str
    name: str
    category: str
    rule_id: str
    action: str
    priority: int
    is_hard_rule: bool
    enabled: bool
    description: str

class PolicyConfigResponse(BaseModel):
    version: str
    last_updated: str
    policies: List[PolicyItem]
    settings: Dict[str, Any]

class EvaluationMetrics(BaseModel):
    total_cases: int
    attacks_detected: int
    missed_attacks: int
    false_positives: int
    correct_benign: int
    reviews_held: int
    precision: float
    recall: float
    false_positive_rate: float
    f1_score: float
    average_latency_ms: float
    rule_only_metrics: Dict[str, float]
    hybrid_metrics: Dict[str, float]
    test_cases: List[Dict[str, Any]]
    evaluated_at: str

class IncidentUpdateRequest(BaseModel):
    status: Optional[str] = Field(default=None, description="Updated investigation status")
    notes: Optional[str] = Field(default=None, description="Authority investigator notes")
    investigator: Optional[str] = Field(default=None, description="Assigned authority investigator")

class AuthorityStatsResponse(BaseModel):
    total_prompts: int
    malicious_attempts: int
    transferred_incidents: int
    departments_monitored: int

class EscalateIncidentRequest(BaseModel):
    inspection_id: Optional[str] = None
    person: PersonData
    malicious_text: str = Field(..., description="The exact offending text causing the threat")
    violating_rules: List[str] = Field(default_factory=list)
    severity: str = Field(default="high")
    complete_prompt: str = Field(..., description="Complete prompt entered by the user")
    authorized_task: str = Field(..., description="Claimed authorized user task")
    decision: str = Field(default="BLOCK")
    risk_priority: Optional[int] = Field(default=85)
    higher_authority: Optional[str] = Field(default="Chief Information Security Officer (CISO) & SecOps Incident Response")
    notes: Optional[str] = Field(default="")

class EscalateIncidentResponse(BaseModel):
    success: bool
    incident_id: str
    status: str
    transferred_to: str
    timestamp: str
    message: str
    dossier: Dict[str, Any]

class GeminiVerifyRequest(BaseModel):
    content: str = Field(..., description="Prompt or content to verify with Cloud AI")
    task: Optional[str] = Field(default="", description="Authorized task context")
    api_key: Optional[str] = Field(default=None, description="Optional Gemini API key")
    allow_simulation: Optional[bool] = Field(default=False, description="Allow offline simulated Gemini assessment")

class GeminiConfigUpdate(BaseModel):
    api_key: str = Field(..., description="Google Gemini API key")


