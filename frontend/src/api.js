/**
 * Clean native fetch API client for PromptShield X Backend.
 */

const API_BASE = import.meta.env.VITE_API_BASE_URL
  ? import.meta.env.VITE_API_BASE_URL.replace(/\/$/, "")
  : (import.meta.env.DEV ? "http://127.0.0.1:8000" : "/api");

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const defaultHeaders = {
    "Content-Type": "application/json",
  };

  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        ...defaultHeaders,
        ...options.headers,
      },
    });

    if (!res.ok) {
      let errDetail = `Server error (${res.status})`;
      try {
        const errJson = await res.json();
        errDetail = errJson.detail || errDetail;
      } catch (e) {
        // fallback to status text
      }
      throw new Error(errDetail);
    }

    return await res.json();
  } catch (error) {
    console.error(`API Error [${endpoint}]:`, error);
    throw error;
  }
}

export const api = {
  checkHealth: () => request("/health"),

  inspectContent: ({
    task,
    content,
    sourceType = "User Prompt",
    forceDegraded = false,
    geminiApiKey = null,
    forceCloudVerification = false,
    allowSimulation = false,
    person = null,
  }) =>
    request("/inspect", {
      method: "POST",
      body: JSON.stringify({
        task,
        content,
        source_type: sourceType,
        force_detector_degraded: forceDegraded,
        gemini_api_key: geminiApiKey,
        force_cloud_verification: forceCloudVerification,
        allow_simulation: allowSimulation,
        person: person,
      }),
    }),

  getPolicies: () => request("/policies"),

  updatePolicies: (settings, version = "v2.1") =>
    request("/policies", {
      method: "PUT",
      body: JSON.stringify({ version, settings }),
    }),

  getHistory: ({ limit = 50, search = "", decision = "" } = {}) => {
    const params = new URLSearchParams();
    if (limit) params.set("limit", limit.toString());
    if (search) params.set("search", search);
    if (decision && decision !== "ALL") params.set("decision", decision);
    return request(`/history?${params.toString()}`);
  },

  getInspectionDetails: (id) => request(`/inspections/${id}`),

  getReviews: () => request("/reviews"),

  submitReview: ({ inspectionId, action, reviewer = "security_lead", notes = "" }) =>
    request("/review", {
      method: "POST",
      body: JSON.stringify({
        inspection_id: inspectionId,
        reviewer,
        action,
        notes,
      }),
    }),

  runAssistant: ({ inspectionId, task }) =>
    request("/assistant/run", {
      method: "POST",
      body: JSON.stringify({
        inspection_id: inspectionId,
        task,
      }),
    }),

  checkAction: ({ toolName, toolArgs, inspectionId = null, authorizedTask = "", targetDestination = null }) =>
    request("/actions/check", {
      method: "POST",
      body: JSON.stringify({
        tool_name: toolName,
        tool_args: toolArgs,
        inspection_id: inspectionId,
        authorized_task: authorizedTask,
        target_destination: targetDestination,
      }),
    }),

  getLatestEvaluation: () => request("/evaluation/latest"),

  escalateIncident: ({
    inspectionId = null,
    person,
    maliciousText,
    violatingRules = [],
    severity = "high",
    completePrompt,
    authorizedTask,
    decision = "BLOCK",
    riskPriority = 85,
    higherAuthority = "Chief Information Security Officer (CISO) & SecOps Incident Response",
    notes = "",
  }) =>
    request("/incidents/escalate", {
      method: "POST",
      body: JSON.stringify({
        inspection_id: inspectionId,
        person,
        malicious_text: maliciousText,
        violating_rules: violatingRules,
        severity,
        complete_prompt: completePrompt,
        authorized_task: authorizedTask,
        decision,
        risk_priority: riskPriority,
        higher_authority: higherAuthority,
        notes,
      }),
    }),

  getIncidents: (limit = 50) => request(`/incidents?limit=${limit}`),

  verifyWithGemini: ({ content, task = "", apiKey = null, allowSimulation = false }) =>
    request("/gemini/verify", {
      method: "POST",
      body: JSON.stringify({
        content,
        task,
        api_key: apiKey,
        allow_simulation: allowSimulation,
      }),
    }),

  getGeminiConfig: () => request("/gemini/config"),

  saveGeminiConfig: (apiKey) =>
    request("/gemini/config", {
      method: "POST",
      body: JSON.stringify({ api_key: apiKey }),
    }),

  getAuthorityPrompts: ({ limit = 100, department = "", decision = "", search = "" } = {}) => {
    const params = new URLSearchParams();
    if (limit) params.set("limit", limit.toString());
    if (department && department !== "ALL") params.set("department", department);
    if (decision && decision !== "ALL") params.set("decision", decision);
    if (search) params.set("search", search);
    return request(`/authority/prompts?${params.toString()}`);
  },

  getAuthorityStats: () => request("/authority/stats"),

  updateIncident: ({ incidentId, status, notes = "", investigator = "" }) =>
    request(`/incidents/${incidentId}`, {
      method: "PATCH",
      body: JSON.stringify({
        status,
        notes,
        investigator,
      }),
    }),
};

