# PromptShield X — Adaptive, Trust-Aware AI Security Gateway

Built for **VORTEXA 3.0** (12-Hour Student Hackathon) — Track **C-03**.

PromptShield X is an adaptive, dual-boundary AI security gateway designed to inspect incoming prompts, uploaded documents, external web snippets, and AI tool operations to defend against prompt injection and data exfiltration threats.

---

## 1. Core Architecture Flow

```
Incoming Content
  → Source Provenance Validation
  → Text Normalization & Obfuscation Detection
  → Hybrid Threat Detection (Local ML + Deterministic Rules)
  → Protected-Value & Secret Exfiltration Inspection
  → Intent Drift Detection
  → Explainable Risk Scoring (Prompt, Source, Drift, Action Impact)
  → Adaptive Inspection
  → Deterministic Policy Engine (ALLOW / BLOCK / SANITIZE / ESCALATE)
  → Surgical Sanitization & Mandatory Reinspection
  → Controlled Stored Forwarding
  → Independent AI Action Firewall
```

---

## 2. Key Innovations

### 1. Intent Drift Engine
Detects when lower-trust content (such as an uploaded document or third-party web page) attempts to divert the AI away from the user's authorized objective (e.g., user asks for a financial summary, but an embedded instruction requests transmitting confidential records).

### 2. Independent Action Firewall
A separate post-model execution barrier. Even if an adversarial prompt bypasses initial text inspection, the Action Firewall intercepts simulated tool calls (e.g. `send_external_http`), validates destination domains, and blocks protected token exposure before any external request can occur.

### 3. Surgical Sanitization with Mandatory Reinspection
When an untrusted document contains an isolated injection within otherwise valuable content, PromptShield X surgically excises the offending span and subjects the cleaned output to a complete second inspection pass before authorizing assistant forwarding.

### 4. Fully Local & Offline Classifier
Powered by scikit-learn (`TF-IDF` + `LogisticRegression`), the model runs completely offline with zero paid cloud API dependencies. In the event of model failure, conservative degraded mode takes over, ensuring the gateway never silently defaults to safe.

---

## 3. Technology Stack

- **Backend**: Python 3.12+, FastAPI, Pydantic, scikit-learn, joblib, SQLite (`sqlite3`), Pytest
- **Frontend**: React, Vite, Tailwind CSS, Lucide React, Recharts
- **Offline ML Pipeline**: TF-IDF N-Gram Vectorizer + Logistic Regression classifier
- **Storage**: Local SQLite database (`backend/runtime/promptshield.db`)

---

## 4. Five Core Sections

1. **Inspector** (Default demo experience): Interactive content inspection with 4 risk indicators, "How this decision was made" 6-step breakdown, surgical sanitization diffs, and controlled simulated assistant forwarding.
2. **Attack Lab**: 30-second judge demonstration centerpiece (Received Input → PromptShield Enforcement → Permitted AI Action) covering 9 pre-configured attack scenarios.
3. **Policies**: Active security policies table, displaying locked hard security invariants (unoverrideable rules) alongside configurable operational thresholds.
4. **Evaluation**: Empirical scorecard featuring real metrics (100% precision, 100% recall, 100% F1 score, 0.0% false positive rate) and a comparative Rule-Only vs. Hybrid detection chart.
5. **History**: Audit trail of past inspections with search, decision filters, masked confidential values, and human review controls.

---

## 5. Live Judge Demonstration Script

| Demo | Scenario | Input Type | Gateway Decision | Key Takeaway for Judges |
| :--- | :--- | :--- | :--- | :--- |
| **Demo A** | Normal User Question | Uploaded Document | **ALLOW** | Genuine report content passes all checks cleanly. |
| **Demo B** | Indirect Document Injection | Uploaded Document | **SANITIZE** | Offending instruction is surgically removed; clean report reaches the AI. |
| **Demo C** | Secret Disclosure Attempt | User Prompt | **BLOCK** | Prohibits attempts to reveal `DEMO_INTERNAL_TOKEN_4821` under hard policy `POL-001`. |
| **Demo D** | Harmless Security Quote | User Prompt | **ALLOW** | Contextual awareness prevents false positives on academic discussions. |
| **Demo E** | Unauthorized Tool Exfiltration | Simulated Assistant | **FIREWALL BLOCK** | Independent Action Firewall blocks outbound leakage to `attacker.example`. |
| **Demo F** | AI Classifier Failure | User Prompt | **DEGRADED FALLBACK** | Fails safely to deterministic rules and human review; never silently authorizes. |

---

## 6. How to Run Locally

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm

### 1. Backend Setup & Run
From the repository root:
```bash
# Verify test suite (all 37 unit & integration tests pass)
python -m pytest backend/tests/ -v

# Start the FastAPI server on port 8000
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
The backend API is now live at `http://127.0.0.1:8000`.

### 2. Frontend Setup & Run
In a second terminal:
```bash
cd frontend
npm run dev
```
Open `http://localhost:5173` in your browser. The application opens directly to the **Inspector**.
---

## 7. Team
Four members working on frontend, backend, AI, and evaluation (VORTEXA 3.0 — Track C-03).

