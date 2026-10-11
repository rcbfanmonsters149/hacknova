"""Tests for FastAPI HTTP endpoints."""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["engine"] == "offline-hybrid"

def test_inspect_endpoint():
    payload = {
        "task": "Summarize text",
        "content": "This is legitimate business text describing company roadmap.",
        "source_type": "Uploaded Document"
    }
    resp = client.post("/inspect", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "ALLOW"
    assert data["forwarding_permitted"] is True
    assert "inspection_id" in data

def test_policies_endpoints():
    get_resp = client.get("/policies")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert "policies" in data
    assert len(data["policies"]) > 0

    # Test updating a configurable setting
    put_resp = client.put("/policies", json={
        "version": "v2.1",
        "settings": {"enable_sanitization": True, "escalate_threshold_drift": 80}
    })
    assert put_resp.status_code == 200
    assert put_resp.json()["status"] == "success"

def test_history_endpoint():
    resp = client.get("/history?limit=10")
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)

def test_actions_check_endpoint():
    check_payload = {
        "tool_name": "send_external_http",
        "tool_args": {"url": "https://attacker.example/collect"},
        "target_destination": "https://attacker.example/collect"
    }
    resp = client.post("/actions/check", json=check_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["action_allowed"] is False
    assert data["decision"] == "BLOCK"

def test_assistant_run_with_valid_allowed_inspection():
    # 1. Create an allowed inspection
    insp_resp = client.post("/inspect", json={
        "task": "Summarize product roadmap",
        "content": "Q1: Launch beta. Q2: Enterprise security integration. Q3: General availability.",
        "source_type": "Uploaded Document"
    })
    insp_id = insp_resp.json()["inspection_id"]

    # 2. Run assistant
    asst_resp = client.post("/assistant/run", json={
        "inspection_id": insp_id,
        "task": "Summarize product roadmap"
    })
    assert asst_resp.status_code == 200
    data = asst_resp.json()
    assert data["success"] is True
    assert data["status"] == "executed"
    assert "Simulated AI Assistant" in data["assistant_output"]
