"""In-memory agentic attack fixtures with malicious and benign twins.

Fixtures do not open sockets, start processes, load plugins, or use credentials.
They exercise explicit authorization decisions against synthetic resources.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping


@dataclass(frozen=True)
class LabFixture:
    fixture_id: str
    name: str
    attack_class: str
    control: str
    malicious_request: Mapping[str, object]
    benign_request: Mapping[str, object]
    atlas_techniques: tuple[str, ...] = ()
    owasp_risks: tuple[str, ...] = ()
    tool_name: str = "synthetic.inspect"


@dataclass(frozen=True)
class LabResult:
    fixture_id: str
    passed: bool
    malicious_prevented: bool
    benign_allowed: bool
    events: tuple[Mapping[str, object], ...]
    safety: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "fixture_id": self.fixture_id,
            "passed": self.passed,
            "malicious_prevented": self.malicious_prevented,
            "benign_allowed": self.benign_allowed,
            "events": [dict(event) for event in self.events],
            "safety": dict(self.safety),
        }


def _fixtures() -> tuple[LabFixture, ...]:
    values = (
        (
            "indirect-prompt-injection", "Indirect prompt injection", "prompt_injection",
            "taint_aware_tool_authorization", {"tainted": True, "tool_risk": "high"},
            {"tainted": False, "tool_risk": "low"}, ("LLM Prompt Injection",),
            ("ASI01 Agent Goal Hijack", "ASI02 Tool Misuse"), "synthetic.catalog.publish",
        ),
        (
            "memory-poisoning", "Memory poisoning", "memory_poisoning",
            "memory_provenance_enforcement", {"trusted_source": False, "persistent_write": True},
            {"trusted_source": True, "persistent_write": True}, ("AI Agent Context Poisoning",),
            ("ASI06 Memory and Context Poisoning",), "synthetic.memory.write",
        ),
        (
            "rag-poisoning", "RAG provenance poisoning", "rag_poisoning",
            "retrieval_provenance_verification", {"trusted_source": False, "retrieval_action": True},
            {"trusted_source": True, "retrieval_action": True}, ("RAG Poisoning",),
            ("ASI06 Memory and Context Poisoning",), "synthetic.documents.retrieve",
        ),
        (
            "mcp-permission-expansion", "MCP permission expansion", "mcp_abuse",
            "least_privilege_scopes", {"scope_expansion": True, "consent": False},
            {"scope_expansion": False, "consent": True}, ("AI Agent Tool Invocation",),
            ("ASI02 Tool Misuse", "ASI03 Identity and Privilege Abuse"), "mcp.synthetic.publish",
        ),
        (
            "mcp-identity-audience", "MCP identity and audience failure", "mcp_identity",
            "mcp_audience_and_identity_validation", {"audience_valid": False, "identity_bound": False},
            {"audience_valid": True, "identity_bound": True}, ("Valid Accounts",),
            ("ASI03 Identity and Privilege Abuse",), "mcp.synthetic.search",
        ),
        (
            "confused-deputy", "Confused deputy", "confused_deputy",
            "principal_resource_binding", {"principal_bound": False, "resource_allowed": False},
            {"principal_bound": True, "resource_allowed": True}, ("AI Agent Tool Invocation",),
            ("ASI03 Identity and Privilege Abuse",), "synthetic.resource.read",
        ),
        (
            "delegation-spoofing", "Delegation and peer spoofing", "delegation_spoofing",
            "delegation_chain_validation", {"delegation_valid": False, "peer_verified": False},
            {"delegation_valid": True, "peer_verified": True}, ("Impersonation",),
            ("ASI07 Insecure Inter-Agent Communication",), "synthetic.delegate",
        ),
        (
            "approval-deception", "Approval deception", "approval_deception",
            "immutable_approval_fingerprint", {"approval_matches": False, "approval_present": True},
            {"approval_matches": True, "approval_present": True}, ("AI Agent Clickbait",),
            ("ASI09 Human-Agent Trust Exploitation",), "synthetic.approved.preview",
        ),
        (
            "decoy-secret-access", "Decoy secret access", "credential_access",
            "decoy_secret_monitoring", {"decoy_secret_requested": True, "purpose_allowed": False},
            {"decoy_secret_requested": False, "purpose_allowed": True},
            ("AI Agent Tool Credential Harvesting",), ("ASI02 Tool Misuse",), "synthetic.decoy.inspect",
        ),
        (
            "budget-recursion", "Budget and recursive delegation abuse", "resource_abuse",
            "tool_and_delegation_budgets", {"budget_remaining": 0, "delegation_depth": 9},
            {"budget_remaining": 10, "delegation_depth": 1}, ("Cost Harvesting",),
            ("ASI05 Unexpected Code Execution", "ASI08 Cascading Failures"), "synthetic.budget.consume",
        ),
        (
            "goal-hijack", "Cross-turn goal hijack", "goal_hijack", "goal_integrity_binding",
            {"goal_integrity_valid": False, "tool_risk": "high"},
            {"goal_integrity_valid": True, "tool_risk": "low"}, ("AI Agent Context Poisoning",),
            ("ASI01 Agent Goal Hijack",), "synthetic.goal.preview",
        ),
        (
            "tool-definition-poisoning", "Tool definition poisoning", "tool_poisoning",
            "signed_tool_manifest", {"tool_signature_valid": False}, {"tool_signature_valid": True},
            ("AI Agent Tool Poisoning",), ("ASI04 Agentic Supply Chain Vulnerabilities",),
            "synthetic.tool.describe",
        ),
        (
            "tool-result-poisoning", "Tool result poisoning", "tool_result_poisoning",
            "tool_result_provenance", {"tool_result_trusted": False}, {"tool_result_trusted": True},
            ("AI Agent Tool Data Poisoning",), ("ASI06 Memory and Context Poisoning",),
            "synthetic.tool.result",
        ),
        (
            "configuration-tampering", "Agent configuration tampering", "configuration_tampering",
            "signed_configuration", {"configuration_signature_valid": False},
            {"configuration_signature_valid": True}, ("Modify AI Agent Configuration",),
            ("ASI04 Agentic Supply Chain Vulnerabilities",), "synthetic.config.preview",
        ),
        (
            "supply-chain-rug-pull", "Agentic supply-chain rug pull", "supply_chain",
            "package_provenance_and_version_pin", {"package_provenance_valid": False},
            {"package_provenance_valid": True}, ("AI Supply Chain Rug Pull",),
            ("ASI04 Agentic Supply Chain Vulnerabilities",), "synthetic.package.inspect",
        ),
        (
            "cross-session-replay", "Cross-session action replay", "session_replay",
            "session_and_intent_binding", {"session_binding_valid": False},
            {"session_binding_valid": True}, ("Use Alternate Authentication Material",),
            ("ASI03 Identity and Privilege Abuse",), "synthetic.session.inspect",
        ),
        (
            "approval-replay", "Stale approval replay", "approval_replay",
            "approval_freshness_and_nonce", {"approval_fresh": False}, {"approval_fresh": True},
            ("AI Agent Clickbait",), ("ASI09 Human-Agent Trust Exploitation",),
            "synthetic.approval.inspect",
        ),
        (
            "delayed-exfiltration", "Delayed exfiltration through an allowed tool", "exfiltration",
            "destination_and_data_class_egress_policy", {"egress_allowed": False},
            {"egress_allowed": True}, ("Exfiltration via AI Agent Tool Invocation",),
            ("ASI02 Tool Misuse",), "synthetic.egress.preview",
        ),
        (
            "cost-harvesting", "Agent resource and cost harvesting", "cost_harvesting",
            "cost_and_rate_budget", {"cost_budget_remaining": 0}, {"cost_budget_remaining": 100},
            ("Cost Harvesting",), ("ASI08 Cascading Failures",), "synthetic.cost.preview",
        ),
        (
            "trust-summary-deception", "Misleading action summary", "trust_exploitation",
            "summary_evidence_binding", {"summary_evidence_valid": False},
            {"summary_evidence_valid": True}, ("AI Agent Clickbait",),
            ("ASI09 Human-Agent Trust Exploitation",), "synthetic.summary.verify",
        ),
    )
    return tuple(LabFixture(*value) for value in values)


def list_fixtures() -> tuple[LabFixture, ...]:
    return _fixtures()


def _allowed(request: Mapping[str, object]) -> tuple[bool, str]:
    deny_flags = ("tainted", "scope_expansion", "decoy_secret_requested")
    required_true = (
        "trusted_source",
        "consent",
        "audience_valid",
        "identity_bound",
        "principal_bound",
        "resource_allowed",
        "delegation_valid",
        "peer_verified",
        "approval_matches",
        "approval_present",
        "purpose_allowed",
        "goal_integrity_valid",
        "tool_signature_valid",
        "tool_result_trusted",
        "configuration_signature_valid",
        "package_provenance_valid",
        "session_binding_valid",
        "approval_fresh",
        "egress_allowed",
        "summary_evidence_valid",
    )
    if any(request.get(flag) is True for flag in deny_flags):
        return False, "risk flag denied"
    if any(field in request and request.get(field) is not True for field in required_true):
        return False, "required trust assertion failed"
    if request.get("tool_risk") == "high":
        return False, "tainted high-risk tool request denied"
    if int(request.get("budget_remaining", 1)) <= 0:
        return False, "tool budget exhausted"
    if int(request.get("delegation_depth", 0)) > 3:
        return False, "delegation depth exceeded"
    if int(request.get("cost_budget_remaining", 1)) <= 0:
        return False, "cost budget exhausted"
    return True, "synthetic policy allowed request"


def run_fixture(fixture_id: str) -> LabResult:
    try:
        fixture = next(item for item in _fixtures() if item.fixture_id == fixture_id)
    except StopIteration as exc:
        raise ValueError(f"Unknown lab fixture: {fixture_id}") from exc
    malicious_allowed, malicious_reason = _allowed(fixture.malicious_request)
    benign_allowed, benign_reason = _allowed(fixture.benign_request)
    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    events = (
        {
            "timestamp": now,
            "source": "agent_runtime",
            "event_type": "agent.tool.requested",
            "fixture_id": fixture.fixture_id,
            "variant": "malicious",
            "attack_class": fixture.attack_class,
            "tool_name": fixture.tool_name,
            "policy_decision": "allow" if malicious_allowed else "deny",
            "reason": malicious_reason,
            "executed": False,
            "synthetic": True,
            "content_recorded": False,
            "mappings": {"mitre_atlas": list(fixture.atlas_techniques), "owasp_agentic": list(fixture.owasp_risks)},
        },
        {
            "timestamp": now,
            "source": "agent_runtime",
            "event_type": "agent.tool.requested",
            "fixture_id": fixture.fixture_id,
            "variant": "benign",
            "attack_class": fixture.attack_class,
            "tool_name": fixture.tool_name,
            "policy_decision": "allow" if benign_allowed else "deny",
            "reason": benign_reason,
            "executed": False,
            "synthetic": True,
            "content_recorded": False,
            "mappings": {"mitre_atlas": list(fixture.atlas_techniques), "owasp_agentic": list(fixture.owasp_risks)},
        },
    )
    malicious_prevented = not malicious_allowed
    return LabResult(
        fixture.fixture_id,
        malicious_prevented and benign_allowed,
        malicious_prevented,
        benign_allowed,
        events,
        {
            "execution_mode": "in_memory_disposable_fixture",
            "network_opened": False,
            "process_started": False,
            "tool_executed": False,
            "credential_used": False,
            "control": fixture.control,
        },
    )


def run_lab_suite() -> tuple[LabResult, ...]:
    return tuple(run_fixture(fixture.fixture_id) for fixture in _fixtures())
