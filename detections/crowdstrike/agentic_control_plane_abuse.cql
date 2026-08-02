// Falcon LogScale / Next-Gen SIEM custom AgentSim repository.
// Map attributes.* fields during JSON ingestion and replace #repo.
#repo=agentsim
| case {
    event_type="agent.model.fallback" AND attributes.safety_profile_changed=true AND attributes.policy_binding_valid=false
      | SignalType:="model_safety_downgrade";
    event_type="agent.policy.decision" AND policy_decision="allow" AND attributes.policy_scope="executor" AND attributes.intent_equivalent=true AND attributes.policy_version_match=false
      | SignalType:="planner_executor_policy_gap";
    event_type="agent.approval.reused" AND attributes.action_fingerprint_match=false
      | SignalType:="approval_replay";
    event_type="agent.authorization.context_changed" AND attributes.tenant_changed=true AND attributes.tenant_binding_valid=false
      | SignalType:="cross_tenant_context_confusion";
    event_type="agent.tool.requested" AND attributes.egress_capable=true AND attributes.composite_risk="high"
      | SignalType:="tool_chain_capability_escalation";
    event_type="agent.registry.entry.changed" AND attributes.capability_expansion=true AND attributes.signature_valid=false
      | SignalType:="agent_registry_poisoning";
    * | SignalType:="";
  }
| SignalType!=""
| select([@timestamp, SignalType, trace_id, sequence, session_id, agent_id,
          principal_id, policy_id, policy_version, approval_id, delegation_id,
          tool_name, tool_risk, policy_decision, data_lineage_id])
