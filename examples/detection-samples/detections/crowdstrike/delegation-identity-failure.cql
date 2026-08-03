// AGENTSIM STATUS: SAMPLE - TUNING AND HUMAN REVIEW REQUIRED
#repo=agentsim
| event_type="agent.delegation.accepted" AND identity_binding_valid=false
| select([@timestamp, trace_id, agent_id, event_id, event_type, policy_decision, tool_name, tool_risk])
