// AGENTSIM STATUS: SAMPLE - TUNING AND HUMAN REVIEW REQUIRED
#repo=agentsim
| event_type="agent.policy.decision" AND tool_risk="high" AND policy_decision="allow"
| select([@timestamp, trace_id, agent_id, event_id, event_type, policy_decision, tool_name, tool_risk])
