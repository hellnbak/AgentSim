// AGENTSIM STATUS: SAMPLE - TUNING AND HUMAN REVIEW REQUIRED
#repo=agentsim
| event_type="agent.tool.requested" AND input_trust="untrusted" AND tool_risk="high"
| select([@timestamp, trace_id, agent_id, event_id, event_type, policy_decision, tool_name, tool_risk])
