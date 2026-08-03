// AGENTSIM STATUS: SAMPLE - TUNING AND HUMAN REVIEW REQUIRED
#repo=agentsim
| event_type="agent.goal.integrity" AND goal_integrity_valid=false
| select([@timestamp, trace_id, agent_id, event_id, event_type, policy_decision, tool_name, tool_risk])
