// CrowdStrike Falcon LogScale / Next-Gen SIEM custom AgentSim repository.
// Map flattened AgentSim v2 JSON fields at ingestion and replace #repo.
#repo=agentsim
| event_type=/^agent\.(input\.observed|memory\.retrieved|retrieval\.result|tool\.requested|network\.requested|delegation\.requested)$/
| case {
    event_type=/^agent\.(input\.observed|memory\.retrieved|retrieval\.result)$/
      AND (input_trust="untrusted" OR taint_labels=*)
      | checkpoint:="untrusted_origin";
    event_type=/^agent\.(tool\.requested|network\.requested|delegation\.requested)$/
      AND (tool_risk=/^(high|critical)$/ OR attributes.recursive_depth>=3)
      | checkpoint:="risky_action";
    * | checkpoint:="other";
  }
| checkpoint=/^(untrusted_origin|risky_action)$/
| groupBy([trace_id, data_lineage_id], function=[
    min(sequence, as=FirstSequence),
    collect([checkpoint, event_type, agent_id, tool_name, tool_risk, policy_decision]),
    count(checkpoint, distinct=true, as=CheckpointKinds)
  ], limit=max)
| CheckpointKinds=2
