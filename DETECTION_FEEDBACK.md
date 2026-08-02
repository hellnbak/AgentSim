# Detection feedback integrity and drift

AgentSim 1.5 treats alert feedback as another security boundary. A detection
verdict is not trusted merely because an agent, service, or operator submitted
it. Before feedback can inform tuning, AgentSim joins the alert to content-safe
trace evidence, validates its structured annotation, and compares the proposed
detection behavior with malicious and benign baselines.

This workflow is offline and advisory. It never deploys a rule, changes a
suppression, queries a vendor, starts a process, opens a network connection, or
accepts prompt/tool content.

## Feedback bundle

The input contract is
[`schemas/detection-feedback.schema.json`](schemas/detection-feedback.schema.json):

```json
{
  "schema_version": "1.0",
  "alerts": [
    {
      "alert_id": "alert-42",
      "rule_id": "organization.agent-risk",
      "detected_at": "2026-08-02T12:00:00Z",
      "severity": "critical",
      "trace_id": "trace-42",
      "source_record_ids": ["event-42"],
      "agent_id": "detection-agent"
    }
  ],
  "annotations": [
    {
      "annotation_id": "annotation-42",
      "target_type": "alert",
      "target_id": "alert-42",
      "disposition": "confirmed_true_positive",
      "reason_code": "control_failure",
      "author_id": "reviewer-7",
      "author_type": "human",
      "created_at": "2026-08-02T12:05:00Z",
      "evidence_ids": ["event-42"],
      "evidence_digest_match": true
    }
  ]
}
```

Annotations intentionally use enumerated dispositions and reason codes. The
contract rejects unknown fields, so free-form notes, prompts, arguments,
results, credentials, and payloads cannot cross this boundary. Keep narrative
case notes in the organization’s authorized case-management system; use only
stable opaque identifiers in AgentSim.

## Alert-to-trace reconciliation

```bash
agentsim defense reconcile feedback.json agent-events.jsonl \
  --collector agent_runtime \
  --output feedback-report.json \
  --fail-on elevated
```

Each alert is classified as:

| Status | Meaning |
| --- | --- |
| `matched` | The explicit trace and every resolved evidence record agree. |
| `ambiguous` | Explicit and evidence-derived trace candidates conflict. |
| `unmatched` | The supplied evidence window cannot resolve the alert. |

The report also checks unresolved annotation targets/evidence, evidence-digest
mismatch, agent-authored final dispositions, contradictory positive/negative
verdicts, and attempts to dismiss traces with high-risk invariant failures.
Statuses are `clean`, `review`, `elevated`, or `critical`. The default CLI gate
returns exit code 1 for `critical`; use `--fail-on elevated`, `review`, or
`never` to select the CI threshold.

The output schema is
[`schemas/detection-feedback-report.schema.json`](schemas/detection-feedback-report.schema.json).
Scores prioritize triage and do not certify that an alert is correct.

## Detection tuning drift

A snapshot contains malicious/benign confusion-matrix counts plus optional
alert reconciliation and detection-latency metrics:

```json
{
  "snapshot_id": "reviewed-baseline",
  "true_positive": 38,
  "false_positive": 0,
  "true_negative": 38,
  "false_negative": 0,
  "mean_checkpoints_to_detection": 3,
  "reconciled_alerts": 4,
  "total_alerts": 4
}
```

Compare a candidate with the reviewed baseline:

```bash
agentsim defense drift baseline.json candidate.json \
  --max-recall-drop 0.05 \
  --max-fpr-increase 0.05 \
  --max-reconciliation-drop 0.05 \
  --max-latency-increase 1 \
  --output detection-drift.json
```

The report calculates precision, recall, false-positive rate, benign rejection
rate, reconciliation rate, and mean checkpoints to detection. A candidate is
`stable`, `review`, or `regressed`. The default command returns exit code 1 for
`regressed`; no candidate is deployed or promoted. The output schema is
[`schemas/detection-drift-report.schema.json`](schemas/detection-drift-report.schema.json).

## Python API

```python
from agentsim.api import detection_drift, detection_feedback_reconciliation
from agentsim.defense import DetectionAlert, DetectionSnapshot, OperatorAnnotation

feedback = detection_feedback_reconciliation(alerts, events, annotations)
drift = detection_drift(baseline_snapshot, candidate_snapshot)
```

Inputs are typed, bounded, and content-safe. Returned values are JSON-ready
schema objects.

## Dashboard workflow

The local dashboard’s **Detection feedback and tuning drift** card runs only
the fixed `detection-feedback-integrity` reference fixture. It displays alert
match rate, annotation coverage, integrity conflicts, feedback/drift scores,
and metric deltas. It does not provide a production telemetry upload or a
free-form annotation field.

## Recommended operating procedure

1. Run telemetry assurance and resolve unusable evidence.
2. Reconcile every candidate alert to one trace and its stable record IDs.
3. Require an authenticated human for final positive/negative dispositions.
4. Reject annotations whose evidence digest or identity binding changed.
5. Evaluate any tuning candidate against malicious, malicious-mutation,
   benign, and benign-mutation baselines.
6. Fail the gate on recall, benign rejection, reconciliation, or latency drift.
7. Review and deploy vendor content outside AgentSim through the organization’s
   normal change-control process.

The design responds to the security-operations and automated-remediation
failure modes described by the
[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
The mapping is descriptive; it is not a certification.
