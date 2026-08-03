"""Ground-truth, agent-contract, and normalized telemetry helpers."""

from .agent_contract import AGENT_COLLECTOR_NAMES, agent_trace_from_record, normalize_agent_records
from .ground_truth import append_event, load_lifecycle_events
from .correlation import correlate_lifecycle
from .normalization import normalize_record, normalize_records
from .assurance import AssuranceFinding, TelemetryAssuranceReport, assess_telemetry
from .investigation import (
    InvariantFinding,
    InvestigationEdge,
    InvestigationNode,
    InvestigationPath,
    InvestigationReport,
    investigate_telemetry,
)
from .flight_recorder import (
    AgentSimTraceProcessor,
    FlightRecorder,
    FlightRecorderBundle,
    attach_to_openai_agents,
    flight_bundle_from_mapping,
    load_flight_bundle,
    otlp_records,
)
from .flight_server import serve_flight_recorder
from .mappings import (
    PORTABLE_PROFILES,
    PROFILE_VERSIONS,
    PortableMappingResult,
    agent_trace_from_portable_record,
    map_agent_trace,
    mapping_catalog,
)
from .conformance import (
    RuntimeConformanceReport,
    evaluate_fixture_conformance,
    run_fixture_conformance,
)

__all__ = [
    "append_event",
    "AgentSimTraceProcessor",
    "AGENT_COLLECTOR_NAMES",
    "agent_trace_from_record",
    "AssuranceFinding",
    "assess_telemetry",
    "correlate_lifecycle",
    "FlightRecorder",
    "FlightRecorderBundle",
    "attach_to_openai_agents",
    "flight_bundle_from_mapping",
    "load_lifecycle_events",
    "load_flight_bundle",
    "InvariantFinding",
    "InvestigationEdge",
    "InvestigationNode",
    "InvestigationPath",
    "InvestigationReport",
    "investigate_telemetry",
    "normalize_record",
    "normalize_records",
    "normalize_agent_records",
    "otlp_records",
    "PORTABLE_PROFILES",
    "PROFILE_VERSIONS",
    "PortableMappingResult",
    "RuntimeConformanceReport",
    "agent_trace_from_portable_record",
    "evaluate_fixture_conformance",
    "map_agent_trace",
    "mapping_catalog",
    "run_fixture_conformance",
    "serve_flight_recorder",
    "TelemetryAssuranceReport",
]
