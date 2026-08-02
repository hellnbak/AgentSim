"""Vendor-neutral detection validation, coverage, and candidate generation."""

from .ast import (
    DetectionRule,
    GraphFanoutNode,
    GraphPathNode,
    load_rule,
    parse_rule,
    rule_to_dict,
)
from .coverage import CoverageReport, analyze_coverage, analyze_registry_coverage
from .evaluator import DetectionEvaluation, evaluate_rule
from .generator import CandidateDetection, generate_candidate, generate_candidates
from .live import LiveDetectionOutcome, evaluate_live_ability, evaluate_live_registry
from .packs import (
    DetectionPack,
    DetectionSweepOutcome,
    DetectionSweepReport,
    load_detection_pack,
    parse_detection_pack,
    sweep_detection_pack,
)

__all__ = [
    "CandidateDetection",
    "LiveDetectionOutcome",
    "CoverageReport",
    "DetectionEvaluation",
    "DetectionRule",
    "GraphFanoutNode",
    "GraphPathNode",
    "DetectionPack",
    "DetectionSweepOutcome",
    "DetectionSweepReport",
    "analyze_coverage",
    "analyze_registry_coverage",
    "evaluate_rule",
    "generate_candidate",
    "generate_candidates",
    "evaluate_live_ability",
    "evaluate_live_registry",
    "load_rule",
    "load_detection_pack",
    "parse_detection_pack",
    "parse_rule",
    "rule_to_dict",
    "sweep_detection_pack",
]
