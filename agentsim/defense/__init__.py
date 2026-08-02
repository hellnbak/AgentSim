"""Defensive recommendations, regression, gap analysis, and scorecards."""

from .gaps import GapFinding, analyze_gaps
from .recommendations import recommendations_for_action
from .regression import RegressionResult, run_regression
from .runbooks import generate_runbook, generate_runbooks
from .scorecard import DefenseScorecard, build_scorecard

__all__ = [
    "DefenseScorecard",
    "GapFinding",
    "RegressionResult",
    "analyze_gaps",
    "build_scorecard",
    "generate_runbook",
    "generate_runbooks",
    "recommendations_for_action",
    "run_regression",
]
