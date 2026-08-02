"""Read-only live telemetry connector plans and bounded execution."""

from .base import HttpQueryTransport, LiveQueryResult, QueryPlan, QuerySpec, QueryTransport
from .vendors import (
    CONNECTOR_NAMES,
    DEFAULT_CREDENTIAL_ENV,
    build_query_plan,
    execute_query_plan,
)

__all__ = [
    "CONNECTOR_NAMES",
    "DEFAULT_CREDENTIAL_ENV",
    "HttpQueryTransport",
    "LiveQueryResult",
    "QueryPlan",
    "QuerySpec",
    "QueryTransport",
    "build_query_plan",
    "execute_query_plan",
]
