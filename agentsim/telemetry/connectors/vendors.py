"""Vendor query builders and response adapters for live validation."""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Callable, Mapping, Sequence
from urllib.parse import quote, urlencode

from agentsim.telemetry.normalization import normalize_records

from .base import (
    HttpQueryTransport,
    LiveQueryResult,
    QueryPlan,
    QuerySpec,
    QueryTransport,
    authorization_headers,
    json_bytes,
    utc_time,
)


CONNECTOR_NAMES = ("splunk", "elastic", "crowdstrike", "sentinel", "panther", "graylog")
DEFAULT_CREDENTIAL_ENV = {
    "splunk": "AGENTSIM_SPLUNK_TOKEN",
    "elastic": "AGENTSIM_ELASTIC_API_KEY",
    "crowdstrike": "AGENTSIM_CROWDSTRIKE_TOKEN",
    "sentinel": "AGENTSIM_SENTINEL_TOKEN",
    "panther": "AGENTSIM_PANTHER_API_KEY",
    "graylog": "AGENTSIM_GRAYLOG_TOKEN",
}


def _credential(spec: QuerySpec) -> str:
    return spec.credential_env or DEFAULT_CREDENTIAL_ENV[spec.connector]


def _quoted(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("'", "''")


def _splunk(spec: QuerySpec) -> QueryPlan:
    field = spec.target_field or "host"
    search = f'search index={spec.dataset} {field}="{_quoted(spec.target)}" | head {spec.limit}'
    body = urlencode(
        {
            "search": search,
            "earliest_time": spec.since,
            "latest_time": spec.until,
            "output_mode": "json",
        }
    ).encode("utf-8")
    return QueryPlan(
        spec.connector,
        "POST",
        f"{spec.base_url}/services/search/v2/jobs/export",
        "application/x-www-form-urlencoded",
        body,
        _credential(spec),
        "bearer",
        "splunk",
        spec.since,
        spec.until,
        spec.target,
        spec.dataset,
        spec.limit,
        {"target_field": field, "api_operation": "search export"},
    )


def _elastic(spec: QuerySpec) -> QueryPlan:
    field = spec.target_field or "host.id"
    body = json_bytes(
        {
            "size": spec.limit,
            "sort": [{"@timestamp": "asc"}],
            "track_total_hits": False,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": spec.since, "lte": spec.until}}},
                        {"term": {field: spec.target}},
                    ]
                }
            },
        }
    )
    return QueryPlan(
        spec.connector,
        "POST",
        f"{spec.base_url}/{quote(spec.dataset, safe='._-')}/_search",
        "application/json",
        body,
        _credential(spec),
        "api-key",
        "elastic",
        spec.since,
        spec.until,
        spec.target,
        spec.dataset,
        spec.limit,
        {"target_field": field, "required_privilege": "read"},
    )


def _crowdstrike(spec: QuerySpec) -> QueryPlan:
    field = spec.target_field or "aid"
    query_text = f'{field}="{_quoted(spec.target)}" | head({spec.limit})'
    body = json_bytes(
        {
            "queryString": query_text,
            "start": int(utc_time(spec.since).timestamp() * 1000),
            "end": int(utc_time(spec.until).timestamp() * 1000),
            "isLive": False,
            "allowEventSkipping": True,
        }
    )
    return QueryPlan(
        spec.connector,
        "POST",
        f"{spec.base_url}/api/v1/repositories/{quote(spec.dataset, safe='._-')}/query",
        "application/json",
        body,
        _credential(spec),
        "bearer",
        "logscale",
        spec.since,
        spec.until,
        spec.target,
        spec.dataset,
        spec.limit,
        {"target_field": field, "api_operation": "bounded streaming search"},
    )


def _sentinel(spec: QuerySpec) -> QueryPlan:
    try:
        workspace, table = spec.dataset.split(":", 1)
    except ValueError as exc:
        raise ValueError("sentinel dataset must be WORKSPACE_ID:TABLE") from exc
    field = spec.target_field or "Computer"
    query_text = (
        f"{table} | where TimeGenerated between (datetime({spec.since}) .. datetime({spec.until})) "
        f'| where {field} == "{_quoted(spec.target)}" | take {spec.limit}'
    )
    return QueryPlan(
        spec.connector,
        "POST",
        f"{spec.base_url}/v1/workspaces/{quote(workspace, safe='-')}/query",
        "application/json",
        json_bytes({"query": query_text, "timespan": f"{spec.since}/{spec.until}"}),
        _credential(spec),
        "bearer",
        "sentinel",
        spec.since,
        spec.until,
        spec.target,
        spec.dataset,
        spec.limit,
        {"target_field": field, "table": table, "workspace": workspace},
    )


def _panther(spec: QuerySpec) -> QueryPlan:
    field = spec.target_field or "p_any_hostname"
    start = utc_time(spec.since).strftime("%Y-%m-%d %H:%M:%S%z")
    end = utc_time(spec.until).strftime("%Y-%m-%d %H:%M:%S%z")
    sql = (
        f"SELECT * FROM {spec.dataset} WHERE p_event_time >= TIMESTAMP '{start}' "
        f"AND p_event_time <= TIMESTAMP '{end}' AND {field} = '{_quoted(spec.target)}' "
        f"LIMIT {spec.limit}"
    )
    body = json_bytes(
        {
            "query": (
                "mutation AgentSimIssueQuery($sql: String!) { "
                "executeDataLakeQuery(input: {sql: $sql}) { id } }"
            ),
            "variables": {"sql": sql},
        }
    )
    return QueryPlan(
        spec.connector,
        "POST",
        f"{spec.base_url}/public/graphql",
        "application/json",
        body,
        _credential(spec),
        "x-api-key",
        "panther",
        spec.since,
        spec.until,
        spec.target,
        spec.dataset,
        spec.limit,
        {"target_field": field, "api_operation": "GraphQL data lake query"},
    )


def _graylog(spec: QuerySpec) -> QueryPlan:
    field = spec.target_field or "source"
    body = json_bytes(
        {
            "query": f'{field}:"{_quoted(spec.target)}"',
            "timerange": {"type": "absolute", "from": spec.since, "to": spec.until},
            "limit": spec.limit,
            "streams": [spec.dataset],
        }
    )
    return QueryPlan(
        spec.connector,
        "POST",
        f"{spec.base_url}/api/search/messages",
        "application/json",
        body,
        _credential(spec),
        "graylog-token",
        "graylog",
        spec.since,
        spec.until,
        spec.target,
        spec.dataset,
        spec.limit,
        {"target_field": field, "stream": spec.dataset},
    )


_BUILDERS = {
    "splunk": _splunk,
    "elastic": _elastic,
    "crowdstrike": _crowdstrike,
    "sentinel": _sentinel,
    "panther": _panther,
    "graylog": _graylog,
}


def build_query_plan(spec: QuerySpec) -> QueryPlan:
    if spec.connector not in CONNECTOR_NAMES:
        raise ValueError(f"unsupported live connector: {spec.connector}")
    return _BUILDERS[spec.connector](spec)


def _plan_base_url(plan: QueryPlan) -> str:
    suffixes = {
        "splunk": "/services/search/v2/jobs/export",
        "elastic": f"/{quote(plan.dataset, safe='._-')}/_search",
        "crowdstrike": f"/api/v1/repositories/{quote(plan.dataset, safe='._-')}/query",
        "sentinel": f"/v1/workspaces/{quote(plan.dataset.split(':', 1)[0], safe='-')}/query",
        "panther": "/public/graphql",
        "graylog": "/api/search/messages",
    }
    try:
        suffix = suffixes[plan.connector]
    except KeyError as exc:
        raise ValueError(f"unsupported live connector: {plan.connector}") from exc
    if not plan.url.endswith(suffix):
        raise ValueError("live query plan endpoint does not match its connector")
    return plan.url[: -len(suffix)]


def _validate_generated_plan(plan: QueryPlan) -> None:
    """Reject manually forged or mutated plans before any transport is called."""

    target_field = plan.metadata.get("target_field")
    if target_field is not None and not isinstance(target_field, str):
        raise ValueError("live query plan target_field must be a string")
    expected = build_query_plan(
        QuerySpec(
            connector=plan.connector,
            base_url=_plan_base_url(plan),
            dataset=plan.dataset,
            target=plan.target,
            since=plan.since,
            until=plan.until,
            limit=plan.limit,
            target_field=target_field,
            credential_env=plan.credential_env,
        )
    )
    if plan != expected:
        raise ValueError("live query plan was not produced by the reviewed connector builder")


def _json_payload(content: bytes) -> object:
    text = content.decode("utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        values: list[object] = []
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid live query JSON at line {line_number}") from exc
        return values


def _mapping_records(values: object) -> list[Mapping[str, object]]:
    if isinstance(values, Sequence) and not isinstance(values, (str, bytes, bytearray)):
        return [item for item in values if isinstance(item, Mapping)]
    if isinstance(values, Mapping):
        return [values]
    return []


def _extract_records(plan: QueryPlan, payload: object) -> list[Mapping[str, object]]:
    if plan.connector == "elastic" and isinstance(payload, Mapping):
        hits = payload.get("hits")
        values = hits.get("hits", ()) if isinstance(hits, Mapping) else ()
        records = []
        for item in _mapping_records(values):
            source = item.get("_source")
            if isinstance(source, Mapping):
                records.append({**source, "_id": item.get("_id")})
        return records
    if plan.connector == "sentinel" and isinstance(payload, Mapping):
        tables = payload.get("tables")
        if not isinstance(tables, Sequence) or not tables:
            return []
        table = tables[0]
        if not isinstance(table, Mapping):
            return []
        columns = table.get("columns", ())
        names = [str(column.get("name")) for column in columns if isinstance(column, Mapping)]
        rows = table.get("rows", ())
        return [dict(zip(names, row)) for row in rows if isinstance(row, Sequence)]
    if plan.connector == "splunk":
        records: list[Mapping[str, object]] = []
        for item in _mapping_records(payload):
            result = item.get("result")
            if isinstance(result, Mapping):
                records.append(result)
            elif isinstance(item.get("results"), Sequence):
                records.extend(_mapping_records(item["results"]))
        return records
    if plan.connector == "graylog" and isinstance(payload, Mapping):
        values = payload.get("messages", payload.get("datarows", ()))
        records = []
        for item in _mapping_records(values):
            message = item.get("message")
            records.append(message if isinstance(message, Mapping) else item)
        return records
    if plan.connector == "crowdstrike":
        if isinstance(payload, Mapping):
            values = payload.get("events", payload.get("results", ()))
            return _mapping_records(values)
        return _mapping_records(payload)
    return _mapping_records(payload)


def _single_request(
    plan: QueryPlan,
    transport: QueryTransport,
    environ: Mapping[str, str] | None,
) -> LiveQueryResult:
    content = transport.request(
        plan.method, plan.url, authorization_headers(plan, environ), plan.body
    )
    records = _extract_records(plan, _json_payload(content))[: plan.limit]
    events = normalize_records(records, collector=plan.profile)
    return LiveQueryResult(plan, events, len(content))


def _panther_request(
    plan: QueryPlan,
    transport: QueryTransport,
    environ: Mapping[str, str] | None,
    sleeper: Callable[[float], None],
) -> LiveQueryResult:
    headers = authorization_headers(plan, environ)
    issued = transport.request(plan.method, plan.url, headers, plan.body)
    issued_value = _json_payload(issued)
    if not isinstance(issued_value, Mapping):
        raise ValueError("Panther query response must be an object")
    data = issued_value.get("data")
    operation = data.get("executeDataLakeQuery") if isinstance(data, Mapping) else None
    query_id = operation.get("id") if isinstance(operation, Mapping) else None
    if not isinstance(query_id, str) or not query_id:
        raise RuntimeError("Panther did not return a data lake query ID")
    total_bytes = len(issued)
    poll_query = (
        "query AgentSimQueryResults($id: ID!) { dataLakeQuery(id: $id) { message status "
        "results { edges { node } pageInfo { hasNextPage endCursor } } } }"
    )
    for request_count in range(2, 22):
        poll_body = json_bytes({"query": poll_query, "variables": {"id": query_id}})
        content = transport.request("POST", plan.url, headers, poll_body)
        total_bytes += len(content)
        value = _json_payload(content)
        data = value.get("data") if isinstance(value, Mapping) else None
        result = data.get("dataLakeQuery") if isinstance(data, Mapping) else None
        status = result.get("status") if isinstance(result, Mapping) else None
        if status == "running":
            sleeper(0.25)
            continue
        if status != "succeeded":
            raise RuntimeError("Panther data lake query did not succeed")
        values = result.get("results") if isinstance(result, Mapping) else None
        edges = values.get("edges", ()) if isinstance(values, Mapping) else ()
        records: list[Mapping[str, object]] = []
        for edge in _mapping_records(edges):
            node = edge.get("node")
            if isinstance(node, str):
                try:
                    node = json.loads(node)
                except json.JSONDecodeError:
                    continue
            if isinstance(node, Mapping):
                records.append(node)
        events = normalize_records(records[: plan.limit], collector=plan.profile)
        return LiveQueryResult(plan, events, total_bytes, request_count, query_id)
    raise RuntimeError("Panther data lake query did not complete within 20 polls")


def execute_query_plan(
    plan: QueryPlan,
    *,
    allow_network: bool = False,
    transport: QueryTransport | None = None,
    environ: Mapping[str, str] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> LiveQueryResult:
    """Execute only after an explicit network opt-in; all requests remain read-only queries."""

    if not allow_network:
        raise PermissionError("live telemetry execution requires allow_network=True")
    _validate_generated_plan(plan)
    selected = transport or HttpQueryTransport()
    if plan.connector == "panther":
        return _panther_request(plan, selected, environ, sleeper)
    return _single_request(plan, selected, environ)
