#!/usr/bin/env python3

import argparse
import json
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import hjson
except ImportError:
    hjson = None

FIELD_IN_QUERY_RE = re.compile(r'(?<![\w.])([A-Za-z0-9_@][A-Za-z0-9_@.\-]*)\s*:')


def strip_field_boost(field: str) -> str:
    """
    Kibana/Lucene query_string fields may look like:
      foo^2
    Return just:
      foo
    """
    return field.split("^", 1)[0]


def add_field(fields: Set[str], value: Any) -> None:
    """
    Add a field name to the set if it looks usable.
    """
    if isinstance(value, str):
        v = strip_field_boost(value.strip())
        if v and v != "*":
            fields.add(v)


def collect_fields_from_query_like(value: Any, fields: Set[str]) -> None:
    """
    Best-effort extraction of field names from OpenSearch/Elasticsearch
    query/filter DSL and Lucene/KQL-ish query strings.

    Handles common forms like:

      {"term": {"event.dataset": "conn"}}
      {"terms": {"event.provider": ["zeek", "suricata"]}}
      {"match_phrase": {"network.protocol": "http"}}
      {"range": {"@timestamp": {"gte": "now-1d"}}}
      {"exists": {"field": "source.ip"}}
      {"query_string": {"query": "event.dataset:pe AND source.ip:*"}}

    It is intentionally recursive so it works inside bool/filter/must/etc.
    """
    if isinstance(value, dict):
        for k, v in value.items():

            # Query DSL forms where field names are object keys.
            if k in {
                "term",
                "terms",
                "match",
                "match_phrase",
                "range",
                "prefix",
                "wildcard",
                "regexp",
            }:
                if isinstance(v, dict):
                    for field_name in v.keys():
                        add_field(fields, field_name)

            # Exists query uses {"field": "..."}.
            elif k == "exists":
                if isinstance(v, dict):
                    add_field(fields, v.get("field"))

            # query_string/simple_query_string may contain field:value text.
            elif k in {"query_string", "simple_query_string"}:
                if isinstance(v, dict):
                    q = v.get("query")
                    if isinstance(q, str):
                        for m in FIELD_IN_QUERY_RE.finditer(q):
                            add_field(fields, m.group(1))

                    q_fields = v.get("fields")
                    if isinstance(q_fields, list):
                        for f in q_fields:
                            add_field(fields, f)

                    default_field = v.get("default_field")
                    add_field(fields, default_field)

            # Kibana/OpenSearch searchSource often has:
            # {"query": {"query": "event.dataset:pe", "


VEGA_TIMEFIELD_RE = re.compile(r'%timefield%\s*:\s*(?:"([^"]+)"|([A-Za-z0-9_@.\-]+))')

VEGA_TERMS_FIELD_RE = re.compile(
    r'terms\s*:\s*\{[^{}]*field\s*:\s*(?:"([^"]+)"|([A-Za-z0-9_@.\-]+))',
    re.DOTALL,
)

VEGA_MATCH_PHRASE_RE = re.compile(
    r'\\*"match_phrase\\*"\s*:\s*\{\s*\\*"([^"\\]+)\\*"\s*:',
    re.DOTALL,
)


def parse_vega_spec(spec: Any) -> Optional[Dict[str, Any]]:
    """
    Vega specs in Kibana/OpenSearch Dashboards are often HJSON:
      - comments
      - unquoted keys
      - unquoted string values
      - trailing commas may appear in some exports

    Use hjson if available.
    """
    if not isinstance(spec, str) or not spec.strip():
        return None

    if hjson is None:
        return None

    try:
        parsed = hjson.loads(spec)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def iter_dicts(value: Any) -> Iterable[Dict[str, Any]]:
    """
    Recursively yield dictionaries from a nested JSON/HJSON structure.
    """
    if isinstance(value, dict):
        yield value
        for v in value.values():
            yield from iter_dicts(v)
    elif isinstance(value, list):
        for item in value:
            yield from iter_dicts(item)


def collect_fields_from_vega_text_fallback(spec_text: str, fields: Set[str]) -> None:
    """
    Fallback extraction for Vega specs when HJSON parsing is not available
    or fails.

    This intentionally focuses on Elasticsearch-looking constructs, not every
    Vega "field", because many Vega fields are internal derived fields such as:
      stk1, stk2, y0, y1, grpId, size, etc.
    """
    if not isinstance(spec_text, str):
        return

    for m in VEGA_TIMEFIELD_RE.finditer(spec_text):
        add_field(fields, m.group(1) or m.group(2))

    for m in VEGA_TERMS_FIELD_RE.finditer(spec_text):
        add_field(fields, m.group(1) or m.group(2))

    # Signal strings like:
    # opensearchDashboardsAddFilter({\"match_phrase\": { \"event.action\": datum.grpId } }, ...)
    for m in VEGA_MATCH_PHRASE_RE.finditer(spec_text):
        add_field(fields, m.group(1))

    # Also catch simple query-string-looking text embedded in the Vega spec.
    # This is best-effort.
    for m in FIELD_IN_QUERY_RE.finditer(spec_text):
        candidate = m.group(1)
        # Avoid obvious Vega-ish or URL-ish false positives.
        if candidate not in {
            "http",
            "https",
            "type",
            "name",
            "scale",
            "field",
            "data",
            "source",
            "target",
            "events",
            "update",
            "signal",
            "expr",
        }:
            add_field(fields, candidate)


def extract_vega_url_requests_from_spec(
    parsed_spec: Dict[str, Any],
    fields: Set[str],
) -> List[Dict[str, Any]]:
    """
    Extract OpenSearch/Elasticsearch requests from parsed Vega spec objects.

    In Kibana/OpenSearch Dashboards, these are typically under:

      data[].url

    Example:

      url: {
        %context%: true
        %timefield%: @timestamp
        index: my-index-*
        body: {
          size: 0
          aggs: {
            x: {
              terms: { field: "event.action" }
            }
          }
        }
      }
    """
    requests: List[Dict[str, Any]] = []

    for d in iter_dicts(parsed_spec):
        url = d.get("url")
        if not isinstance(url, dict):
            continue

        data_name = d.get("name")

        timefield = url.get("%timefield%") or url.get("timefield")
        index = url.get("index")
        body = url.get("body")

        add_field(fields, timefield)

        if isinstance(body, dict):
            # Only inspect the ES request body, not the entire Vega spec.
            collect_fields_from_query_like(body, fields)
            collect_fields_by_key(body, fields)

        request_summary: Dict[str, Any] = {
            "dataName": data_name,
            "context": url.get("%context%"),
            "timefield": timefield,
            "index": index,
        }

        if body is not None:
            request_summary["body"] = body

        requests.append(request_summary)

    return requests


def collect_vega_add_filter_fields_from_text(spec_text: str, fields: Set[str]) -> None:
    """
    Extract fields used in interactive filters created by Vega signals.

    Example from your export:

      opensearchDashboardsAddFilter(
        {\"match_phrase\": { \"event.action\": datum.grpId } },
        'MALCOLM_NETWORK_INDEX_PATTERN_REPLACER'
      )

    This does not try to parse arbitrary JavaScript. It just catches common
    match_phrase / term / terms / range / exists filter objects embedded
    inside signal strings.
    """
    if not isinstance(spec_text, str):
        return

    # Escaped or unescaped versions of common filter clauses.
    patterns = [
        r'\\*"match_phrase\\*"\s*:\s*\{\s*\\*"([^"\\]+)\\*"\s*:',
        r'\\*"term\\*"\s*:\s*\{\s*\\*"([^"\\]+)\\*"\s*:',
        r'\\*"terms\\*"\s*:\s*\{\s*\\*"([^"\\]+)\\*"\s*:',
        r'\\*"range\\*"\s*:\s*\{\s*\\*"([^"\\]+)\\*"\s*:',
        r'"match_phrase"\s*:\s*\{\s*"([^"]+)"\s*:',
        r'"term"\s*:\s*\{\s*"([^"]+)"\s*:',
        r'"terms"\s*:\s*\{\s*"([^"]+)"\s*:',
        r'"range"\s*:\s*\{\s*"([^"]+)"\s*:',
    ]

    for pat in patterns:
        for m in re.finditer(pat, spec_text):
            add_field(fields, m.group(1))


def extract_vega_info(vis_state: Dict[str, Any], fields: Set[str]) -> Dict[str, Any]:
    """
    Return a summary of Vega-specific query/request info and update fields.
    """
    params = vis_state.get("params") or {}
    spec_text = params.get("spec")

    result: Dict[str, Any] = {
        "hasSpec": isinstance(spec_text, str) and bool(spec_text.strip()),
        "parsed": False,
        "requests": [],
    }

    if not isinstance(spec_text, str) or not spec_text.strip():
        return result

    parsed_spec = parse_vega_spec(spec_text)

    if parsed_spec:
        result["parsed"] = True
        result["requests"] = extract_vega_url_requests_from_spec(parsed_spec, fields)
    else:
        result["parseWarning"] = (
            "Could not parse Vega spec as HJSON. "
            "Using regex fallback; field list may be incomplete or contain false positives."
        )
        collect_fields_from_vega_text_fallback(spec_text, fields)

    # Do this in either case, because signal update strings may contain escaped
    # filter JSON even when the full Vega spec parsed successfully.
    collect_vega_add_filter_fields_from_text(spec_text, fields)

    return result


def parse_json_maybe(value: Any, default: Any = None) -> Any:
    """
    OpenSearch/Kibana saved objects often store JSON as strings.
    Parse strings that contain JSON; otherwise return the original value.
    """
    if value is None:
        return default
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return default
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return value
    return value


def get_attr(obj: Dict[str, Any], key: str, default: Any = None) -> Any:
    return obj.get("attributes", {}).get(key, default)


def get_search_source(obj: Dict[str, Any]) -> Dict[str, Any]:
    meta = get_attr(obj, "kibanaSavedObjectMeta", {}) or {}
    ss = parse_json_maybe(meta.get("searchSourceJSON"), {})
    return ss if isinstance(ss, dict) else {}


def strip_field_boost(field: str) -> str:
    # Kibana query_string fields may look like "foo^2"
    return field.split("^", 1)[0]


def add_field(fields: Set[str], value: Any) -> None:
    if isinstance(value, str):
        v = strip_field_boost(value.strip())
        if v and v != "*":
            fields.add(v)


def collect_fields_by_key(value: Any, fields: Set[str]) -> None:
    """
    Generic extraction of values under keys commonly used for field references
    in saved object definitions.

    Note:
      - "field" is used by classic visualizations and ES aggregations.
      - "fieldName" is used by input_control_vis controls.
      - "fields" is used in several places, but in Vega it can also refer to
        internal Vega data fields. For parsed Vega specs we avoid using this
        function on the entire spec and instead inspect only ES request bodies.
    """
    if isinstance(value, dict):
        for k, v in value.items():
            if k in {"field", "fieldName"}:
                add_field(fields, v)

            elif k == "fields":
                if isinstance(v, list):
                    for item in v:
                        add_field(fields, item)
                elif isinstance(v, str):
                    add_field(fields, v)

            collect_fields_by_key(v, fields)

    elif isinstance(value, list):
        for item in value:
            collect_fields_by_key(item, fields)


def collect_fields_by_key(value: Any, fields: Set[str]) -> None:
    """
    Generic extraction of values under keys commonly used for field references
    in saved object definitions: field, fields.
    """
    if isinstance(value, dict):
        for k, v in value.items():
            if k == "field":
                add_field(fields, v)
            elif k == "fields":
                if isinstance(v, list):
                    for item in v:
                        add_field(fields, item)
                elif isinstance(v, str):
                    add_field(fields, v)

            collect_fields_by_key(v, fields)

    elif isinstance(value, list):
        for item in value:
            collect_fields_by_key(item, fields)


def collect_fields_from_saved_search(search_obj: Dict[str, Any], fields: Set[str]) -> None:
    attrs = search_obj.get("attributes", {})

    columns = attrs.get("columns") or []
    if isinstance(columns, list):
        for c in columns:
            add_field(fields, c)

    sort = attrs.get("sort") or []
    if isinstance(sort, list):
        for item in sort:
            if isinstance(item, list) and item:
                add_field(fields, item[0])
            elif isinstance(item, str):
                add_field(fields, item)

    ss = get_search_source(search_obj)
    collect_fields_from_query_like(ss, fields)
    collect_fields_by_key(ss, fields)


def find_referenced_saved_search(
    vis_obj: Dict[str, Any],
    objects_by_key: Dict[Tuple[str, str], Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Classic visualizations often reference a saved search by attributes.savedSearchRefName.
    """
    attrs = vis_obj.get("attributes", {})
    wanted_name = attrs.get("savedSearchRefName")

    refs = vis_obj.get("references", []) or []

    if wanted_name:
        for ref in refs:
            if ref.get("type") == "search" and ref.get("name") == wanted_name:
                return objects_by_key.get(("search", ref.get("id")))

    # Fallback: first search reference.
    for ref in refs:
        if ref.get("type") == "search":
            return objects_by_key.get(("search", ref.get("id")))

    return None


def compact_search_source(ss: Dict[str, Any]) -> Dict[str, Any]:
    """
    Keep the useful query/filter/index parts instead of dumping irrelevant state.
    """
    out: Dict[str, Any] = {}

    if "query" in ss:
        out["query"] = ss.get("query")

    if "filter" in ss:
        out["filter"] = ss.get("filter")

    if "index" in ss:
        out["index"] = ss.get("index")

    if "indexRefName" in ss:
        out["indexRefName"] = ss.get("indexRefName")

    # Include other keys only if needed.
    return out


def extract_visualization_panel(
    panel: Dict[str, Any],
    vis_obj: Dict[str, Any],
    dashboard_search_source: Dict[str, Any],
    objects_by_key: Dict[Tuple[str, str], Dict[str, Any]],
) -> Dict[str, Any]:
    attrs = vis_obj.get("attributes", {})

    vis_state = parse_json_maybe(attrs.get("visState"), {})
    if not isinstance(vis_state, dict):
        vis_state = {}

    vis_search_source = get_search_source(vis_obj)
    saved_search_obj = find_referenced_saved_search(vis_obj, objects_by_key)

    panel_title_override = panel.get("title") or (panel.get("embeddableConfig") or {}).get("title")

    title = panel_title_override or attrs.get("title") or vis_state.get("title") or ""

    fields: Set[str] = set()

    visualization_type = vis_state.get("type")

    vega_info = None

    if visualization_type == "vega":
        # For Vega, do NOT call collect_fields_by_key() on the whole parsed spec,
        # because Vega has many internal fields: stk1, stk2, y0, y1, grpId, etc.
        #
        # Instead:
        #   1. collect normal visualization search source fields
        #   2. inspect only Vega ES url.body sections and Vega add-filter signals
        vega_info = extract_vega_info(vis_state, fields)
    else:
        # Fields used by classic visualization aggregations/config.
        collect_fields_by_key(vis_state, fields)

    # Fields from visualization search source.
    collect_fields_from_query_like(vis_search_source, fields)
    collect_fields_by_key(vis_search_source, fields)

    saved_search_summary = None
    if saved_search_obj:
        collect_fields_from_saved_search(saved_search_obj, fields)

        saved_search_summary = {
            "id": saved_search_obj.get("id"),
            "title": get_attr(saved_search_obj, "title", ""),
            "description": get_attr(saved_search_obj, "description", ""),
            "columns": get_attr(saved_search_obj, "columns", []),
            "sort": get_attr(saved_search_obj, "sort", []),
            "searchSource": compact_search_source(get_search_source(saved_search_obj)),
        }

    out = {
        "panelIndex": panel.get("panelIndex"),
        "panelRefName": panel.get("panelRefName"),
        "objectType": "visualization",
        "objectId": vis_obj.get("id"),
        "title": title,
        "description": attrs.get("description", ""),
        "visualizationType": visualization_type,
        "querySources": {
            "dashboard": compact_search_source(dashboard_search_source),
            "visualization": compact_search_source(vis_search_source),
            "savedSearch": saved_search_summary["searchSource"] if saved_search_summary else None,
        },
        "savedSearch": saved_search_summary,
        "fields": sorted(fields),
    }

    if vega_info is not None:
        out["vega"] = vega_info
        out["querySources"]["vegaRequests"] = vega_info.get("requests", [])

    return out


def extract_search_panel(
    panel: Dict[str, Any],
    search_obj: Dict[str, Any],
    dashboard_search_source: Dict[str, Any],
) -> Dict[str, Any]:
    attrs = search_obj.get("attributes", {})
    ss = get_search_source(search_obj)

    panel_title_override = panel.get("title") or (panel.get("embeddableConfig") or {}).get("title")

    fields: Set[str] = set()
    collect_fields_from_saved_search(search_obj, fields)

    return {
        "panelIndex": panel.get("panelIndex"),
        "panelRefName": panel.get("panelRefName"),
        "objectType": "search",
        "objectId": search_obj.get("id"),
        "title": panel_title_override or attrs.get("title", ""),
        "description": attrs.get("description", ""),
        "querySources": {
            "dashboard": compact_search_source(dashboard_search_source),
            "search": compact_search_source(ss),
        },
        "columns": attrs.get("columns", []),
        "sort": attrs.get("sort", []),
        "fields": sorted(fields),
    }


def extract_dashboard(
    dashboard_obj: Dict[str, Any],
    objects_by_key: Dict[Tuple[str, str], Dict[str, Any]],
) -> Dict[str, Any]:
    attrs = dashboard_obj.get("attributes", {})
    dashboard_search_source = get_search_source(dashboard_obj)

    panels = parse_json_maybe(attrs.get("panelsJSON"), [])
    if not isinstance(panels, list):
        panels = []

    refs_by_name = {ref.get("name"): ref for ref in dashboard_obj.get("references", []) or [] if ref.get("name")}

    extracted_panels: List[Dict[str, Any]] = []

    for panel in panels:
        ref_name = panel.get("panelRefName")
        ref = refs_by_name.get(ref_name)

        if not ref:
            extracted_panels.append(
                {
                    "panelIndex": panel.get("panelIndex"),
                    "panelRefName": ref_name,
                    "error": "No matching dashboard reference found",
                }
            )
            continue

        obj_type = ref.get("type")
        obj_id = ref.get("id")
        embedded_obj = objects_by_key.get((obj_type, obj_id))

        if not embedded_obj:
            extracted_panels.append(
                {
                    "panelIndex": panel.get("panelIndex"),
                    "panelRefName": ref_name,
                    "objectType": obj_type,
                    "objectId": obj_id,
                    "error": "Referenced object not found in export",
                }
            )
            continue

        if obj_type == "visualization":
            extracted_panels.append(
                extract_visualization_panel(
                    panel,
                    embedded_obj,
                    dashboard_search_source,
                    objects_by_key,
                )
            )
        elif obj_type == "search":
            extracted_panels.append(
                extract_search_panel(
                    panel,
                    embedded_obj,
                    dashboard_search_source,
                )
            )
        else:
            extracted_panels.append(
                {
                    "panelIndex": panel.get("panelIndex"),
                    "panelRefName": ref_name,
                    "objectType": obj_type,
                    "objectId": obj_id,
                    "title": get_attr(embedded_obj, "title", ""),
                    "description": get_attr(embedded_obj, "description", ""),
                    "note": "Unsupported panel object type",
                }
            )

    return {
        "id": dashboard_obj.get("id"),
        "title": attrs.get("title", ""),
        "description": attrs.get("description", ""),
        "searchSource": compact_search_source(dashboard_search_source),
        "panels": extracted_panels,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract dashboard/panel titles, queries, filters, and fields from an OpenSearch Dashboards saved-object export."
    )
    parser.add_argument("file", help="Saved-object export JSON file")
    parser.add_argument(
        "--dashboard-id",
        help="Only extract a specific dashboard id",
    )
    args = parser.parse_args()

    with open(args.file, "r", encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])
    if not isinstance(objects, list):
        print("Input JSON does not contain an objects array", file=sys.stderr)
        return 1

    objects_by_key: Dict[Tuple[str, str], Dict[str, Any]] = {
        (obj.get("type"), obj.get("id")): obj for obj in objects if obj.get("type") and obj.get("id")
    }

    dashboards = [
        obj
        for obj in objects
        if obj.get("type") == "dashboard" and (args.dashboard_id is None or obj.get("id") == args.dashboard_id)
    ]

    result = {"dashboards": [extract_dashboard(dashboard_obj, objects_by_key) for dashboard_obj in dashboards]}

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
