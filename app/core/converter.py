import json
import re
from typing import Any, Dict, List

from sigma.collection import SigmaCollection

from app.config import WAZUH_MAX_RULES_PER_SIGMA, WAZUH_RULE_ID_START
from app.core.fieldmap import MappingError, map_inputs
from app.core.parsing import parse_inputs
from app.core.targets import TARGET_MAP, build_backend, build_relaxed_backend, target_formats
from app.core.wazuh.backend import WazuhBackend, WazuhOptions


class ConversionRequestError(ValueError):
    pass


def _to_text(item: Any) -> str:
    if isinstance(item, str):
        return item
    try:
        return json.dumps(item, indent=2, default=str)
    except TypeError:
        return str(item)


def _bundle_text(output: Any, fmt: str = "") -> str:
    if isinstance(output, str):
        return output
    if isinstance(output, list) and fmt.endswith("ndjson"):
        return "\n".join(x if isinstance(x, str) else json.dumps(x, default=str) for x in output)
    if isinstance(output, list):
        if all(isinstance(x, str) for x in output):
            return "\n".join(output)
        return json.dumps(output, indent=2, default=str)
    return _to_text(output)


def convert(inputs, target_id: str, fmt: str, options, field_mapping=None) -> Dict:
    target = TARGET_MAP.get(target_id)
    if target is None:
        raise ConversionRequestError(f"Unknown target: {target_id}")
    formats = target_formats(target)
    if fmt not in formats:
        raise ConversionRequestError(f"Format '{fmt}' is not supported by {target.name}. Choose one of: {', '.join(formats)}")

    try:
        items, mapped = map_inputs(inputs, field_mapping or {})
    except MappingError as exc:
        raise ConversionRequestError(str(exc))
    parsed = parse_inputs(items)
    results: List[Dict] = []
    mapping_note = _mapping_note(mapped)

    if target.backend is None:
        wazuh = WazuhBackend(WazuhOptions(
            rule_id_start=options.wazuh_rule_id_start or WAZUH_RULE_ID_START,
            double_backslash=options.wazuh_double_backslash,
            parent_group=options.wazuh_parent_group,
            max_split=WAZUH_MAX_RULES_PER_SIGMA,
        ))
        chunks = []
        for p in parsed:
            row = _row(p)
            if p.kind == "correlation" and p.correlation is not None and not p.error:
                try:
                    res = wazuh.convert_correlation(p.correlation)
                    row["queries"] = [res.xml]
                    row["warnings"] = res.warnings
                    row["meta"] = {"rule_ids": res.rule_ids}
                    chunks.append(res.xml)
                except Exception as exc:
                    row["error"] = str(exc)
            elif p.rule is not None and not p.error:
                try:
                    res = wazuh.convert_rule(p.rule)
                    row["queries"] = [res.xml]
                    row["warnings"] = res.warnings
                    row["meta"] = {"rule_ids": res.rule_ids}
                    chunks.append(res.xml)
                except Exception as exc:
                    row["error"] = str(exc)
            results.append(row)
        bundle = "\n".join(chunks)
        notes = ["Wazuh rules use pcre2 field matching. Test them on your manager with tools/wazuh_check.py before production."]
        if options.wazuh_double_backslash:
            notes.append("Backslashes are matched doubled because Wazuh eventchannel fields keep escaped backslashes. Turn this off if your data has single backslashes.")
        return _response(target, fmt, results, bundle, None, notes + mapping_note, mapped)

    backend = build_backend(target)
    for p in parsed:
        row = _row(p)
        if p.kind == "correlation" and p.correlation is not None and not p.error:
            try:
                row["queries"] = _convert_correlation(target, items, p, fmt)
            except Exception as exc:
                alt = ALTERNATES.get(target.id)
                if alt:
                    try:
                        alt_target = TARGET_MAP[alt[0]]
                        row["queries"] = _convert_correlation(alt_target, items, p, "default")
                        row["warnings"].append(alt[1])
                        row["meta"]["fallback"] = True
                        results.append(row)
                        continue
                    except Exception:
                        pass
                message = str(exc)
                if "not supported by backend" in message.lower() or "does not support correlation" in message.lower():
                    message = f"{target.name} cannot convert correlation rules. Splunk SPL, Elastic ES|QL, EQL, ElastAlert, OpenSearch PPL, Grafana Loki, ClickHouse, SQLite and Wazuh can."
                row["error"] = message
        elif p.rule is not None and not p.error:
            try:
                queries = backend.convert_rule(p.rule, fmt)
                row["queries"] = [_to_text(q) for q in queries]
                if not row["queries"]:
                    row["meta"]["skipped"] = True
                    row["warnings"].append("This rule is only used inside a correlation rule, so it has no query of its own. Add 'generate: true' to the rule to convert it alone too.")
            except Exception as exc:
                rescued = _convert_with_fallbacks(target, items, p, fmt, exc)
                if rescued is not None:
                    row["queries"], notes = rescued
                    row["warnings"].extend(notes)
                    row["meta"]["fallback"] = True
                    if not row["queries"]:
                        row["meta"]["skipped"] = True
                        row["warnings"].append("This rule is only used inside a correlation rule, so it has no query of its own. Add 'generate: true' to the rule to convert it alone too.")
                else:
                    row["error"] = str(exc)
        results.append(row)

    bundle, bundle_error, bundle_base = "", None, ""
    ok_keys = {r["key"] for r in results if not r["error"] and r["queries"] and not r["meta"].get("fallback")}
    if ok_keys or any(r["meta"].get("fallback") for r in results):
        try:
            fresh = [p.rule for p in parse_inputs(items) if p.rule is not None and p.key in ok_keys]
            parts = [_bundle_text(build_backend(target).convert(SigmaCollection(fresh), fmt), fmt)] if fresh else []
            bundle_base = parts[0] if parts else ""
            parts += [_compact(q, fmt) for r in results if (r.get("kind") == "correlation" or r["meta"].get("fallback")) and not r["error"] for q in r["queries"]]
            bundle = "\n".join(x for x in parts if x)
        except Exception as exc:
            bundle_error = str(exc)
    if fmt == "default" and target_id != "sqlite":
        from app.core.cost import check as cost_check, score as cost_score

        for r in results:
            if r["queries"] and not r["error"]:
                items_cost = cost_check(target_id, target.language, r["queries"][0])
                r["cost"] = {"rating": cost_score(items_cost), "items": items_cost}
    response = _response(target, fmt, results, bundle, bundle_error, list(target.notes) + mapping_note, mapped)
    response["bundle_base"] = bundle_base
    return response


def _compact(text: str, fmt: str) -> str:
    if not fmt.endswith("ndjson"):
        return text
    try:
        return json.dumps(json.loads(text), default=str)
    except ValueError:
        return text


def _convert_correlation(target, items, parsed, fmt) -> List[str]:
    source = next(i for i in items if i.name == parsed.file)
    fresh = SigmaCollection.from_yaml(source.content)
    fresh.resolve_rule_references()
    corr = fresh.rules[parsed.index]
    refs = [r.rule for r in corr.rules if getattr(r, "rule", None) is not None]
    for ref in refs:
        ref.correlation_rule = None
    sub = SigmaCollection([*refs, corr])
    sub.resolve_rule_references()
    output = build_backend(target).convert(sub, fmt)
    if fmt != "default" and "{'" in _bundle_text(output, fmt):
        output = build_backend(target).convert(sub, "default")
    if isinstance(output, list):
        return [_to_text(q) for q in output]
    return [_to_text(output)]


CASED_RE = re.compile(r"\|cased(?=[|:\s'\"])")

MAPPING_HINTS = (
    "invalid sigmadetectionitem field",
    "invalid fieldname",
    "invalid udm field",
    "unable to determine table",
    "rule type not yet supported",
    "supports only the following field",
    "only file name of parent image",
    "does not support the",
    "can't map any logtypes",
    "please use valid fields",
    "sigmanumber",
)

NOTE_CASED = "This target cannot match case sensitive text, so the cased modifier was dropped and the query matches any case."
NOTE_CIDR = "This target cannot join CIDR ranges with OR, so each range was turned into an IP prefix match."
NOTE_RELAXED = "This platform has no field or table mapping for this rule, so the Sigma field names were kept. Rename them to the fields in your data before you use the query."


NOTE_KEYWORDS = "This target has no full text search, so keywords are matched against a field named message. Change it to the field that holds the raw log line."
NOTE_EXISTS = "This target cannot test if a field exists, so the check became a match on any value."
NOTE_NULL = "This target cannot test for empty fields, so the check became a match on an empty string."
NOTE_NUMBERS = "Numbers were sent as text because this backend cannot handle number values."

FEATURE_HINTS = {
    "keywords": ("value-only string", "string value expressions", "unbound value expressions", "full text"),
    "exists": ("exists expressions", "field existence"),
    "null": ("null expressions",),
    "numbers": ("sigmanumber",),
}


def _rewrite_items(rule, features) -> set:
    from sigma.rule import SigmaDetection, SigmaDetectionItem
    from sigma.types import SigmaCIDRExpression, SigmaExists, SigmaNull, SigmaNumber, SigmaString

    used = set()

    def walk(node):
        if isinstance(node, SigmaDetection):
            for item in node.detection_items:
                walk(item)
            return
        if not isinstance(node, SigmaDetectionItem):
            return
        if "keywords" in features and node.field is None:
            node.field = "message"
            node.value = [SigmaString(f"*{v.to_plain()}*") if isinstance(v, SigmaString) and not v.contains_special() else v for v in node.value]
            used.add("keywords")
        values = []
        for value in node.value:
            if "cidr" in features and isinstance(value, SigmaCIDRExpression):
                values.extend(SigmaString(prefix) for prefix in value.expand(wildcard="*"))
                used.add("cidr")
            elif "exists" in features and isinstance(value, SigmaExists):
                if value.exists:
                    values.append(SigmaString("*"))
                    used.add("exists")
                else:
                    values.append(value)
            elif "null" in features and isinstance(value, SigmaNull):
                values.append(SigmaString(""))
                used.add("null")
            elif "numbers" in features and isinstance(value, SigmaNumber):
                values.append(SigmaString(str(value.number)))
                used.add("numbers")
            else:
                values.append(value)
        node.value = values

    for detection in rule.detection.detections.values():
        walk(detection)
    return used


def _features_for(message: str) -> set:
    found = set()
    for name, hints in FEATURE_HINTS.items():
        if any(h in message for h in hints):
            found.add(name)
    if "cidr" in message:
        found.add("cidr")
    return found


def _convert_with_fallbacks(target, items, parsed, fmt, first_exc):
    source = next((i for i in items if i.name == parsed.file), None)
    if source is None:
        return None
    message = str(first_exc).lower()
    content = source.content
    drop_cased = "|cased" in content and ("case-sensitive" in message or "cased" in message)
    features = _features_for(message)
    relaxed = any(h in message for h in MAPPING_HINTS)
    if not (drop_cased or features or relaxed):
        return _alternate_target(target, content, parsed, fmt, [])

    text = content
    for attempt in range(6):
        text = CASED_RE.sub("", content) if drop_cased else content
        try:
            fresh = SigmaCollection.from_yaml(text)
            fresh.resolve_rule_references()
            rule = fresh.rules[parsed.index]
            used = _rewrite_items(rule, features)
            backend = build_relaxed_backend(target) if relaxed else build_backend(target)
            queries = [_to_text(q) for q in backend.convert_rule(rule, fmt)]
            if not queries:
                return [], []
            notes = []
            if drop_cased:
                notes.append(NOTE_CASED)
            notes += [n for k, n in (("cidr", NOTE_CIDR), ("keywords", NOTE_KEYWORDS), ("exists", NOTE_EXISTS), ("null", NOTE_NULL), ("numbers", NOTE_NUMBERS)) if k in used]
            if relaxed:
                notes.append(NOTE_RELAXED)
            return queries, notes
        except Exception as exc:
            msg = str(exc).lower()
            progressed = False
            if not drop_cased and "|cased" in content and ("case-sensitive" in msg or "cased" in msg):
                drop_cased = progressed = True
            new = _features_for(msg) - features
            if new:
                features |= new
                progressed = True
            if not relaxed and any(h in msg for h in MAPPING_HINTS):
                relaxed = progressed = True
            if not progressed:
                return _alternate_target(target, text, parsed, fmt, [])
    return _alternate_target(target, text, parsed, fmt, [])


ALTERNATES = {"splunk_cim": ("splunk", "No CIM data model fits this log source, so this is a plain SPL search over the raw events instead.")}


def _alternate_target(target, text, parsed, fmt, notes):
    alt = ALTERNATES.get(target.id)
    if not alt:
        return None
    alt_target = TARGET_MAP[alt[0]]
    alt_fmt = fmt if fmt in target_formats(alt_target) else "default"
    try:
        fresh = SigmaCollection.from_yaml(text)
        fresh.resolve_rule_references()
        queries = [_to_text(q) for q in build_backend(alt_target).convert_rule(fresh.rules[parsed.index], alt_fmt)]
    except Exception:
        return None
    return queries, ([alt[1]] if queries else [])


def _row(p) -> Dict:
    obj = p.rule if p.rule is not None else p.correlation
    return {
        "key": p.key,
        "file": p.file,
        "kind": p.kind,
        "title": obj.title if obj is not None else p.file,
        "level": obj.level.name.lower() if obj is not None and obj.level else "",
        "queries": [],
        "warnings": [],
        "error": p.error,
        "meta": {},
    }


def _mapping_note(mapped: Dict[str, int]) -> List[str]:
    if not mapped:
        return []
    names = ", ".join(sorted(mapped)[:8]) + (" and more" if len(mapped) > 8 else "")
    return [f"Your field mapping renamed {len(mapped)} field{'s' if len(mapped) != 1 else ''} before conversion: {names}."]


def _response(target, fmt, results, bundle, bundle_error, notes, mapped=None) -> Dict:
    ok = sum(1 for r in results if not r["error"] and r["queries"])
    skipped = sum(1 for r in results if not r["error"] and not r["queries"])
    return {
        "target": {"id": target.id, "name": target.name, "language": target.language},
        "format": fmt,
        "summary": {"total": len(results), "converted": ok, "skipped": skipped, "failed": len(results) - ok - skipped},
        "results": results,
        "bundle": bundle,
        "bundle_error": bundle_error,
        "notes": notes,
        "mapped_fields": mapped or {},
    }
