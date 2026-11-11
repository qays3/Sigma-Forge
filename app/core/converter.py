import json
from typing import Any, Dict, List

from sigma.collection import SigmaCollection

from app.config import WAZUH_MAX_RULES_PER_SIGMA, WAZUH_RULE_ID_START
from app.core.parsing import parse_inputs
from app.core.targets import TARGET_MAP, build_backend, target_formats
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


def _bundle_text(output: Any) -> str:
    if isinstance(output, str):
        return output
    if isinstance(output, list):
        if all(isinstance(x, str) for x in output):
            return "\n".join(output)
        return json.dumps(output, indent=2, default=str)
    return _to_text(output)


def convert(inputs, target_id: str, fmt: str, options) -> Dict:
    target = TARGET_MAP.get(target_id)
    if target is None:
        raise ConversionRequestError(f"Unknown target: {target_id}")
    formats = target_formats(target)
    if fmt not in formats:
        raise ConversionRequestError(f"Format '{fmt}' is not supported by {target.name}. Choose one of: {', '.join(formats)}")

    items = list(inputs)
    parsed = parse_inputs(items)
    results: List[Dict] = []

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
        return _response(target, fmt, results, bundle, None, notes)

    backend = build_backend(target)
    for p in parsed:
        row = _row(p)
        if p.kind == "correlation" and p.correlation is not None and not p.error:
            try:
                row["queries"] = _convert_correlation(target, items, p, fmt)
            except Exception as exc:
                row["error"] = str(exc)
        elif p.rule is not None and not p.error:
            try:
                queries = backend.convert_rule(p.rule, fmt)
                row["queries"] = [_to_text(q) for q in queries]
                if not row["queries"]:
                    row["meta"]["skipped"] = True
                    row["warnings"].append("This rule is only used inside a correlation rule, so it has no query of its own. Add 'generate: true' to the rule to convert it alone too.")
            except Exception as exc:
                row["error"] = str(exc)
        results.append(row)

    bundle, bundle_error = "", None
    ok_keys = {r["key"] for r in results if not r["error"] and r["queries"]}
    if ok_keys:
        try:
            fresh = [p.rule for p in parse_inputs(items) if p.rule is not None and p.key in ok_keys]
            parts = [_bundle_text(build_backend(target).convert(SigmaCollection(fresh), fmt))] if fresh else []
            parts += [q for r in results if r.get("kind") == "correlation" and not r["error"] for q in r["queries"]]
            bundle = "\n".join(x for x in parts if x)
        except Exception as exc:
            bundle_error = str(exc)
    return _response(target, fmt, results, bundle, bundle_error, [])


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
    if isinstance(output, list):
        return [_to_text(q) for q in output]
    return [_to_text(output)]


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


def _response(target, fmt, results, bundle, bundle_error, notes) -> Dict:
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
    }
