import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import re._parser as sre_parse
    import re._constants as sre_c
except ImportError:
    import sre_constants as sre_c
    import sre_parse

from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT, ConditionOR, ConditionValueExpression
from sigma.types import (
    SigmaBool,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from app.core.parsing import parse_inputs

BASE_TIME = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
FILLERS = [("C:\\Users\\Public\\tool", " test", " "), ("D:\\work\\app", " run", "_"), ("x", " y", "z")]
ABSENT = object()


class Unsupported(Exception):
    pass


def _regex_sample(pattern: str) -> str:
    try:
        parsed = sre_parse.parse(pattern)
    except Exception:
        raise Unsupported("regex too complex")
    return _walk(parsed)


def _walk(items) -> str:
    out = []
    for op, av in items:
        name = str(op)
        if op == sre_c.LITERAL:
            out.append(chr(av))
        elif op == sre_c.NOT_LITERAL:
            out.append("a" if chr(av) != "a" else "b")
        elif op == sre_c.ANY:
            out.append("a")
        elif op == sre_c.IN:
            out.append(_class_char(av))
        elif op in (sre_c.MAX_REPEAT, sre_c.MIN_REPEAT):
            lo, hi, sub = av
            count = lo if lo > 0 else (1 if hi and hi > 0 else 0)
            out.append(_walk(sub) * count)
        elif op == sre_c.SUBPATTERN:
            out.append(_walk(av[-1]))
        elif op == sre_c.BRANCH:
            out.append(_walk(av[1][0]))
        elif op == sre_c.AT:
            continue
        elif op in (sre_c.ASSERT, sre_c.ASSERT_NOT):
            continue
        elif op == sre_c.GROUPREF:
            continue
        elif op == sre_c.CATEGORY:
            out.append(_category(av))
        else:
            raise Unsupported(f"regex part {name}")
    return "".join(out)


def _category(cat) -> str:
    n = str(cat)
    if "DIGIT" in n and "NOT" not in n:
        return "1"
    if "SPACE" in n and "NOT" not in n:
        return " "
    if "WORD" in n and "NOT" not in n:
        return "a"
    if "NOT_DIGIT" in n or "NOT_SPACE" in n:
        return "a"
    return "-"


def _class_char(items) -> str:
    negate = False
    for op, av in items:
        if op == sre_c.NEGATE:
            negate = True
            continue
        if negate:
            continue
        if op == sre_c.LITERAL:
            return chr(av)
        if op == sre_c.RANGE:
            return chr(av[0])
        if op == sre_c.CATEGORY:
            return _category(av)
    return "q"


def _rx(value) -> str:
    rx = value.regexp
    return rx.original if hasattr(rx, "original") else str(rx)


def _shape(value):
    if not isinstance(value, SigmaString):
        return None, None
    parts = list(value.s)
    if any(not isinstance(p, str) and p != SpecialChars.WILDCARD_MULTI for p in parts):
        return None, None
    core = [p for p in parts if isinstance(p, str)]
    if len(core) != 1:
        if not core:
            return "any", ""
        return None, None
    lead = parts[0] == SpecialChars.WILDCARD_MULTI
    trail = parts[-1] == SpecialChars.WILDCARD_MULTI
    kind = {(True, True): "contains", (False, True): "start", (True, False): "end", (False, False): "exact"}[(lead, trail)]
    return kind, core[0]


def build_field(values, variant: int):
    if len(values) == 1:
        return make_value(values[0], variant)
    shaped = [_shape(v) for v in values]
    if all(k for k, _ in shaped):
        exact = [c for k, c in shaped if k == "exact"]
        if exact:
            cand = exact[0]
        else:
            lead, trail, _ = FILLERS[variant % len(FILLERS)]
            start = next((c for k, c in shaped if k == "start"), lead)
            end = next((c for k, c in shaped if k == "end"), trail)
            mids = "".join(c for k, c in shaped if k == "contains")
            cand = start + mids + end
        if all(matches(v, cand) for v in values):
            return cand
    first = make_value(values[0], variant)
    for v in values[1:]:
        extra = make_value(v, variant)
        if not isinstance(first, str) or not isinstance(extra, str):
            break
        first = f"{first} {extra}"
    if all(matches(v, first) for v in values):
        return first
    raise Unsupported("several values for one field")


def _string_value(value: SigmaString, variant: int) -> str:
    lead, trail, mid = FILLERS[variant % len(FILLERS)]
    parts = list(value.s)
    out = []
    for i, part in enumerate(parts):
        if isinstance(part, str):
            out.append(part)
        elif part == SpecialChars.WILDCARD_MULTI:
            if i == 0:
                out.append(lead)
            elif i == len(parts) - 1:
                out.append(trail)
            else:
                out.append(mid)
        elif part == SpecialChars.WILDCARD_SINGLE:
            out.append("a")
        else:
            raise Unsupported("placeholder in value")
    return "".join(out)


def make_value(value, variant: int = 0):
    if isinstance(value, SigmaExpansion):
        return make_value(value.values[variant % len(value.values)] if variant else value.values[0], 0)
    if isinstance(value, SigmaString):
        return _string_value(value, variant)
    if isinstance(value, SigmaRegularExpression):
        return _regex_sample(_rx(value))
    if isinstance(value, SigmaCIDRExpression):
        net = value.network
        return str(net[1] if net.num_addresses > 2 else net[0])
    if isinstance(value, SigmaCompareExpression):
        n = value.number.number
        op = value.op.name.lower() if hasattr(value.op, "name") else str(value.op)
        if op in ("gt",):
            return n + 1
        if op in ("lt",):
            return n - 1
        return n
    if isinstance(value, SigmaNumber):
        return value.number
    if isinstance(value, SigmaBool):
        return "true" if value.boolean else "false"
    if isinstance(value, SigmaNull):
        return ABSENT
    if isinstance(value, SigmaExists):
        return "present" if value.exists else ABSENT
    if isinstance(value, SigmaFieldReference):
        return ("ref", value.field)
    raise Unsupported(f"value type {type(value).__name__}")


def matches(value, got) -> bool:
    if got is ABSENT or got is None:
        if isinstance(value, SigmaNull):
            return True
        if isinstance(value, SigmaExists):
            return not value.exists
        return False
    text = str(got)
    if isinstance(value, SigmaExpansion):
        return any(matches(v, got) for v in value.values)
    if isinstance(value, SigmaString):
        rx = ""
        for part in value.s:
            if isinstance(part, str):
                rx += re.escape(part)
            elif part == SpecialChars.WILDCARD_MULTI:
                rx += ".*"
            elif part == SpecialChars.WILDCARD_SINGLE:
                rx += "."
        return re.fullmatch(rx, text, re.IGNORECASE | re.DOTALL) is not None
    if isinstance(value, SigmaRegularExpression):
        try:
            flags = re.IGNORECASE if any("IGNORECASE" in str(f) for f in (value.flags or [])) else 0
            return re.search(_rx(value), text, flags) is not None
        except re.error:
            return False
    if isinstance(value, SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(text) in value.network
        except ValueError:
            return False
    if isinstance(value, SigmaCompareExpression):
        try:
            n = float(text)
        except ValueError:
            return False
        op = value.op.name.lower()
        ref = value.number.number
        return {"lt": n < ref, "lte": n <= ref, "gt": n > ref, "gte": n >= ref}.get(op, False)
    if isinstance(value, SigmaNumber):
        return text == str(value.number)
    if isinstance(value, SigmaBool):
        return text.lower() == ("true" if value.boolean else "false")
    if isinstance(value, SigmaExists):
        return value.exists
    if isinstance(value, SigmaNull):
        return text == ""
    return False


def _constraints(node, positive=True) -> List[Tuple[str, Any, bool]]:
    if isinstance(node, ConditionAND):
        if positive:
            out = []
            for arg in node.args:
                out += _constraints(arg, True)
            return out
        return _constraints(node.args[0], False)
    if isinstance(node, ConditionOR):
        if positive:
            return _constraints(node.args[0], True)
        out = []
        for arg in node.args:
            out += _constraints(arg, False)
        return out
    if isinstance(node, ConditionNOT):
        return _constraints(node.args[0], not positive)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return [(node.field, node.value, positive)]
    if isinstance(node, ConditionValueExpression):
        return [(None, node.value, positive)]
    raise Unsupported(f"condition part {type(node).__name__}")


def event_for_rule(rule) -> Dict[str, Any]:
    last_error = None
    for variant in range(len(FILLERS)):
        try:
            return _try_event(rule, variant)
        except Unsupported as exc:
            last_error = exc
    raise last_error or Unsupported("no event")


def _try_event(rule, variant: int) -> Dict[str, Any]:
    event: Dict[str, Any] = {}
    positives: Dict[str, List[Any]] = {}
    avoid: List[Tuple[str, Any]] = []
    keywords: List[str] = []
    refs: List[Tuple[str, str]] = []
    for cond in rule.detection.parsed_condition:
        for field, value, positive in _constraints(cond.parsed):
            if field is None:
                if positive:
                    keywords.append(str(make_value(value, variant)))
                continue
            if not positive:
                avoid.append((field, value))
                continue
            if isinstance(value, SigmaFieldReference):
                refs.append((field, value.field))
                continue
            positives.setdefault(field, []).append(value)
    for field, values in positives.items():
        event[field] = build_field(values, variant)
    for field, other in refs:
        val = event.get(other)
        if val is None or val is ABSENT:
            val = "same-value"
            event[other] = val
        event[field] = val
    for field, value in avoid:
        cur = event.get(field)
        if cur is None:
            event[field] = "sigma-forge-test"
            if matches(value, event[field]):
                event[field] = "zz-other"
        elif cur is not ABSENT and matches(value, cur):
            raise Unsupported(f"filter on {field} hides the generated value")
    if keywords:
        event["Message"] = " ".join(keywords)
    return {k: v for k, v in event.items() if v is not ABSENT}


def _logsource(rule) -> Dict[str, str]:
    ls = rule.logsource
    return {k: v for k, v in (("product", ls.product), ("category", ls.category), ("service", ls.service)) if v}


def _stamp(seconds: float) -> str:
    return (BASE_TIME + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def generate(rule_inputs) -> Dict[str, Any]:
    parsed = parse_inputs(list(rule_inputs))
    by_name: Dict[str, Any] = {}
    rows = []
    events: List[Dict[str, Any]] = []
    clock = [0.0]

    def add(ev: Dict[str, Any], key: str, title: str) -> None:
        ev = dict(ev)
        ev.setdefault("timestamp", _stamp(clock[0]))
        clock[0] += 61
        ev["_generated_for"] = title
        events.append(ev)

    for p in parsed:
        if p.rule is not None:
            by_name[p.rule.name or ""] = p
    for p in parsed:
        row = {"key": p.key, "file": p.file, "title": "", "events": 0, "status": "ok", "message": ""}
        if p.error:
            row.update(status="error", message=p.error, title=p.file)
            rows.append(row)
            continue
        if p.rule is not None:
            row["title"] = p.rule.title
            try:
                ev = event_for_rule(p.rule)
                ev["logsource"] = _logsource(p.rule)
                add(ev, p.key, p.rule.title)
                row["events"] = 1
            except Unsupported as exc:
                row.update(status="skipped", message=f"Could not build an event: {exc}")
            rows.append(row)
            continue
        corr = p.correlation
        row["title"] = corr.title
        try:
            n = _generate_correlation(corr, add, clock)
            row["events"] = n
        except Unsupported as exc:
            row.update(status="skipped", message=f"Could not build events: {exc}")
        rows.append(row)
    return {"events": events, "rules": rows}


def _generate_correlation(corr, add, clock) -> int:
    kind = (corr.type.name if hasattr(corr.type, "name") else str(corr.type)).lower()
    refs = [r.rule for r in corr.rules if getattr(r, "rule", None) is not None]
    if not refs:
        raise Unsupported("referenced rules not found")
    base_events = []
    for ref in refs:
        if ref.__class__.__name__ != "SigmaRule":
            raise Unsupported("nested correlations")
        ev = event_for_rule(ref)
        ev["logsource"] = _logsource(ref)
        base_events.append(ev)
    group = list(corr.group_by or [])
    span = corr.timespan.seconds
    cond = corr.condition
    op = cond.op.name.lower() if cond is not None else "gte"
    count = int(cond.count) if cond is not None and cond.count is not None else 1
    if op == "gt":
        count += 1
    if op in ("lt", "lte"):
        count = 1
    count = max(1, min(count, 200))
    start = clock[0] + 3600
    step = min(1.0, span / (count + 2))
    made = 0
    if kind in ("event_count", "value_count"):
        field = cond.fieldref if cond is not None else None
        for i in range(count):
            ev = dict(base_events[i % len(base_events)])
            for g in group:
                ev[g] = ev.get(g) if ev.get(g) not in (None, "sigma-forge-test") else "sf-group-1"
            if kind == "value_count" and field:
                ev[field] = f"value-{i + 1}"
            ev["timestamp"] = _stamp(start + i * step)
            add(ev, "", corr.title)
            made += 1
    else:
        for i, ev in enumerate(base_events):
            ev = dict(ev)
            for g in group:
                ev[g] = "sf-group-1"
            ev["timestamp"] = _stamp(start + i * step)
            add(ev, "", corr.title)
            made += 1
    clock[0] = start + span + 120
    return made


def to_jsonl(events: List[Dict[str, Any]]) -> str:
    return "\n".join(json.dumps(e, default=str) for e in events) + "\n"
