import re
from typing import Dict, List

SLOW_REGEX = re.compile(r"(\bmatches regex\b|\bregex\b|=~\s*/|\brex\b|\bREGEXP\b|\bRLIKE\b|\bmatch\(|\bregex\(|/[^/\s]{3,}/[a-z]*\s*$)", re.I)
LEAD_WILD = re.compile(r"""(?:=|:|\bLIKE\b|\bIN\b\s*\(|,)\s*["']?(?:\*|%)[^*%\s"',)]""", re.I)
TERMS = re.compile(r"\bOR\b|\bor\b|,")


def check(target: str, language: str, query: str) -> List[Dict[str, str]]:
    q = query or ""
    out: List[Dict[str, str]] = []
    if not q.strip():
        return out
    lang = (language or "").lower()
    if lang in ("xml", "json", "python", "yaml"):
        return out
    lead = LEAD_WILD.findall(q)
    if lead and lang not in ("kql",):
        out.append({"level": "warn" if len(lead) > 4 else "info", "text": f"{len(lead)} value{'s' if len(lead) > 1 else ''} start with a wildcard. The index cannot help with those, so every event in range is read."})
    if SLOW_REGEX.search(q):
        out.append({"level": "warn", "text": "Uses a regular expression. Regex runs on every event and is slow on big data."})
    terms = len(TERMS.findall(q))
    if terms > 60:
        out.append({"level": "warn", "text": f"About {terms} OR terms. Long lists are slow; a lookup table or watchlist is faster."})
    elif terms > 25:
        out.append({"level": "info", "text": f"About {terms} OR terms. Fine for scheduled rules, slow for wide time ranges."})
    if lang in ("spl",) and not re.search(r"\bindex\s*=", q) and "tstats" not in q and not q.lstrip().lower().startswith("from"):
        out.append({"level": "info", "text": "No index= in the query, so Splunk searches every default index. Add your index to make it faster."})
    if lang == "kql":
        if re.search(r"\bcontains\b", q) and not re.search(r"\bhas\b", q):
            out.append({"level": "info", "text": "Uses contains. In KQL has is much faster when you match whole words."})
        if not re.search(r"TimeGenerated|Timestamp|ago\(", q):
            out.append({"level": "info", "text": "No time filter. Add a TimeGenerated or Timestamp filter when you run it by hand."})
    if lang in ("lucene",) and re.search(r"\*[^\s\"]*\*", q):
        out.append({"level": "info", "text": "Uses *value* searches. On keyword fields these are slow; a wildcard field type helps."})
    if lang in ("esql", "sql") and re.search(r"\bfrom\s+\*", q, re.I):
        out.append({"level": "info", "text": "Reads from every index (from *). Point it at your log index."})
    if len(q) > 6000:
        out.append({"level": "warn", "text": f"The query is {len(q)} characters. Some platforms limit query length."})
    return out


def score(items: List[Dict[str, str]]) -> str:
    if any(i["level"] == "warn" for i in items):
        return "slow"
    if items:
        return "ok"
    return "fast"
