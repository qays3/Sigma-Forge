import json
import os
import re
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.config import MAX_LOG_BYTES, MAX_LOG_EVENTS, LOG_QUERY_SECONDS
from app.core.converter import convert
from app.core.parsing import parse_inputs


class LogInputError(ValueError):
    pass


SYSMON_CATEGORIES = {
    1: ["process_creation"],
    2: ["file_change"],
    3: ["network_connection"],
    4: ["sysmon_status"],
    5: ["process_termination"],
    6: ["driver_load"],
    7: ["image_load"],
    8: ["create_remote_thread"],
    9: ["raw_access_thread"],
    10: ["process_access"],
    11: ["file_event"],
    12: ["registry_event", "registry_add", "registry_delete"],
    13: ["registry_event", "registry_set"],
    14: ["registry_event", "registry_rename"],
    15: ["create_stream_hash"],
    16: ["sysmon_status"],
    17: ["pipe_created"],
    18: ["pipe_created"],
    19: ["wmi_event"],
    20: ["wmi_event"],
    21: ["wmi_event"],
    22: ["dns_query"],
    23: ["file_delete"],
    24: ["clipboard_capture"],
    25: ["process_tampering"],
    26: ["file_delete", "file_delete_detected"],
    27: ["file_block_executable"],
    28: ["file_block_shredding"],
    29: ["file_executable_detected"],
    255: ["sysmon_error"],
}

CHANNEL_SERVICES = {
    "security": "security",
    "system": "system",
    "application": "application",
    "microsoft-windows-powershell/operational": "powershell",
    "windows powershell": "powershell-classic",
    "microsoft-windows-windows defender/operational": "windefend",
    "microsoft-windows-wmi-activity/operational": "wmi",
    "microsoft-windows-taskscheduler/operational": "taskscheduler",
    "microsoft-windows-bits-client/operational": "bits-client",
    "microsoft-windows-dns-client/operational": "dns-client",
    "microsoft-windows-codeintegrity/operational": "codeintegrity-operational",
    "microsoft-windows-windows firewall with advanced security/firewall": "firewall-as",
    "microsoft-windows-sysmon/operational": "sysmon",
    "microsoft-windows-ntlm/operational": "ntlm",
    "microsoft-windows-applocker/exe and dll": "applocker",
    "microsoft-windows-terminalservices-localsessionmanager/operational": "terminalservices-localsessionmanager",
}

POWERSHELL_CATEGORIES = {4103: ["ps_module"], 4104: ["ps_script"]}
CLASSIC_CATEGORIES = {400: ["ps_classic_start"], 600: ["ps_classic_provider_start"], 800: ["ps_classic_script"]}
SECURITY_CATEGORIES = {4688: ["process_creation"]}

ALIASES = {
    "providername": "Provider_Name",
    "provider_name": "Provider_Name",
    "eventid": "EventID",
    "eventrecordid": "EventRecordID",
    "@timestamp": "timestamp",
    "systemtime": "timestamp",
    "timecreated": "timestamp",
    "utctime": "UtcTime",
}

TIME_KEYS = ("timestamp", "@timestamp", "systemtime", "timecreated", "eventtime", "time", "utctime", "date")

SKIP_KEYS = {"#attributes", "xmlns"}

WINDOWS_ROOTS = {"System", "EventData", "UserData", "Event", "win", "RenderingInfo"}


def _scalar(value: Any) -> Any:
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def _flatten(obj: Any, path: Tuple[str, ...], out: Dict[str, Any]) -> None:
    if isinstance(obj, dict):
        text = obj.get("#text")
        attrs = obj.get("#attributes")
        if isinstance(attrs, dict) and path and path[-1] == "Data" and "Name" in attrs:
            _put(out, str(attrs["Name"]), _scalar(text), path + (str(attrs["Name"]),))
            return
        if isinstance(attrs, dict):
            for key, value in attrs.items():
                if key == "xmlns":
                    continue
                name = f"{path[-1]}_{key}" if path else key
                if path and path[-1] == "TimeCreated" and key == "SystemTime":
                    name = "timestamp"
                if path and path[-1] == "Provider":
                    name = f"Provider_{key}"
                _put(out, name, _scalar(value), path + (key,))
        if text is not None and path:
            _put(out, path[-1], _scalar(text), path)
        for key, value in obj.items():
            if key in SKIP_KEYS or key == "#text":
                continue
            _flatten(value, path + (str(key),), out)
        return
    if isinstance(obj, list):
        if path and all(not isinstance(v, (dict, list)) for v in obj):
            _put(out, path[-1], " ".join(str(_scalar(v)) for v in obj if v is not None), path)
            return
        for value in obj:
            _flatten(value, path, out)
        return
    if path:
        _put(out, path[-1], _scalar(obj), path)


def _put(out: Dict[str, Any], key: str, value: Any, path: Tuple[str, ...]) -> None:
    if value is None or key == "":
        return
    name = ALIASES.get(key.lower(), key)
    lowered = name.lower()
    if lowered not in out:
        out[lowered] = (name, value)
    if len(path) > 1 and path[0] not in WINDOWS_ROOTS:
        dotted = ".".join(p for p in path if not p.startswith("#"))
        dl = dotted.lower()
        if dl != lowered and dl not in out:
            out[dl] = (dotted, value)


def _strip_wrapper(obj: Any) -> Any:
    if isinstance(obj, dict):
        if isinstance(obj.get("event"), dict) and ("expect" in obj or "name" in obj) and len(obj) <= 4:
            return obj["event"]
        if isinstance(obj.get("_source"), dict):
            return obj["_source"]
        if set(obj.keys()) <= {"Event"} and isinstance(obj.get("Event"), dict):
            return obj["Event"]
    return obj


def _timestamp(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        seconds = value / 1000.0 if value > 1e11 else float(value)
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    match = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?", text)
    if not match:
        return None
    frac = (match.group(3) or ".000")[1:4].ljust(3, "0")
    return f"{match.group(1)} {match.group(2)}.{frac}"


def _number(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _logsource(flat: Dict[str, Tuple[str, Any]], declared: Any) -> Tuple[str, str, str]:
    if isinstance(declared, dict):
        return (
            str(declared.get("product") or "").lower(),
            str(declared.get("service") or "").lower(),
            ",".join(declared.get("category") if isinstance(declared.get("category"), list) else [str(declared.get("category") or "")]).lower(),
        )
    channel = str((flat.get("channel") or ("", ""))[1]).lower()
    event_id = _number((flat.get("eventid") or ("", None))[1])
    if not channel:
        return "", "", ""
    service = CHANNEL_SERVICES.get(channel, "")
    categories: List[str] = []
    if channel == "microsoft-windows-sysmon/operational" and event_id is not None:
        categories = SYSMON_CATEGORIES.get(event_id, [])
    elif channel == "microsoft-windows-powershell/operational" and event_id is not None:
        categories = POWERSHELL_CATEGORIES.get(event_id, [])
    elif channel == "windows powershell" and event_id is not None:
        categories = CLASSIC_CATEGORIES.get(event_id, [])
    elif channel == "security" and event_id is not None:
        categories = SECURITY_CATEGORIES.get(event_id, [])
    return "windows", service, ",".join(categories)


def _records_from_json_text(text: str) -> Iterable[Any]:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped[0] in "[{":
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = None
        if data is not None:
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                for key in ("events", "records", "logs", "Records"):
                    if isinstance(data.get(key), list):
                        return data[key]
                hits = data.get("hits")
                if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
                    return hits["hits"]
                return [data]
    out = []
    for number, line in enumerate(stripped.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise LogInputError(f"Line {number} is not valid JSON: {exc.msg}")
    return out


def _records_from_evtx(data: bytes) -> Iterable[Any]:
    try:
        from evtx import PyEvtxParser
    except ImportError:
        raise LogInputError("EVTX support needs the evtx package. Run setup again to install it.")
    handle, path = tempfile.mkstemp(suffix=".evtx")
    try:
        with os.fdopen(handle, "wb") as fh:
            fh.write(data)
        parser = PyEvtxParser(path)
        out = []
        for record in parser.records_json():
            try:
                out.append(json.loads(record["data"]))
            except (KeyError, json.JSONDecodeError):
                continue
        return out
    except LogInputError:
        raise
    except Exception as exc:
        raise LogInputError(f"Could not read EVTX file: {exc}")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def load_events(files: List[Tuple[str, bytes]]) -> List[Dict[str, Any]]:
    total = sum(len(data) for _, data in files)
    if total > MAX_LOG_BYTES:
        raise LogInputError(f"Log files are {total // 1048576} MB. The limit is {MAX_LOG_BYTES // 1048576} MB.")
    events: List[Dict[str, Any]] = []
    for name, data in files:
        is_evtx = name.lower().endswith(".evtx") or data[:8] == b"ElfFile\x00"
        if is_evtx:
            records = _records_from_evtx(data)
        else:
            try:
                text = data.decode("utf-8-sig")
            except UnicodeDecodeError:
                raise LogInputError(f"{name} is not UTF-8 text, JSON or EVTX")
            try:
                records = _records_from_json_text(text)
            except LogInputError as exc:
                raise LogInputError(f"{name}: {exc}")
        for record in records:
            record = _strip_wrapper(record)
            if not isinstance(record, dict):
                continue
            events.append({"source": name, "raw": record})
            if len(events) > MAX_LOG_EVENTS:
                raise LogInputError(f"More than {MAX_LOG_EVENTS} events. Split the logs into smaller sets.")
    if not events:
        raise LogInputError("No events found in the uploaded files")
    return events


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


@lru_cache(maxsize=512)
def _compile(pattern: str):
    return re.compile(pattern)


def _regexp(pattern, value):
    if value is None or pattern is None:
        return 0
    try:
        return 1 if _compile(str(pattern)).search(str(value)) else 0
    except re.error:
        return 0


RESERVED = {"message", "_idx", "_source", "_product", "_service", "_category", "rowid", "timestamp"}


class LogDatabase:
    def __init__(self, events: List[Dict[str, Any]]):
        self.conn = sqlite3.connect(":memory:")
        self.conn.create_function("REGEXP", 2, _regexp, deterministic=True)
        self.events = events
        self.stats: Dict[str, int] = {}
        rows = []
        counts: Dict[str, int] = {}
        names: Dict[str, str] = {}
        for idx, event in enumerate(events):
            raw = event["raw"]
            declared = raw.pop("logsource", None) if isinstance(raw.get("logsource"), dict) else None
            flat: Dict[str, Tuple[str, Any]] = {}
            _flatten(raw, (), flat)
            ts = None
            for key in TIME_KEYS:
                if key in flat:
                    ts = _timestamp(flat[key][1])
                    if ts:
                        break
            product, service, category = _logsource(flat, declared)
            event["logsource"] = {"product": product, "service": service, "category": category}
            label = ":".join(x for x in (product, service or category.split(",")[0]) if x) or "unknown"
            self.stats[label] = self.stats.get(label, 0) + 1
            values = {}
            for lowered, (name, value) in flat.items():
                if lowered in RESERVED:
                    continue
                if isinstance(value, (dict, list)):
                    continue
                names.setdefault(lowered, name)
                counts[lowered] = counts.get(lowered, 0) + 1
                values[lowered] = value
            rows.append((idx, event["source"], json.dumps(raw, ensure_ascii=False, default=str), product, service, category, ts, values))
        keep = sorted(counts, key=lambda k: -counts[k])[:1900]
        self.columns = {k: names[k] for k in keep}
        cols = ", ".join(f"{_quote(self.columns[k])} NUMERIC" for k in keep)
        self.conn.execute(
            "CREATE TABLE events (_idx INTEGER, _source TEXT, message TEXT, _product TEXT, _service TEXT, _category TEXT, timestamp TEXT"
            + (", " + cols if cols else "") + ")"
        )
        placeholders = ", ".join("?" for _ in range(7 + len(keep)))
        insert = f"INSERT INTO events VALUES ({placeholders})"
        self.conn.executemany(insert, ((r[0], r[1], r[2], r[3], r[4], r[5], r[6], *[_cell(r[7].get(k)) for k in keep]) for r in rows))
        self.known = {k.lower() for k in keep} | RESERVED
        self.conn.commit()

    def add_column(self, name: str) -> bool:
        if name.lower() in self.known or len(self.known) > 1990:
            return False
        self.conn.execute(f"ALTER TABLE events ADD COLUMN {_quote(name)} NUMERIC")
        self.known.add(name.lower())
        return True

    def run(self, query: str, where: str, deadline: float) -> List[sqlite3.Row]:
        self.conn.execute("DROP VIEW IF EXISTS temp.logs")
        self.conn.execute(f"CREATE TEMP VIEW logs AS SELECT rowid AS rowid, * FROM events WHERE {where}")
        self.conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 20000)
        try:
            cursor = self.conn.execute(query)
            names = [d[0] for d in cursor.description or []]
            return names, cursor.fetchall()
        finally:
            self.conn.set_progress_handler(None, 0)


def _cell(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (int, float, str)):
        return value
    return str(value)


def _ls_filter(rule, mode: str) -> Tuple[str, List[str]]:
    if mode == "off" or rule is None:
        return "1", []
    ls = rule.logsource
    conds = []
    shown = []
    for attr in ("product", "service", "category"):
        value = getattr(ls, attr, None)
        if not value:
            continue
        value = str(value).lower().replace("'", "''")
        shown.append(f"{attr}:{value}")
        if attr == "product":
            conds.append(f"_product = '{value}'")
        elif attr == "service":
            conds.append(f"_service = '{value}'" if mode == "strict" else f"(_service = '' OR _service = '{value}')")
        else:
            conds.append(f"(',' || _category || ',') LIKE '%,{value},%'")
    if not conds:
        return "1", shown
    joined = " AND ".join(conds)
    if mode == "auto":
        return f"(_product = '' OR ({joined}))", shown
    return joined, shown


MISSING_COLUMN = re.compile(r"no such column: (.+)$")


def _sample(event: Dict[str, Any]) -> Dict[str, Any]:
    return {"source": event["source"], "logsource": event["logsource"], "event": event["raw"]}


def run_test(rule_inputs, files: List[Tuple[str, bytes]], mode: str = "auto", max_samples: int = 5, options=None) -> Dict[str, Any]:
    if mode not in ("auto", "strict", "off"):
        mode = "auto"
    started = time.monotonic()
    events = load_events(files)
    db = LogDatabase(events)
    items = list(rule_inputs)
    from app.schemas import ConvertOptions

    converted = convert(items, "sqlite", "default", options or ConvertOptions())
    rules_by_key = {p.key: p for p in parse_inputs(items)}
    matched_events = set()
    results = []
    for row in converted["results"]:
        parsed = rules_by_key.get(row["key"])
        entry = {
            "key": row["key"],
            "file": row["file"],
            "kind": row["kind"],
            "title": row["title"],
            "level": row["level"],
            "hits": 0,
            "samples": [],
            "alerts": [],
            "query": row["queries"][0] if row["queries"] else "",
            "logsource": "",
            "status": "ok",
            "message": "",
            "warnings": row["warnings"],
        }
        if row["error"]:
            entry["status"] = "failed"
            entry["message"] = row["error"]
            results.append(entry)
            continue
        if not row["queries"]:
            entry["status"] = "skipped"
            entry["message"] = "Used only inside a correlation rule"
            results.append(entry)
            continue
        is_corr = row["kind"] == "correlation"
        where, shown = _ls_filter(None if is_corr else (parsed.rule if parsed else None), mode)
        entry["logsource"] = " ".join(shown)
        deadline = time.monotonic() + LOG_QUERY_SECONDS
        hit_rows: List[int] = []
        alerts = []
        try:
            for query in row["queries"]:
                for _ in range(40):
                    try:
                        names, fetched = db.run(query, where, deadline)
                        break
                    except sqlite3.OperationalError as exc:
                        miss = MISSING_COLUMN.search(str(exc))
                        if miss and db.add_column(miss.group(1).strip("`\"[]")):
                            continue
                        raise
                else:
                    raise sqlite3.OperationalError("Too many unknown fields")
                if is_corr:
                    for item in fetched:
                        alert = dict(zip(names, item))
                        alerts.append(alert)
                        try:
                            for eid in json.loads(alert.get("event_ids") or "[]"):
                                rid = str(eid).split(":")[-1]
                                if rid.isdigit():
                                    hit_rows.append(int(rid))
                        except (TypeError, ValueError):
                            pass
                else:
                    if "rowid" in names:
                        pos = names.index("rowid")
                    elif "_idx" in names:
                        pos = names.index("_idx")
                    else:
                        pos = None
                    for item in fetched:
                        if pos is not None and item[pos] is not None:
                            hit_rows.append(int(item[pos]))
        except sqlite3.OperationalError as exc:
            text = str(exc)
            entry["status"] = "error"
            entry["message"] = "The query took too long and was stopped" if "interrupted" in text else f"SQLite error: {text}"
            results.append(entry)
            continue
        idx_rows = []
        if hit_rows:
            placeholders = ",".join("?" for _ in set(hit_rows))
            idx_rows = [r[0] for r in db.conn.execute(f"SELECT _idx FROM events WHERE rowid IN ({placeholders}) ORDER BY rowid", list(set(hit_rows)))]
        entry["hits"] = len(alerts) if is_corr else len(idx_rows)
        entry["events"] = len(idx_rows)
        entry["alerts"] = [_alert(a) for a in alerts[:max_samples]]
        entry["samples"] = [_sample(events[i]) for i in idx_rows[:max_samples]]
        matched_events.update(idx_rows)
        results.append(entry)

    results.sort(key=lambda r: (0 if r["hits"] else 1, {"ok": 0, "skipped": 2}.get(r["status"], 1), r["title"].lower()))
    ok = [r for r in results if r["status"] == "ok"]
    return {
        "summary": {
            "events": len(events),
            "files": len(files),
            "rules": len(results),
            "tested": len(ok),
            "matched_rules": sum(1 for r in ok if r["hits"]),
            "silent_rules": sum(1 for r in ok if not r["hits"]),
            "matched_events": len(matched_events),
            "unmatched_events": len(events) - len(matched_events),
            "errors": sum(1 for r in results if r["status"] in ("failed", "error")),
            "seconds": round(time.monotonic() - started, 2),
        },
        "mode": mode,
        "logsources": [{"name": k, "events": v} for k, v in sorted(db.stats.items(), key=lambda x: -x[1])],
        "fields": len(db.columns),
        "results": results,
    }


def _alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for key in ("group_keys", "window_start", "window_end", "metric_name", "metric_value", "event_count"):
        value = alert.get(key)
        if key == "group_keys" and isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                pass
        if key in ("window_start", "window_end") and isinstance(value, (int, float)):
            value = datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        out[key] = value
    return out
