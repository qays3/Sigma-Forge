import json
import os
import platform
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CHANNELS = [
    {"id": "Microsoft-Windows-Sysmon/Operational", "name": "Sysmon", "note": "Process, network, file, registry and DNS events"},
    {"id": "Security", "name": "Security", "note": "Logons, process creation (4688), account changes. Needs admin"},
    {"id": "System", "name": "System", "note": "Services, drivers, shutdowns"},
    {"id": "Application", "name": "Application", "note": "App crashes and app events"},
    {"id": "Microsoft-Windows-PowerShell/Operational", "name": "PowerShell", "note": "Script block (4104) and module (4103) logs"},
    {"id": "Windows PowerShell", "name": "Windows PowerShell", "note": "Classic engine start and provider events"},
    {"id": "Microsoft-Windows-Windows Defender/Operational", "name": "Defender", "note": "Detections and setting changes"},
    {"id": "Microsoft-Windows-TaskScheduler/Operational", "name": "Task Scheduler", "note": "Scheduled task changes"},
    {"id": "Microsoft-Windows-WMI-Activity/Operational", "name": "WMI activity", "note": "WMI queries and consumers"},
    {"id": "Microsoft-Windows-Bits-Client/Operational", "name": "BITS", "note": "Background transfer jobs"},
    {"id": "Microsoft-Windows-DNS-Client/Operational", "name": "DNS client", "note": "Name lookups when enabled"},
    {"id": "Microsoft-Windows-CodeIntegrity/Operational", "name": "Code Integrity", "note": "Blocked or unsigned code"},
    {"id": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "name": "Firewall", "note": "Firewall rule changes"},
    {"id": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "name": "RDP sessions", "note": "Remote desktop logons"},
]

LINUX_CHANNELS = [
    {"id": "journal", "name": "systemd journal", "note": "Services, logins, sudo, cron and kernel messages"},
    {"id": "auditd", "name": "auditd", "note": "Process runs (EXECVE), file and user changes. Needs root"},
    {"id": "authlog", "name": "auth log", "note": "SSH, sudo and login lines from /var/log/auth.log or /var/log/secure"},
]

MAC_CHANNELS = [
    {"id": "unified", "name": "Unified log", "note": "Process, security and system messages from log show"},
]

AUTH_FILES = ["/var/log/auth.log", "/var/log/secure"]
AUDIT_FILE = "/var/log/audit/audit.log"
TAIL_BYTES = 48 * 1024 * 1024

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
MAX_EVENTS = 50000
QUERY_TIMEOUT = 120


class HuntError(ValueError):
    pass


def is_windows() -> bool:
    return platform.system() == "Windows"


def os_kind() -> str:
    name = platform.system()
    return {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(name, "other")


def channel_list() -> List[Dict[str, str]]:
    return {"windows": CHANNELS, "linux": LINUX_CHANNELS, "macos": MAC_CHANNELS}.get(os_kind(), [])


def is_admin() -> bool:
    if not is_windows():
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(args: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=flags)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def _channel_info(channel: str) -> Dict[str, Any]:
    try:
        code, out, err = _run(["wevtutil", "gli", channel], 10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"exists": False, "records": 0, "error": str(exc)}
    if code != 0:
        msg = (err or out).strip()
        denied = "denied" in msg.lower()
        return {"exists": denied, "records": 0, "error": "Access denied. Run Sigma Forge as admin." if denied else "Not found on this machine"}
    records = 0
    for line in out.splitlines():
        if line.strip().lower().startswith("numberoflogrecords"):
            try:
                records = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
    return {"exists": True, "records": records, "error": ""}


def suggested_paths() -> List[str]:
    home = Path.home()
    candidates = [home / "Downloads", home / "Desktop", home / "Documents"]
    if is_windows():
        env = os.environ
        candidates += [
            Path(env.get("TEMP", "")) if env.get("TEMP") else None,
            Path(env.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" if env.get("APPDATA") else None,
            Path(env.get("PUBLIC", "C:\\Users\\Public")),
            Path(env.get("PROGRAMDATA", "C:\\ProgramData")),
        ]
    else:
        candidates += [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")]
    out = []
    for c in candidates:
        if c and c.is_dir() and str(c) not in out:
            out.append(str(c))
    return out


def _unix_info(channel: str) -> Dict[str, Any]:
    import shutil

    if channel == "journal":
        ok = shutil.which("journalctl") is not None
        return {"exists": ok, "records": 0, "error": "" if ok else "journalctl not found"}
    if channel == "auditd":
        if not os.path.exists(AUDIT_FILE):
            return {"exists": False, "records": 0, "error": "auditd log not found"}
        if not os.access(AUDIT_FILE, os.R_OK):
            return {"exists": True, "records": 0, "error": "Access denied. Run Sigma Forge as root."}
        return {"exists": True, "records": 0, "error": ""}
    if channel == "authlog":
        for f in AUTH_FILES:
            if os.path.exists(f):
                ok = os.access(f, os.R_OK)
                return {"exists": True, "records": 0, "error": "" if ok else "Access denied. Run Sigma Forge as root."}
        return {"exists": False, "records": 0, "error": "No auth log file found"}
    if channel == "unified":
        ok = shutil.which("log") is not None
        return {"exists": ok, "records": 0, "error": "" if ok else "The log command was not found"}
    return {"exists": False, "records": 0, "error": "Unknown log"}


def status() -> Dict[str, Any]:
    win = is_windows()
    kind = os_kind()
    channels = []
    if win:
        for ch in CHANNELS:
            channels.append({**ch, **_channel_info(ch["id"])})
    elif kind in ("linux", "macos"):
        for ch in channel_list():
            channels.append({**ch, **_unix_info(ch["id"])})
    return {
        "platform": platform.system() or "Unknown",
        "host": platform.node(),
        "windows": win,
        "os": kind,
        "live": kind in ("windows", "linux", "macos"),
        "admin": is_admin(),
        "channels": channels,
        "paths": suggested_paths(),
    }


def parse_events_xml(text: str, channel_hint: str = "") -> List[Dict[str, Any]]:
    body = text.strip()
    if not body:
        return []
    if not body.startswith("<Events"):
        body = "<Events>" + body + "</Events>"
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise HuntError(f"Could not read events from {channel_hint or 'the log'}: {exc}")
    out = []
    for ev in root.iter(NS + "Event"):
        flat: Dict[str, Any] = {}
        system = ev.find(NS + "System")
        if system is not None:
            for child in system:
                tag = child.tag.replace(NS, "")
                if tag == "Provider":
                    if child.get("Name"):
                        flat["Provider_Name"] = child.get("Name")
                elif tag == "TimeCreated":
                    if child.get("SystemTime"):
                        flat["timestamp"] = child.get("SystemTime")
                elif tag == "Execution":
                    if child.get("ProcessID"):
                        flat["ExecutionProcessID"] = child.get("ProcessID")
                elif tag == "Security":
                    if child.get("UserID"):
                        flat["SecurityUserID"] = child.get("UserID")
                elif child.text and child.text.strip():
                    flat[tag] = child.text.strip()
        for section in ("EventData", "UserData"):
            node = ev.find(NS + section)
            if node is None:
                continue
            datas = list(node.iter(NS + "Data"))
            if datas:
                unnamed = []
                for d in datas:
                    name = d.get("Name")
                    value = (d.text or "").strip()
                    if name:
                        flat[name] = value
                    elif value:
                        unnamed.append(value)
                if unnamed:
                    flat.setdefault("Data", " ".join(unnamed))
            else:
                for child in node.iter():
                    if child is node or len(child):
                        continue
                    if child.text and child.text.strip():
                        flat.setdefault(child.tag.split("}")[-1], child.text.strip())
        if "EventID" in flat:
            try:
                flat["EventID"] = int(flat["EventID"])
            except ValueError:
                pass
        if channel_hint and "Channel" not in flat:
            flat["Channel"] = channel_hint
        out.append(flat)
    return out


def read_channel(channel: str, hours: float, limit: int) -> List[Dict[str, Any]]:
    if not is_windows():
        raise HuntError("Live scan needs Sigma Forge running on Windows. Upload .evtx files instead.")
    ms = int(max(hours, 0.05) * 3600 * 1000)
    query = f"*[System[TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    args = ["wevtutil", "qe", channel, f"/q:{query}", "/f:xml", f"/c:{int(limit)}", "/rd:true", "/e:Events"]
    try:
        code, out, err = _run(args, QUERY_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise HuntError(f"{channel}: reading took too long. Pick fewer hours.")
    except OSError as exc:
        raise HuntError(f"{channel}: {exc}")
    if code != 0:
        msg = (err or out).strip()
        if "denied" in msg.lower():
            raise HuntError(f"{channel}: access denied. Run Sigma Forge as admin to read this log.")
        raise HuntError(f"{channel}: {msg or 'could not read this log'}")
    return parse_events_xml(out, channel)


def _iso(seconds: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _tail_lines(path: str, limit: int) -> List[str]:
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - TAIL_BYTES))
        data = fh.read().decode("utf-8", "replace")
    lines = data.splitlines()
    if size > TAIL_BYTES and lines:
        lines = lines[1:]
    return lines[-limit:]


JOURNAL_SERVICE = {"sshd": "sshd", "sudo": "sudo", "su": "auth", "login": "auth", "systemd-logind": "auth", "cron": "cron", "crond": "cron", "CRON": "cron", "vsftpd": "vsftpd"}


def read_journal(hours: float, limit: int) -> List[Dict[str, Any]]:
    minutes = max(1, int(hours * 60))
    code, out, err = _run(["journalctl", f"--since=-{minutes}min", "-o", "json", "--no-pager", "-r", "-n", str(int(limit))], QUERY_TIMEOUT)
    if code != 0 and not out:
        raise HuntError(f"journal: {(err or 'could not read the journal').strip()}")
    events = []
    for line in out.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        ident = str(rec.get("SYSLOG_IDENTIFIER") or rec.get("_COMM") or "")
        msg = rec.get("MESSAGE")
        if isinstance(msg, list):
            msg = bytes(x for x in msg if isinstance(x, int)).decode("utf-8", "replace")
        ev = {
            "Message": msg or "",
            "SyslogIdentifier": ident,
            "Image": rec.get("_EXE", ""),
            "CommandLine": rec.get("_CMDLINE", ""),
            "ProcessId": rec.get("_PID", ""),
            "User": rec.get("_UID", ""),
            "Computer": rec.get("_HOSTNAME", ""),
            "Unit": rec.get("_SYSTEMD_UNIT", ""),
            "logsource": {"product": "linux", "service": JOURNAL_SERVICE.get(ident, "syslog")},
        }
        ts = rec.get("__REALTIME_TIMESTAMP")
        if ts and str(ts).isdigit():
            ev["timestamp"] = _iso(int(ts) / 1_000_000)
        events.append({k: v for k, v in ev.items() if v not in ("", None)})
    return events


AUDIT_RE = None


def parse_audit_line(line: str) -> Optional[Dict[str, Any]]:
    import re
    import shlex

    global AUDIT_RE
    if AUDIT_RE is None:
        AUDIT_RE = re.compile(r"msg=audit\((\d+)(?:\.(\d+))?:(\d+)\)")
    m = AUDIT_RE.search(line)
    if not m:
        return None
    ev: Dict[str, Any] = {"timestamp": _iso(int(m.group(1)) + int((m.group(2) or "0").ljust(3, "0")[:3]) / 1000), "audit_id": m.group(3)}
    body = line.replace(m.group(0), " ")
    try:
        parts = shlex.split(body, posix=True)
    except ValueError:
        parts = body.split()
    for part in parts:
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip().strip("'")
        if key and key not in ev:
            ev[key] = value
    ev["logsource"] = {"product": "linux", "service": "auditd"}
    return ev


def _merge_execve(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for ev in events:
        if ev.get("type") == "EXECVE":
            args = [ev[f"a{i}"] for i in range(int(ev.get("argc", "0") or 0)) if f"a{i}" in ev]
            fixed = []
            for a in args:
                if len(a) % 2 == 0 and a and all(c in "0123456789ABCDEFabcdef" for c in a):
                    try:
                        a = bytes.fromhex(a).decode("utf-8", "replace").replace("\x00", " ")
                    except ValueError:
                        pass
                fixed.append(a)
            ev["CommandLine"] = " ".join(fixed)
    return events


def read_auditd(hours: float, limit: int) -> List[Dict[str, Any]]:
    import time as _t

    if not os.path.exists(AUDIT_FILE):
        raise HuntError("auditd: no log file. Install and start auditd first.")
    if not os.access(AUDIT_FILE, os.R_OK):
        raise HuntError("auditd: access denied. Run Sigma Forge as root.")
    cutoff = _t.time() - hours * 3600
    out = []
    for line in _tail_lines(AUDIT_FILE, limit * 4):
        ev = parse_audit_line(line)
        if not ev:
            continue
        out.append(ev)
    from datetime import datetime

    keep = []
    for ev in out:
        try:
            ts = datetime.strptime(ev["timestamp"][:19], "%Y-%m-%dT%H:%M:%S").timestamp()
        except ValueError:
            ts = cutoff
        if ts >= cutoff - 3 * 3600:
            keep.append(ev)
    return _merge_execve(keep[-limit:])


def read_authlog(hours: float, limit: int) -> List[Dict[str, Any]]:
    path = next((f for f in AUTH_FILES if os.path.exists(f)), None)
    if not path:
        raise HuntError("auth log: no file found")
    if not os.access(path, os.R_OK):
        raise HuntError("auth log: access denied. Run Sigma Forge as root.")
    events = []
    for line in _tail_lines(path, limit):
        ident = ""
        head = line.split(":", 3)
        if len(head) >= 3:
            prog = head[2].split()[-1] if head[2].split() else ""
            ident = prog.split("[")[0]
        events.append({"Message": line, "SyslogIdentifier": ident, "logsource": {"product": "linux", "service": "auth"}})
    return events


def read_unified(hours: float, limit: int) -> List[Dict[str, Any]]:
    minutes = max(1, int(hours * 60))
    code, out, err = _run(["log", "show", "--last", f"{minutes}m", "--style", "ndjson", "--info"], QUERY_TIMEOUT)
    if code != 0 and not out:
        raise HuntError(f"unified log: {(err or 'could not read the log').strip()}")
    events = []
    for line in out.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict) or "eventMessage" not in rec:
            continue
        events.append({
            "Message": rec.get("eventMessage", ""),
            "Image": rec.get("processImagePath", ""),
            "ProcessId": rec.get("processID", ""),
            "Subsystem": rec.get("subsystem", ""),
            "Category": rec.get("category", ""),
            "User": rec.get("userID", ""),
            "timestamp": rec.get("timestamp", ""),
            "logsource": {"product": "macos"},
        })
        if len(events) >= limit:
            break
    return events


UNIX_READERS = {"journal": read_journal, "auditd": read_auditd, "authlog": read_authlog, "unified": read_unified}


def collect(channels: List[str], hours: float, max_events: int) -> Tuple[List[Tuple[str, bytes]], List[Dict[str, Any]]]:
    if not is_windows():
        return collect_unix(channels, hours, max_events)
    allowed = {c["id"] for c in CHANNELS}
    limit = max(100, min(int(max_events), MAX_EVENTS))
    per = max(100, limit // max(len(channels), 1))
    blobs: List[Tuple[str, bytes]] = []
    stats: List[Dict[str, Any]] = []
    for ch in channels:
        if ch not in allowed:
            stats.append({"channel": ch, "events": 0, "error": "Unknown log channel", "seconds": 0})
            continue
        started = time.monotonic()
        try:
            events = read_channel(ch, hours, per)
            err = ""
        except HuntError as exc:
            events, err = [], str(exc)
        stats.append({"channel": ch, "events": len(events), "error": err, "seconds": round(time.monotonic() - started, 2)})
        if events:
            data = "\n".join(json.dumps(e, ensure_ascii=False) for e in events).encode("utf-8")
            blobs.append((f"live:{ch}", data))
    return blobs, stats


def walk_files(paths: List[str], recursive: bool, max_files: int, max_size: int, extensions: Optional[List[str]] = None):
    exts = {e.lower() if e.startswith(".") else "." + e.lower() for e in (extensions or []) if e}
    seen = 0
    skipped = {"too_big": 0, "no_access": 0, "filtered": 0}
    for raw in paths:
        p = Path(os.path.expandvars(os.path.expanduser(raw.strip().strip('"'))))
        if p.is_file():
            items = [p]
        elif p.is_dir():
            items = p.rglob("*") if recursive else p.glob("*")
        else:
            yield ("missing", str(p), 0)
            continue
        try:
            for f in items:
                try:
                    if f.is_symlink() or not f.is_file():
                        continue
                    if exts and f.suffix.lower() not in exts:
                        skipped["filtered"] += 1
                        continue
                    size = f.stat().st_size
                except OSError:
                    skipped["no_access"] += 1
                    continue
                if size > max_size:
                    skipped["too_big"] += 1
                    continue
                seen += 1
                if seen > max_files:
                    yield ("limit", str(f), 0)
                    yield ("skipped", json.dumps(skipped), 0)
                    return
                yield ("file", str(f), size)
        except OSError:
            skipped["no_access"] += 1
    yield ("skipped", json.dumps(skipped), 0)


def collect_unix(channels: List[str], hours: float, max_events: int) -> Tuple[List[Tuple[str, bytes]], List[Dict[str, Any]]]:
    allowed = {c["id"] for c in channel_list()}
    limit = max(100, min(int(max_events), MAX_EVENTS))
    per = max(100, limit // max(len(channels), 1))
    blobs: List[Tuple[str, bytes]] = []
    stats: List[Dict[str, Any]] = []
    for ch in channels:
        started = time.monotonic()
        if ch not in allowed:
            stats.append({"channel": ch, "events": 0, "error": "Not available on this system", "seconds": 0})
            continue
        try:
            events = UNIX_READERS[ch](hours, per)
            err = ""
        except (HuntError, OSError, subprocess.TimeoutExpired) as exc:
            events, err = [], str(exc)
        stats.append({"channel": ch, "events": len(events), "error": err, "seconds": round(time.monotonic() - started, 2)})
        if events:
            blobs.append((f"live:{ch}", "\n".join(json.dumps(e, ensure_ascii=False, default=str) for e in events).encode("utf-8")))
    return blobs, stats


def list_processes() -> List[Dict[str, Any]]:
    out = []
    try:
        import psutil

        for p in psutil.process_iter(["pid", "name", "exe", "username"]):
            info = p.info
            out.append({"pid": info["pid"], "name": info.get("name") or "", "exe": info.get("exe") or "", "user": info.get("username") or ""})
        return out
    except ImportError:
        pass
    if is_windows():
        code, text, _ = _run(["tasklist", "/fo", "csv", "/nh"], 20)
        import csv
        import io

        for row in csv.reader(io.StringIO(text)):
            if len(row) >= 2 and row[1].isdigit():
                out.append({"pid": int(row[1]), "name": row[0], "exe": "", "user": ""})
        return out
    proc = Path("/proc")
    if proc.is_dir():
        for d in proc.iterdir():
            if d.name.isdigit():
                try:
                    name = (d / "comm").read_text().strip()
                except OSError:
                    continue
                try:
                    exe = os.readlink(d / "exe")
                except OSError:
                    exe = ""
                out.append({"pid": int(d.name), "name": name, "exe": exe, "user": ""})
    return out
