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

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
MAX_EVENTS = 50000
QUERY_TIMEOUT = 120


class HuntError(ValueError):
    pass


def is_windows() -> bool:
    return platform.system() == "Windows"


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


def status() -> Dict[str, Any]:
    win = is_windows()
    channels = []
    if win:
        for ch in CHANNELS:
            channels.append({**ch, **_channel_info(ch["id"])})
    return {
        "platform": platform.system() or "Unknown",
        "host": platform.node(),
        "windows": win,
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


def collect(channels: List[str], hours: float, max_events: int) -> Tuple[List[Tuple[str, bytes]], List[Dict[str, Any]]]:
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
