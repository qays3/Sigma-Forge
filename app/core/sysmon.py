import re
from typing import Any, Dict, List, Tuple
from xml.sax.saxutils import escape

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.types import SigmaString, SpecialChars

from app.core.parsing import parse_inputs

COMMON = ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User"]
TYPES = {
    "process_creation": ("ProcessCreate", 1, COMMON + ["FileVersion", "Description", "Product", "Company", "OriginalFileName", "CommandLine", "CurrentDirectory", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine", "ParentUser"]),
    "file_change": ("FileCreateTime", 2, COMMON + ["TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime"]),
    "network_connection": ("NetworkConnect", 3, COMMON + ["Protocol", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname", "SourcePort", "SourcePortName", "DestinationIsIpv6", "DestinationIp", "DestinationHostname", "DestinationPort", "DestinationPortName"]),
    "process_termination": ("ProcessTerminate", 5, COMMON),
    "driver_load": ("DriverLoad", 6, ["RuleName", "UtcTime", "ImageLoaded", "Hashes", "Signed", "Signature", "SignatureStatus"]),
    "image_load": ("ImageLoad", 7, COMMON + ["ImageLoaded", "FileVersion", "Description", "Product", "Company", "OriginalFileName", "Hashes", "Signed", "Signature", "SignatureStatus"]),
    "create_remote_thread": ("CreateRemoteThread", 8, ["RuleName", "UtcTime", "SourceProcessGuid", "SourceProcessId", "SourceImage", "TargetProcessGuid", "TargetProcessId", "TargetImage", "NewThreadId", "StartAddress", "StartModule", "StartFunction", "SourceUser", "TargetUser"]),
    "raw_access_thread": ("RawAccessRead", 9, COMMON + ["Device"]),
    "process_access": ("ProcessAccess", 10, ["RuleName", "UtcTime", "SourceProcessGUID", "SourceProcessId", "SourceThreadId", "SourceImage", "TargetProcessGUID", "TargetProcessId", "TargetImage", "GrantedAccess", "CallTrace", "SourceUser", "TargetUser"]),
    "file_event": ("FileCreate", 11, COMMON + ["TargetFilename", "CreationUtcTime"]),
    "registry_add": ("RegistryEvent", 12, ["RuleName", "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "Details", "NewName", "User"]),
    "registry_delete": ("RegistryEvent", 12, ["RuleName", "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "Details", "NewName", "User"]),
    "registry_set": ("RegistryEvent", 13, ["RuleName", "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "Details", "NewName", "User"]),
    "registry_rename": ("RegistryEvent", 14, ["RuleName", "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "Details", "NewName", "User"]),
    "registry_event": ("RegistryEvent", 12, ["RuleName", "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "Details", "NewName", "User"]),
    "create_stream_hash": ("FileCreateStreamHash", 15, COMMON + ["TargetFilename", "CreationUtcTime", "Hash", "Contents"]),
    "pipe_created": ("PipeEvent", 17, COMMON + ["EventType", "PipeName"]),
    "wmi_event": ("WmiEvent", 19, ["RuleName", "EventType", "UtcTime", "Operation", "User", "EventNamespace", "Name", "Query", "Type", "Destination", "Consumer", "Filter"]),
    "dns_query": ("DnsQuery", 22, COMMON + ["QueryName", "QueryStatus", "QueryResults"]),
    "file_delete": ("FileDelete", 23, COMMON + ["TargetFilename", "Hashes", "IsExecutable", "Archived"]),
    "clipboard_capture": ("ClipboardChange", 24, COMMON + ["Session", "ClientInfo", "Hashes", "Archived"]),
    "process_tampering": ("ProcessTampering", 25, COMMON + ["Type"]),
    "file_block_executable": ("FileBlockExecutable", 27, COMMON + ["TargetFilename", "Hashes"]),
    "file_block_shredding": ("FileBlockShredding", 28, COMMON + ["TargetFilename", "Hashes", "IsExecutable"]),
    "file_executable_detected": ("FileExecutableDetected", 29, COMMON + ["TargetFilename", "Hashes"]),
}
ORDER = ["ProcessCreate", "FileCreateTime", "NetworkConnect", "ProcessTerminate", "DriverLoad", "ImageLoad", "CreateRemoteThread", "RawAccessRead",
         "ProcessAccess", "FileCreate", "RegistryEvent", "FileCreateStreamHash", "PipeEvent", "WmiEvent", "DnsQuery", "FileDelete", "ClipboardChange",
         "ProcessTampering", "FileBlockExecutable", "FileBlockShredding", "FileExecutableDetected"]

AUDIT = [
    ({4624, 4625, 4634, 4647, 4648}, "Logon", True, "logon and logoff"),
    ({4634, 4647}, "Logoff", False, "logoff"),
    ({4672, 4964}, "Special Logon", False, "admin logons"),
    ({4688, 4689}, "Process Creation", False, "new processes"),
    ({4698, 4699, 4700, 4701, 4702, 5888, 5889, 5890}, "Other Object Access Events", True, "scheduled tasks and COM+ changes"),
    ({4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4765, 4766, 4767, 4780, 4781, 4794, 5376, 5377}, "User Account Management", True, "user account changes"),
    ({4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764, 4799}, "Security Group Management", True, "group changes"),
    ({4741, 4742, 4743}, "Computer Account Management", True, "computer account changes"),
    ({4768, 4771, 4772}, "Kerberos Authentication Service", True, "Kerberos TGT requests"),
    ({4769, 4770, 4773}, "Kerberos Service Ticket Operations", True, "Kerberos service tickets"),
    ({4774, 4775, 4776, 4777}, "Credential Validation", True, "NTLM credential checks"),
    ({5140}, "File Share", True, "share access"),
    ({5145}, "Detailed File Share", True, "file access on shares"),
    ({4656, 4658, 4660, 4663, 4670}, "File System", True, "file object access (needs a SACL on the folders)"),
    ({4657}, "Registry", True, "registry value changes (needs a SACL on the keys)"),
    ({4697}, "Security System Extension", True, "service installs"),
    ({5156, 5157, 5158}, "Filtering Platform Connection", True, "network connections"),
    ({4662}, "Directory Service Access", True, "Active Directory object access"),
    ({5136, 5137, 5138, 5139, 5141}, "Directory Service Changes", True, "Active Directory changes"),
    ({4673, 4674}, "Sensitive Privilege Use", True, "sensitive privileges"),
    ({1102, 4719, 4906, 4907, 4912}, "Audit Policy Change", True, "audit policy changes"),
    ({4704, 4705, 4706, 4707, 4713, 4716, 4739}, "Authentication Policy Change", True, "trust and policy changes"),
    ({4616, 4821, 4822, 4823, 4824}, "Security State Change", True, "system time and state"),
    ({4610, 4611, 4614, 4622}, "Security System Extension", True, "packages loaded by LSA"),
    ({4625}, "Account Lockout", False, "failed logons from lockouts"),
    ({4627}, "Group Membership", False, "group membership at logon"),
    ({4932, 4933}, "Directory Service Replication", True, "DC replication (DCSync)"),
]

REG_PS = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell"
REG_CMD = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"

CAP = 64


def _cover(node) -> List[List[Tuple[str, Any]]]:
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return [[(node.field, node.value)]]
    if isinstance(node, (ConditionNOT, ConditionValueExpression)):
        return [[]]
    if isinstance(node, ConditionOR):
        out: List[List[Tuple[str, Any]]] = []
        for arg in node.args:
            out.extend(_cover(arg))
            if len(out) > CAP * 4:
                return [[]]
        return out
    if isinstance(node, ConditionAND):
        acc = [[]]
        for arg in node.args:
            part = _cover(arg)
            if part == [[]]:
                continue
            if len(acc) * len(part) > CAP:
                continue
            acc = [a + b for a in acc for b in part]
        return acc
    args = getattr(node, "args", None)
    if args:
        return _cover(ConditionAND(args=list(args)))
    return [[]]


def _condition(value) -> Tuple[str, str]:
    if not isinstance(value, SigmaString):
        return "", ""
    parts = value.s
    if any(p == SpecialChars.WILDCARD_SINGLE for p in parts):
        parts = [SpecialChars.WILDCARD_MULTI if p == SpecialChars.WILDCARD_SINGLE else p for p in parts]
    lead = bool(parts) and parts[0] == SpecialChars.WILDCARD_MULTI
    tail = bool(parts) and parts[-1] == SpecialChars.WILDCARD_MULTI
    core = parts[1 if lead else 0: len(parts) - (1 if tail else 0)]
    chunks = []
    cur = ""
    for p in core:
        if isinstance(p, str):
            cur += p
        else:
            chunks.append(cur)
            cur = ""
    chunks.append(cur)
    chunks = [c for c in chunks if c]
    if not chunks:
        return "", ""
    if len(chunks) > 1:
        return "contains", max(chunks, key=len)
    text = chunks[0]
    if lead and tail:
        return "contains", text
    if lead:
        return "end with", text
    if tail:
        return "begin with", text
    return "is", text


def _rule_tag(rule) -> str:
    tid = ""
    for tag in rule.tags or []:
        t = str(tag).lower()
        m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)$", t)
        if m:
            tid = m.group(1).upper()
            break
    title = re.sub(r"[,=]", " ", rule.title or "rule")[:120]
    return f"technique_id={tid},technique_name={title}" if tid else title


def _event_ids(rule) -> List[int]:
    out = []
    for det in rule.detection.detections.values():
        stack = [det]
        while stack:
            node = stack.pop()
            items = getattr(node, "detection_items", None)
            if items is not None:
                stack.extend(items)
                continue
            if str(getattr(node, "field", "") or "").lower() == "eventid":
                for v in node.value:
                    try:
                        out.append(int(str(v)))
                    except ValueError:
                        pass
    return out


def build(inputs) -> Dict[str, Any]:
    by_type: Dict[str, Dict[str, Any]] = {}
    skipped = []
    services = set()
    ids = set()
    proc_rules = 0
    for p in parse_inputs(inputs):
        rule = p.rule
        if rule is None:
            continue
        ls = rule.logsource
        product = (ls.product or "").lower()
        category = (ls.category or "").lower()
        service = (ls.service or "").lower()
        if product and product != "windows":
            skipped.append({"title": rule.title, "reason": f"Not a Windows rule ({product})"})
            continue
        if service:
            services.add(service)
            if service in ("security", "system"):
                ids.update(_event_ids(rule))
        if category in ("ps_script", "ps_module", "ps_classic_start", "ps_classic_script"):
            services.add(category)
        if category == "process_creation":
            proc_rules += 1
        if category not in TYPES:
            if not service and category not in ("ps_script", "ps_module", "ps_classic_start", "ps_classic_script"):
                skipped.append({"title": rule.title, "reason": f"No Sysmon event for {category or 'this log source'}"})
            continue
        tag, eid, fields = TYPES[category]
        valid = {f.lower(): f for f in fields}
        slot = by_type.setdefault(tag, {"event": tag, "id": eid, "rules": [], "items": [], "all": False, "dropped": set(), "wide": []})
        slot["rules"].append(rule.title)
        try:
            trees = [c.parsed for c in rule.detection.parsed_condition]
        except Exception as exc:
            skipped.append({"title": rule.title, "reason": f"Condition could not be read: {exc}"})
            continue
        name = _rule_tag(rule)
        for tree in trees:
            for clause in _cover(tree):
                conds = []
                for field, value in clause:
                    real = valid.get(str(field).lower())
                    if str(field).lower() == "eventid":
                        continue
                    if not real:
                        slot["dropped"].add(str(field))
                        continue
                    op, text = _condition(value)
                    if not op:
                        continue
                    conds.append((real, op, text))
                conds = list(dict.fromkeys(conds))
                if not conds:
                    slot["all"] = True
                    if rule.title not in slot["wide"]:
                        slot["wide"].append(rule.title)
                    continue
                slot["items"].append((name, tuple(conds)))
    types = []
    blocks = []
    for tag in ORDER:
        slot = by_type.get(tag)
        if not slot:
            continue
        items = list(dict.fromkeys(slot["items"]))
        types.append({"event": tag, "id": slot["id"], "rules": len(slot["rules"]), "conditions": len(items), "all": slot["all"], "dropped": sorted(slot["dropped"]), "wide": slot["wide"][:10]})
        if slot["all"]:
            blocks.append(f'    <RuleGroup name="{tag}" groupRelation="or">\n      <{tag} onmatch="exclude">\n      </{tag}>\n    </RuleGroup>')
            continue
        lines = []
        for name, conds in items:
            attr = escape(name, {'"': "&quot;"})
            if len(conds) == 1:
                f, op, text = conds[0]
                lines.append(f'        <{f} name="{attr}" condition="{op}">{escape(text)}</{f}>')
            else:
                inner = "\n".join(f'          <{f} condition="{op}">{escape(text)}</{f}>' for f, op, text in conds)
                lines.append(f'        <Rule name="{attr}" groupRelation="and">\n{inner}\n        </Rule>')
        blocks.append(f'    <RuleGroup name="{tag}" groupRelation="or">\n      <{tag} onmatch="include">\n' + "\n".join(lines) + f"\n      </{tag}>\n    </RuleGroup>")
    xml = (
        '<Sysmon schemaversion="4.90">\n  <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>\n  <CheckRevocation>False</CheckRevocation>\n'
        "  <EventFiltering>\n" + "\n".join(blocks) + "\n  </EventFiltering>\n</Sysmon>\n"
    )
    audit = []
    seen = set()
    if proc_rules:
        ids.add(4688)
    for codes, sub, failure, why in AUDIT:
        hit = sorted(codes & ids)
        if not hit or sub in seen:
            continue
        seen.add(sub)
        cmd = f'auditpol /set /subcategory:"{sub}" /success:enable' + (" /failure:enable" if failure else "")
        audit.append({"subcategory": sub, "command": cmd, "why": why, "ids": hit})
    registry = []
    if 4688 in ids:
        registry.append({"path": REG_CMD, "name": "ProcessCreationIncludeCmdLine_Enabled", "value": 1, "why": "Adds the command line to event 4688"})
    if services & {"ps_script", "powershell"}:
        registry.append({"path": REG_PS + "\\ScriptBlockLogging", "name": "EnableScriptBlockLogging", "value": 1, "why": "Script block logging, event 4104"})
    if services & {"ps_module", "powershell"}:
        registry.append({"path": REG_PS + "\\ModuleLogging", "name": "EnableModuleLogging", "value": 1, "why": "Module logging, event 4103"})
        registry.append({"path": REG_PS + "\\ModuleLogging\\ModuleNames", "name": "*", "value": "*", "why": "Log every module"})
    if services & {"ps_classic_start", "ps_classic_script", "powershell-classic"}:
        registry.append({"path": REG_PS + "\\Transcription", "name": "EnableTranscripting", "value": 1, "why": "Classic PowerShell and transcripts"})
    script = []
    for a in audit:
        script.append(a["command"])
    for r in registry:
        kind = "REG_SZ" if isinstance(r["value"], str) else "REG_DWORD"
        script.append(f'reg add "{r["path"]}" /v "{r["name"]}" /t {kind} /d {r["value"]} /f')
    if by_type:
        script.append("sysmon64.exe -c sysmon-sigma-forge.xml")
    return {
        "xml": xml if by_type else "",
        "types": types,
        "audit": audit,
        "registry": registry,
        "script": "\n".join(script),
        "skipped": skipped,
        "services": sorted(services),
    }
