from typing import Dict, List, Optional, Tuple

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

SYSMON_EVENTS: Dict[str, List[int]] = {
    "process_creation": [1],
    "file_change": [2],
    "network_connection": [3],
    "sysmon_status": [4, 16],
    "process_termination": [5],
    "driver_load": [6],
    "image_load": [7],
    "create_remote_thread": [8],
    "raw_access_thread": [9],
    "raw_access_read": [9],
    "process_access": [10],
    "file_event": [11],
    "registry_add": [12],
    "registry_delete": [12],
    "registry_set": [13],
    "registry_rename": [14],
    "registry_event": [12, 13, 14],
    "create_stream_hash": [15],
    "pipe_created": [17, 18],
    "wmi_event": [19, 20, 21],
    "dns_query": [22],
    "file_delete": [23, 26],
    "clipboard_capture": [24],
    "process_tampering": [25],
    "file_delete_detected": [26],
    "file_block_executable": [27],
    "file_block_shredding": [28],
    "file_executable_detected": [29],
    "sysmon_error": [255],
}

WINDOWS_CATEGORY_CHANNELS: Dict[str, Tuple[str, List[int]]] = {
    "ps_script": ("Microsoft-Windows-PowerShell/Operational", [4104]),
    "ps_module": ("Microsoft-Windows-PowerShell/Operational", [4103]),
    "ps_classic_start": ("Windows PowerShell", [400]),
    "ps_classic_provider_start": ("Windows PowerShell", [600]),
    "ps_classic_script": ("Windows PowerShell", [800]),
}

WINDOWS_SERVICE_CHANNELS: Dict[str, str] = {
    "security": "Security",
    "system": "System",
    "application": "Application",
    "sysmon": SYSMON_CHANNEL,
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "powershell-classic": "Windows PowerShell",
    "taskscheduler": "Microsoft-Windows-TaskScheduler/Operational",
    "wmi": "Microsoft-Windows-WMI-Activity/Operational",
    "dns-server": "DNS Server",
    "dns-client": "Microsoft-Windows-DNS Client Events/Operational",
    "driver-framework": "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    "windefend": "Microsoft-Windows-Windows Defender/Operational",
    "bits-client": "Microsoft-Windows-Bits-Client/Operational",
    "codeintegrity-operational": "Microsoft-Windows-CodeIntegrity/Operational",
    "firewall-as": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "ntlm": "Microsoft-Windows-NTLM/Operational",
    "printservice-admin": "Microsoft-Windows-PrintService/Admin",
    "printservice-operational": "Microsoft-Windows-PrintService/Operational",
    "terminalservices-localsessionmanager": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "smbclient-security": "Microsoft-Windows-SmbClient/Security",
    "appxdeployment-server": "Microsoft-Windows-AppXDeploymentServer/Operational",
    "lsa-server": "Microsoft-Windows-LSA/Operational",
    "openssh": "OpenSSH/Operational",
    "shell-core": "Microsoft-Windows-Shell-Core/Operational",
    "vhdmp": "Microsoft-Windows-VHDMP/Operational",
    "diagnosis-scripted": "Microsoft-Windows-Diagnosis-Scripted/Operational",
    "ldap_debug": "Microsoft-Windows-LDAP-Client/Debug",
}

WINDOWS_SYSTEM_FIELDS: Dict[str, str] = {
    "EventID": "win.system.eventID",
    "Channel": "win.system.channel",
    "Provider_Name": "win.system.providerName",
    "Provider": "win.system.providerName",
    "Computer": "win.system.computer",
    "Level": "win.system.level",
    "Keywords": "win.system.keywords",
    "Task": "win.system.task",
    "Opcode": "win.system.opcode",
    "EventRecordID": "win.system.eventRecordID",
}


def lower_first(name: str) -> str:
    return name[:1].lower() + name[1:] if name else name


def map_field(field: str, product: str) -> Tuple[str, bool]:
    if product != "windows":
        return field, False
    if field in WINDOWS_SYSTEM_FIELDS:
        return WINDOWS_SYSTEM_FIELDS[field], True
    if field.startswith("win.") or "." in field:
        return field, True
    return f"win.eventdata.{lower_first(field)}", True


class ParentSpec:
    def __init__(self, group: Optional[str], channel: Optional[str], event_ids: List[int], note: Optional[str] = None):
        self.group = group
        self.channel = channel
        self.event_ids = event_ids
        self.note = note


def resolve_parent(product: str, category: str, service: str) -> ParentSpec:
    product = (product or "").lower()
    category = (category or "").lower()
    service = (service or "").lower()

    if product != "windows":
        label = "/".join(x for x in [product, category, service] if x) or "empty logsource"
        return ParentSpec(None, None, [], f"No Wazuh parent mapping for logsource {label}. Field names are kept as they are, so check them against your decoder.")

    if category in SYSMON_EVENTS:
        return ParentSpec("sysmon", None, SYSMON_EVENTS[category])

    if category in WINDOWS_CATEGORY_CHANNELS:
        channel, ids = WINDOWS_CATEGORY_CHANNELS[category]
        return ParentSpec("windows", channel, ids)

    if service == "sysmon":
        return ParentSpec("sysmon", None, [])

    if service in WINDOWS_SERVICE_CHANNELS:
        return ParentSpec("windows", WINDOWS_SERVICE_CHANNELS[service], [])

    label = category or service or "none"
    return ParentSpec("windows", None, [], f"Windows logsource '{label}' has no channel mapping. The rule only uses if_group windows.")
