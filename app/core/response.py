import re
from typing import List

import yaml

from app.core.attack import load_attack, split_attack_tags
from app.core.report import NEXT_STEPS

BY_TECHNIQUE = {
    "T1003": "Reset the passwords of every account that logged on to the host, including service accounts.",
    "T1003.001": "Check what read LSASS memory, then reset passwords for accounts on the host.",
    "T1003.006": "Reset the krbtgt password twice and check which account has replication rights.",
    "T1059.001": "Get the full script from PowerShell script block logs (event 4104) and decode it.",
    "T1105": "Get the downloaded file, hash it and search for the hash on other hosts.",
    "T1053.005": "Export the task with schtasks /query /xml, then delete it after you keep a copy.",
    "T1543.003": "Look at the service binary, hash it and remove the service after you keep a copy.",
    "T1547.001": "Save the run key value and the file it points to, then remove the key.",
    "T1490": "Isolate the host now. Ransomware usually runs next. Check that backups are safe.",
    "T1486": "Isolate the host and the file shares it can reach. Do not restart it.",
    "T1110": "Check if any of the tried accounts logged on after the failures, and block the source address.",
    "T1110.003": "Find accounts that logged on from the spraying address and reset them.",
    "T1558.003": "Check the requested service accounts. Give them long random passwords.",
    "T1021.002": "Find every host the account reached over SMB in the same time window.",
    "T1562.001": "Turn the security tool back on and find what changed it.",
    "T1070.001": "Collect logs from your SIEM for this host, since the local ones were cleared.",
    "T1071.004": "Block the domain at the DNS server and look for the same queries on other hosts.",
    "T1136.001": "Disable the new account and check what it did.",
    "T1098": "Remove the account from the group and check who added it.",
}
FIRST = "Check the user and host. Confirm with the owner whether the activity was expected."


def suggest(content: str) -> List[str]:
    from app.core.parsing import parse_file

    steps: List[str] = [FIRST]
    for p in parse_file("rule.yml", content):
        if p.rule is None:
            continue
        tids, tactics = split_attack_tags(p.rule.tags)
        for t in tids:
            step = BY_TECHNIQUE.get(t.upper()) or BY_TECHNIQUE.get(t.upper().split(".")[0])
            if step and step not in steps:
                steps.append(step)
        known = load_attack().get("techniques", {})
        tac = set(x.replace("_", "-") for x in tactics)
        for t in tids:
            tac.update(known.get(t.upper(), {}).get("tactics", []))
        for t in tac:
            step = NEXT_STEPS.get(t)
            if step and step not in steps:
                steps.append(step)
        break
    steps.append("Write down what you found in a case and close it, or tune the rule if it was a false positive.")
    return steps[:10]


def set_steps(content: str, steps: List[str]) -> str:
    steps = [re.sub(r"\s+", " ", s).strip()[:500] for s in steps if s and s.strip()][:30]
    lines = content.rstrip("\n").split("\n")
    out = []
    skip = False
    for line in lines:
        if re.match(r"^response\s*:", line):
            skip = True
            continue
        if skip:
            if line.startswith((" ", "\t", "-")) or not line.strip():
                continue
            skip = False
        out.append(line)
    if steps:
        block = ["response:"] + ["    - " + yaml.safe_dump(s, default_flow_style=True, width=10000, allow_unicode=True).strip().removesuffix("...").strip() for s in steps]
        idx = next((i for i, l in enumerate(out) if re.match(r"^level\s*:", l)), None)
        if idx is None:
            out += block
        else:
            out = out[: idx + 1] + block + out[idx + 1:]
    return "\n".join(out) + "\n"
