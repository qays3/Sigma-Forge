import argparse
import json
import os
import sys
import time
from pathlib import Path

import requests
import urllib3


class WazuhAPI:
    def __init__(self, url, user, password, verify):
        self.url = url.rstrip("/")
        self.verify = verify
        self.session = requests.Session()
        res = self.session.post(f"{self.url}/security/user/authenticate", auth=(user, password), verify=verify, timeout=30)
        res.raise_for_status()
        token = res.json()["data"]["token"]
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def upload_rules(self, name, content):
        res = self.session.put(
            f"{self.url}/rules/files/{name}",
            params={"overwrite": "true"},
            data=content.encode("utf-8"),
            headers={"Content-Type": "application/octet-stream"},
            verify=self.verify,
            timeout=60,
        )
        res.raise_for_status()
        return res.json()

    def validate(self):
        res = self.session.get(f"{self.url}/manager/configuration/validation", verify=self.verify, timeout=60)
        res.raise_for_status()
        return res.json()

    def restart(self, wait_seconds=90):
        self.session.put(f"{self.url}/manager/restart", verify=self.verify, timeout=60).raise_for_status()
        deadline = time.time() + wait_seconds
        time.sleep(5)
        while time.time() < deadline:
            try:
                res = self.session.get(f"{self.url}/manager/status", verify=self.verify, timeout=10)
                if res.ok:
                    items = res.json()["data"]["affected_items"][0]
                    if items.get("wazuh-analysisd") == "running":
                        return True
            except requests.RequestException:
                pass
            time.sleep(3)
        return False

    def logtest(self, event, log_format, location, token=None):
        body = {"event": event, "log_format": log_format, "location": location}
        if token:
            body["token"] = token
        res = self.session.put(f"{self.url}/logtest", json=body, verify=self.verify, timeout=30)
        res.raise_for_status()
        return res.json()["data"]

    def end_session(self, token):
        try:
            self.session.delete(f"{self.url}/logtest/sessions/{token}", verify=self.verify, timeout=10)
        except requests.RequestException:
            pass


def load_events(path):
    events = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        obj = json.loads(line)
        if isinstance(obj, dict) and "event" in obj:
            event = obj["event"]
            expect = obj.get("expect")
            name = obj.get("name", f"line {number}")
        else:
            event, expect, name = obj, None, f"line {number}"
        text = event if isinstance(event, str) else json.dumps(event)
        events.append({"name": name, "event": text, "expect": str(expect) if expect is not None else None})
    return events


def expectation_met(expect, got, description):
    if expect.lower() == "none":
        return not description.startswith("Sigma:")
    if expect.isdigit():
        return expect == got
    return expect.lower() in description.lower()


def main():
    parser = argparse.ArgumentParser(description="Upload Sigma Forge Wazuh rules and test them with the Wazuh logtest API")
    parser.add_argument("--url", default=os.getenv("WAZUH_API_URL", "https://127.0.0.1:55000"))
    parser.add_argument("--user", default=os.getenv("WAZUH_API_USER", "wazuh"))
    parser.add_argument("--password", default=os.getenv("WAZUH_API_PASSWORD"))
    parser.add_argument("--rules", help="Wazuh rules XML exported from Sigma Forge")
    parser.add_argument("--rules-name", default="sigma_forge_rules.xml", help="File name on the manager")
    parser.add_argument("--events", required=True, help="JSON Lines file with events to test")
    parser.add_argument("--log-format", default="eventchannel")
    parser.add_argument("--location", default="EventChannel")
    parser.add_argument("--no-restart", action="store_true", help="Upload rules without restarting the manager")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate checks (lab managers with self signed certs)")
    args = parser.parse_args()

    if not args.password:
        print("Set --password or WAZUH_API_PASSWORD", file=sys.stderr)
        return 2
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        api = WazuhAPI(args.url, args.user, args.password, verify=not args.insecure)
    except Exception as exc:
        print(f"Login failed: {exc}", file=sys.stderr)
        return 1

    if args.rules:
        content = Path(args.rules).read_text(encoding="utf-8")
        print(f"Uploading {args.rules} as {args.rules_name}")
        api.upload_rules(args.rules_name, content)
        if not args.no_restart:
            print("Restarting manager")
            if not api.restart():
                print("Manager did not come back in time. Check ossec.log for rule errors.", file=sys.stderr)
                return 1

    events = load_events(args.events)
    token = None
    passed = failed = 0
    print(f"\n{'RESULT':8} {'EXPECT':8} {'GOT':8} {'LEVEL':5}  NAME / DESCRIPTION")
    for item in events:
        data = api.logtest(item["event"], args.log_format, args.location, token)
        token = data.get("token", token)
        rule = (data.get("output") or {}).get("rule") or {}
        got = str(rule.get("id", "-"))
        level = str(rule.get("level", "-"))
        desc = rule.get("description", "no rule matched")
        if item["expect"] is None:
            status = "INFO"
        elif expectation_met(item["expect"], got, desc):
            status = "PASS"
            passed += 1
        else:
            status = "FAIL"
            failed += 1
        print(f"{status:8} {str(item['expect'] or '-'):8} {got:8} {level:5}  {item['name']} / {desc}")

    if token:
        api.end_session(token)
    print(f"\n{passed} passed, {failed} failed, {len(events)} events")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
