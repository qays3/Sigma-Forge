<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="web/assets/img/banner.png">
  <source media="(prefers-color-scheme: light)" srcset="web/assets/img/banner-light.png">
  <img src="web/assets/img/banner-light.png" alt="Sigma Forge" width="720">
</picture>

Convert Sigma rules to 31 SIEM, EDR and log platforms, test and tune them on real logs, hunt on your own machine with Sigma and YARA, and see which MITRE ATT&CK techniques they cover.

![Python](https://img.shields.io/badge/Python-3.10%2B-B06CFF?style=flat-square&logo=python&logoColor=white&labelColor=0A1120)
![FastAPI](https://img.shields.io/badge/FastAPI-backend-B06CFF?style=flat-square&logo=fastapi&logoColor=white&labelColor=0A1120)
![pySigma](https://img.shields.io/badge/pySigma-1.5-B06CFF?style=flat-square&labelColor=0A1120)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v20-B06CFF?style=flat-square&labelColor=0A1120)
![Docker](https://img.shields.io/badge/Docker-ready-B06CFF?style=flat-square&logo=docker&logoColor=white&labelColor=0A1120)
![Platforms](https://img.shields.io/badge/Linux%20%7C%20Windows%20%7C%20macOS-supported-B06CFF?style=flat-square&labelColor=0A1120)

</div>

## Table of contents

1. [What is Sigma Forge](#what-is-sigma-forge)
2. [Features](#features)
3. [Demo video](#demo-video)
4. [Screenshots](#screenshots)
5. [Quick start](#quick-start)
6. [Setup script options](#setup-script-options)
7. [How to use it](#how-to-use-it)
8. [Sample pack](#sample-pack)
9. [Supported targets](#supported-targets) and [target guide](#target-guide)
10. [Automatic fallbacks](#automatic-fallbacks)
11. [Correlation rules](#correlation-rules)
12. [ATT&CK coverage](#attck-coverage)
13. [Threat groups, log readiness and reports](#threat-groups-log-readiness-and-reports)
14. [Testing rules on logs](#testing-rules-on-logs)
15. [Noise check and filters](#noise-check-and-filters)
16. [Building rules: from a query, from an event](#building-rules-from-a-query-from-an-event)
17. [Rule quality score and version history](#rule-quality-score-and-version-history)
18. [Hunt: scan this machine](#hunt-scan-this-machine)
19. [YARA](#yara)
20. [Deploy to your SIEM](#deploy-to-your-siem)
21. [GitHub sync](#github-sync)
22. [Command line and GitHub Action](#command-line-and-github-action)
23. [SigmaHQ library](#sigmahq-library)
24. [Field mapping](#field-mapping)
25. [Export packages](#export-packages)
26. [API](#api)
27. [Configuration](#configuration)
28. [Architecture](#architecture)
29. [Project layout](#project-layout)
30. [Development](#development)
31. [Known limits](#known-limits)
32. [Credits](#credits)

## What is Sigma Forge

[Sigma](https://github.com/SigmaHQ/sigma) is an open format for writing detection rules once and running them on any SIEM (Security Information and Event Management) platform. Sigma Forge is a local web app that takes a folder of Sigma rules and helps you write, check, test, convert and ship them:

1. **Conversion** to 31 targets across 19 platforms: Splunk, Elastic, OpenSearch, Microsoft, CrowdStrike, SentinelOne, Palo Alto, Google SecOps, Carbon Black, QRadar, Wazuh and more, with ready to deploy packages for each.
2. **Quality checks** with the pySigma validators, plus checks for revoked or unknown ATT&CK tags, live in a rule editor.
3. **Testing** on your own EVTX or JSON logs, so you see which rules fire before you deploy them.
4. **Coverage** on a full MITRE ATT&CK (Adversarial Tactics, Techniques and Common Knowledge) Enterprise heat map, by technique and by log source, with gap suggestions from the SigmaHQ library and export to ATT&CK Navigator.
5. **Hunting** on the machine it runs on: Sigma on the live Windows Event Logs, YARA on any folder, or uploaded `.evtx` files.
6. **Shipping**: deploy straight to Splunk, Elastic, Sentinel or Wazuh, or run the same checks in CI (Continuous Integration) with the command line and the GitHub Action.

Everything runs on your machine. Rules are kept in your browser (IndexedDB) and are only sent to your own Sigma Forge server when you analyze or convert them.

## Features

| Area | What you get |
|---|---|
| **Load rules** | Drag and drop files or whole folders, pick a folder, paste YAML, load the built in sample pack (which includes one rule for every Enterprise technique) or rules from the SigmaHQ library. Multi document files and `action: global` collections are supported. |
| **Editor** | Write a rule with templates, line numbers and live checks. The query for any target, the ATT&CK mapping and the quality score update as you type. Start from a query or an event, save with Ctrl+S and go back to any saved version. |
| **Correlations** | Sigma correlation rules (`event_count`, `value_count`, `temporal`) are parsed, listed and converted on every target whose backend supports them. |
| **Convert** | 31 targets: Splunk SPL, SPL2 and CIM, Elastic Lucene, ES\|QL, EQL and ElastAlert, OpenSearch Lucene and PPL, Microsoft KQL (Defender XDR, Sentinel ASIM, Azure Monitor), CrowdStrike LogScale, SentinelOne, Cortex XDR, Google SecOps UDM and YARA-L, Carbon Black, QRadar AQL, Logpoint, NetWitness, Sumo Logic, Panther, Trellix Helix, Grafana Loki, Quickwit, ClickHouse, SQLite (Zircolite), SurrealQL and Wazuh. Every output format of each backend is available. See the [target guide](#target-guide). |
| **Compare** | One rule, up to four platforms side by side, to see how each writes the same detection. |
| **Test on logs** | Drop EVTX, JSON or JSON lines files, load the sample logs, a normal baseline week or generated test events. Events are loaded into SQLite and every rule runs on them, correlations included. See hits, noisy and silent rules and the matching events. |
| **SigmaHQ library** | Sync the full SigmaHQ release (more than 3,000 rules) or upload the zip offline, search by technique, log source, level or status, and add rules to the workspace. |
| **Field mapping** | Profiles that rename Sigma fields to your own field names, with ECS, Wazuh and Splunk CIM presets. Used by Convert, Compare, Test, the editor and exports. |
| **Export packages** | A zip per platform ready to deploy: a Splunk app, Kibana detection rules, a Sentinel ARM template, a Wazuh rules file, a Loki ruler file, YARA-L rules, a Zircolite pack and more, each with a README and a manifest. |
| **Validate** | pySigma validators (dangling detections, wildcard misuse, duplicate tags, bad modifier mixes and more) run offline, plus ATT&CK tag checks against local data. |
| **Coverage** | ATT&CK v20 Enterprise heat map with every tactic, technique counts that roll up from sub techniques, coverage by log source, the biggest gaps compared with SigmaHQ, and a Navigator layer export. |
| **Threat groups** | Pick one of 174 ATT&CK threat groups (APT29, FIN7 and more). The map highlights what the group uses and what you miss, with a list of missing techniques to write first. |
| **Log readiness** | Tick the log sources you really collect. Coverage then shows what you can detect today and marks blind spots: techniques covered on paper whose logs you do not have. |
| **Coverage report** | One click printable HTML report with KPIs (Key Performance Indicators), tactic bars, readiness, the threat group, SigmaHQ gaps and rule quality. Print it to PDF for a manager. |
| **Atomic Red Team** | Each technique lists the matching [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests (1,950 tests for 353 techniques, offline) so you can make your rules fire for real. |
| **Noise check** | Run rules on a normal week of logs. Each rule gets hits per 1000 events (quiet, busy, noisy), the top values behind the hits, and suggested filters. One click adds the filter and opens the rule in the editor. |
| **Auto test events** | Builds events that each rule should catch, straight from its detection logic. Every one of the 269 sample rules fires on its own events. |
| **Rule from an event** | Click any matching event (or paste one) and pick the fields that make it stand out. Sigma Forge drafts the rule. |
| **Query to rule** | Paste a Splunk SPL, Sentinel or Defender KQL, Kibana or Lucene, Elastic EQL or ES\|QL query and get a Sigma rule back, with field names mapped to Sigma and the log source guessed. Then convert it to any other platform. |
| **Quality score** | Every rule gets a score from 0 to 100 and a grade (A to F) from 12 checks: description, references, ATT&CK tags, real false positives, filters, status and more. Shown in the rules table, the editor and reports. |
| **Version history** | Every save in the editor keeps a version (30 per file). See a line diff against the editor and restore any version. |
| **Hunt** | Scan the machine Sigma Forge runs on: Sigma rules on the live Windows Event Logs (Sysmon, Security, PowerShell and more), YARA rules on folders, or uploaded `.evtx` files from another machine. |
| **YARA** | Write YARA rules in an editor checked by the real YARA engine, scan files you drop in, or whole folders from the Hunt page. Matches show the string, offset, text and hex. |
| **Deploy** | Push rules to Splunk (saved searches), Elastic Security (detection rules), Microsoft Sentinel (analytics rules) or a Wazuh manager (rules file) through their APIs. A dry run shows every request first. |
| **GitHub sync** | Pull rules from any public GitHub repository or folder, save it as a source, and sync it again later to get the newest rules. |
| **CLI and GitHub Action** | `sigma-forge validate`, `test`, `convert`, `coverage`, `export`, `from-query`, `hunt` and `yara` on the command line, plus a GitHub Action that checks every pull request and writes a job summary. |
| **Review** | Sortable and filterable rule table with a quality grade column and a detail drawer: metadata, findings, quality checks, source and a one click convert to any target. |
| **Run anywhere** | One setup script for Linux and macOS (`setup.sh`), one for Windows (`setup.ps1`), both using a Python venv, or Docker with a hardened compose file. |
| **UI** | SPA with clean URLs, the animated Sigma Forge logo on the splash screen, header, loading panels and empty states, dark and light themes, skeleton loading while data loads, keyboard support and a mobile layout. |

## Demo video

<a href="media/sigma-forge-demo.mp4"><img src="media/sigma-forge-demo.jpg" alt="Watch the Sigma Forge demo video" width="100%"></a>

A two minute tour of every page: loading the samples, converting to Sentinel and exporting a package, writing a rule in the editor, testing rules on sample logs, the full ATT&CK coverage map, the SigmaHQ library, comparing platforms, reviewing rules and setting a field mapping. Click the picture to open [`media/sigma-forge-demo.mp4`](media/sigma-forge-demo.mp4) (1080p, 60 fps, with sound).

## Screenshots

<table>
  <tr>
    <td width="50%"><img src="web/assets/img/screenshots/workspace.png" alt="Workspace"><p align="center"><b>Workspace</b>: load rules and see an overview</p></td>
    <td width="50%"><img src="web/assets/img/screenshots/convert.png" alt="Convert to Splunk"><p align="center"><b>Convert</b>: Splunk SPL from the sample pack</p></td>
  </tr>
  <tr>
    <td width="50%"><img src="web/assets/img/screenshots/convert-target.png" alt="Convert to Sentinel"><p align="center"><b>Targets</b>: 31 platforms with tips for each</p></td>
    <td width="50%"><img src="web/assets/img/screenshots/coverage.png" alt="ATT&CK heat map"><p align="center"><b>Coverage</b>: ATT&amp;CK heat map</p></td>
  </tr>
  <tr>
    <td width="50%"><img src="web/assets/img/screenshots/coverage-technique.png" alt="Technique detail"><p align="center"><b>Technique</b>: sub techniques and rules</p></td>
    <td width="50%"><img src="web/assets/img/screenshots/rules.png" alt="Rules table"><p align="center"><b>Rules</b>: search, filter and sort</p></td>
  </tr>
  <tr>
    <td width="50%"><img src="web/assets/img/screenshots/coverage-sources.png" alt="Coverage by log source"><p align="center"><b>Log sources and gaps</b>: what SigmaHQ covers that you do not</p></td>
    <td width="50%"><img src="web/assets/img/screenshots/editor.png" alt="Rule editor"><p align="center"><b>Editor</b>: live checks and queries as you type</p></td>
  </tr>
  <tr>
    <td width="50%"><img src="web/assets/img/screenshots/compare.png" alt="Compare targets"><p align="center"><b>Compare</b>: one rule on four platforms</p></td>
    <td width="50%"><img src="web/assets/img/screenshots/test.png" alt="Test on logs"><p align="center"><b>Test</b>: run rules on EVTX and JSON logs</p></td>
  </tr>
  <tr>
    <td width="50%"><img src="web/assets/img/screenshots/test-detail.png" alt="Test hit detail"><p align="center"><b>Hits</b>: the events a rule matched</p></td>
    <td width="50%"><img src="web/assets/img/screenshots/library.png" alt="SigmaHQ library"><p align="center"><b>Library</b>: search and import SigmaHQ rules</p></td>
  </tr>
  <tr>
    <td width="50%"><img src="web/assets/img/screenshots/mappings.png" alt="Field mapping"><p align="center"><b>Mappings</b>: rename fields to match your data</p></td>
    <td width="50%"><img src="web/assets/img/screenshots/export.png" alt="Export package"><p align="center"><b>Export</b>: ready to deploy packages</p></td>
  </tr>
  <tr>
    <td width="50%"><img src="web/assets/img/screenshots/rule-detail.png" alt="Rule detail"><p align="center"><b>Rule detail</b>: convert any rule in one click</p></td>
    <td width="50%"><img src="web/assets/img/screenshots/quality.png" alt="Quality score"><p align="center"><b>Quality</b>: a score and grade from 12 checks</p></td>
  </tr>
  <tr>
    <td width="50%"><img src="web/assets/img/screenshots/threat-group.png" alt="Threat group coverage"><p align="center"><b>Threat group</b>: what APT29 uses and what you miss</p></td>
    <td width="50%"><img src="web/assets/img/screenshots/readiness.png" alt="Log readiness"><p align="center"><b>Log readiness</b>: blind spots from missing logs</p></td>
  </tr>
  <tr>
    <td width="50%"><img src="web/assets/img/screenshots/atomic.png" alt="Atomic Red Team tests"><p align="center"><b>Atomic Red Team</b>: tests for each technique</p></td>
    <td width="50%"><img src="web/assets/img/screenshots/noise.png" alt="Noise check"><p align="center"><b>Noise check</b>: hits per 1000 events and filters</p></td>
  </tr>
  <tr>
    <td width="50%"><img src="web/assets/img/screenshots/rule-from-event.png" alt="Rule from an event"><p align="center"><b>Rule from an event</b>: pick fields, get a rule</p></td>
    <td width="50%"><img src="web/assets/img/screenshots/query-to-rule.png" alt="Query to rule"><p align="center"><b>Query to rule</b>: Splunk, KQL or Elastic to Sigma</p></td>
  </tr>
  <tr>
    <td width="50%"><img src="web/assets/img/screenshots/history.png" alt="Version history"><p align="center"><b>History</b>: diff and restore saved versions</p></td>
    <td width="50%"><img src="web/assets/img/screenshots/deploy.png" alt="Deploy"><p align="center"><b>Deploy</b>: dry run, then push to your SIEM</p></td>
  </tr>
  <tr>
    <td width="50%"><img src="web/assets/img/screenshots/hunt.png" alt="Hunt"><p align="center"><b>Hunt</b>: scan this machine with YARA and Sigma</p></td>
    <td width="50%"><img src="web/assets/img/screenshots/yara.png" alt="YARA editor"><p align="center"><b>YARA</b>: write, check and scan</p></td>
  </tr>
  <tr>
    <td width="50%"><img src="web/assets/img/screenshots/yara-hit.png" alt="YARA match"><p align="center"><b>YARA match</b>: strings, offsets and hex</p></td>
    <td width="50%"><img src="web/assets/img/screenshots/light.png" alt="Light theme"><p align="center"><b>Light theme</b></p></td>
  </tr>
</table>

## Quick start

You need **Python 3.10 or newer**. Docker is optional.

### Linux and macOS

```bash
git clone https://github.com/qays3/Sigma-Forge.git
cd Sigma-Forge
chmod +x setup.sh
./setup.sh --run
```

### Windows (PowerShell)

```powershell
git clone https://github.com/qays3/Sigma-Forge.git
cd Sigma-Forge
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup.ps1 -Run
```

### Docker

```bash
docker compose up -d --build
```

Then open **http://127.0.0.1:8000** and click **Load samples** to load the [sample pack](#sample-pack).

The setup scripts create a virtual environment in `.venv`, install the packages from `requirements.txt`, check the ATT&CK data and print the command to start the server. Run them again any time. They only change what is needed.

### Manual setup

If you prefer to do it by hand:

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Setup script options

| `setup.sh` | `setup.ps1` | What it does |
|---|---|---|
| `--run` | `-Run` | Start the server after setup |
| `--dev` | `-Dev` | Install test tools and run the test suite |
| `--update-attack` | `-UpdateAttack` | Download the latest MITRE ATT&CK data |
| `--docker` | `-Docker` | Build and start with Docker Compose instead of a venv |
| `--recreate` | `-Recreate` | Delete and rebuild `.venv` |
| `--host HOST` | `-BindHost HOST` | Bind address (default `127.0.0.1`) |
| `--port PORT` | `-Port PORT` | Port (default `8000`) |
| `--help` | `-Help` | Show help |

Examples:

```bash
./setup.sh --dev                      # install, then run the tests
./setup.sh --update-attack --run      # refresh ATT&CK data and start
./setup.sh --host 0.0.0.0 --port 9000 --run
```

```powershell
.\setup.ps1 -Dev
.\setup.ps1 -UpdateAttack -Run
.\setup.ps1 -BindHost 0.0.0.0 -Port 9000 -Run
```

## How to use it

```mermaid
flowchart LR
    L[SigmaHQ library] --> A
    A[Load rules<br/>files, folder, paste, packs] --> B[Workspace<br/>overview and checks]
    ED[Editor<br/>write and check live] --> B
    B --> T[Test<br/>run on EVTX and JSON logs]
    B --> C[Convert<br/>pick a target and format]
    B --> CP[Compare<br/>four targets side by side]
    B --> D[Coverage<br/>ATT&CK heat map and gaps]
    B --> E[Rules<br/>review and quick convert]
    M[Mappings<br/>your field names] -.-> C
    M -.-> T
    C --> F[Copy, download<br/>or export a package]
    C --> DP[Deploy<br/>Splunk, Elastic, Sentinel, Wazuh]
    D --> G[Navigator layer<br/>and HTML report]
    D -.-> L
    GH[GitHub repo] --> A
    Q[SIEM query or event] --> ED
    T -.-> ED
    H[Hunt<br/>live logs, evtx, YARA] --> B
```

1. **Workspace.** Drop rule files or a folder on the drop zone, or click **Load samples** (and **Load error samples** to see how problems are reported). You see how many rules parsed, how many have errors or findings, and a breakdown by level and log source.
2. **Convert.** Pick a target on the left, choose an output format, select the rules, and press **Convert**. Each rule gets its own card with the query, any notes and a copy button. Tabs above the cards filter them by Converted, Skipped and Failed. **Download** saves all converted rules as one file.
3. **Coverage.** The heat map shows every ATT&CK Enterprise tactic and technique. Darker purple means more rules. Click a technique to see its sub techniques and the rules that cover it. Use **Covered only** to hide gaps, or keep them visible to find what to write next. **Navigator layer** downloads a JSON layer for [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
4. **Rules.** Search and filter by level, status, product, tactic or check state. Click a row to open the detail drawer with metadata, validator findings, the rule source and a quick convert to any target.
5. **Editor.** Start from a template or open a workspace rule. Checks, the query for the chosen target and the ATT&CK tags refresh as you type. **Save to workspace** (or Ctrl+S) stores it. Your draft is kept in the browser between visits.
6. **Compare.** Pick one rule and up to four platforms to see their queries next to each other.
7. **Test.** Drop log files or click **Load sample logs**, choose how strictly log sources must match, and press **Run test**. Tabs split the rules into Fired, Silent, Errors and Skipped. **Details** shows the matching events, correlation alerts and the SQLite query that ran.
8. **Library.** Click **Sync now** to download the latest SigmaHQ release, then search and add rules. The Coverage page uses it to suggest rules for the techniques you miss.
9. **Mappings.** Make a profile of field renames, or start from a preset, and press **Save and use**. Convert, Compare and Test also let you pick a profile per run.
10. **Export.** On the Convert page, **Export package** builds a zip for the selected target with install steps.
11. **Deploy.** On the Convert page, **Deploy** sends the selected rules to Splunk, Elastic, Sentinel or Wazuh. Press **Dry run** first to see every request.
12. **Hunt.** Run Sigma on the live event logs of this machine, scan folders with YARA, or upload `.evtx` files.
13. **YARA.** Keep YARA rules next to your Sigma rules, check them and scan files.

## Sample pack

The [`sample`](sample) folder has rules, logs, test events and API requests that touch every feature. In the Workspace:

* **Load samples** loads 266 rule files: the 39 feature samples that show every modifier, log source and rule type, plus the ATT&CK pack with one rule for every ATT&CK Enterprise technique across all 15 tactics, so the heat map lights up end to end.
* **Load error samples** adds the six files in `sample/rules/broken`, which show how errors and findings look.

```mermaid
flowchart LR
    S[sample] --> R[rules]
    S --> W[wazuh<br/>events.jsonl]
    S --> LG[logs<br/>EVTX style JSON, auditd, cloud]
    S --> A[api<br/>request bodies and scripts]
    R --> R1[windows]
    R --> R2[linux]
    R --> R3[network]
    R --> R4[cloud]
    R --> R5[modifiers]
    R --> R6[correlation]
    R --> R7[collections]
    R --> R8[broken]
    R --> R9[attack<br/>227 rules, 15 tactics]
```

| Folder | What it shows |
|---|---|
| [`rules/windows`](sample/rules/windows) | 21 rules over Sysmon categories (process creation, network, image and driver load, remote thread, process access, pipes, WMI, files, registry, DNS) and Windows services (Security, System, PowerShell script and module logs, Defender). Levels from informational to critical. |
| [`rules/linux`](sample/rules/linux) | Process creation and auditd rules, including a keyword search. |
| [`rules/network`](sample/rules/network) | Proxy and firewall rules, with `cidr`. |
| [`rules/cloud`](sample/rules/cloud) | AWS CloudTrail and Azure sign in rules. Some pipelines do not map these, so you see clear per rule errors. |
| [`rules/modifiers`](sample/rules/modifiers) | One rule per group of modifiers: `contains`, `all`, `windash`, `re` with flags, `base64`, `wide` with `base64offset`, `cidr`, `exists`, `null`, `cased`, wildcards and keyword search. When a target cannot do one of them, Sigma Forge rewrites it to the closest thing the target can do and says so on the card. |
| [`rules/correlation`](sample/rules/correlation) | An `event_count` brute force rule and a `value_count` password spray rule. See [correlation rules](#correlation-rules) for the targets that convert them. |
| [`rules/collections`](sample/rules/collections) | A file with three rules, and an `action: global` file that shares one log source and selection between two rules. |
| [`rules/broken`](sample/rules/broken) | A YAML error, a missing detection, an unknown modifier, revoked and unknown ATT&CK tags, validator findings and a rule with no id or level. They show how errors and findings look. |
| [`rules/attack`](sample/rules/attack) | The ATT&CK pack: one folder per tactic (`01_reconnaissance` to `15_impact`) with one rule for each Enterprise technique. A technique that sits in several tactics is tagged with all of them and stored under the first. The rules use Windows, Linux, macOS, cloud (AWS, Azure, Microsoft 365, GCP), Kubernetes, ESXi, proxy, web server and firewall log sources. They are samples to learn from, so tune them before production use. |
| [`logs`](sample/logs) | Six log files for the Test page: Sysmon and Security events in the same JSON layout the EVTX parser makes (both `EventData` styles), PowerShell and Defender events, Linux auditd and process events, firewall and proxy events, and AWS CloudTrail plus Azure sign in records. Every feature sample rule fires on them, and the failed logon bursts trigger both correlation rules. |
| [`wazuh/events.jsonl`](sample/wazuh/events.jsonl) | Test events for the Wazuh target's `wazuh_check.py` tool. |
| [`api`](sample/api) | Ready request bodies for every endpoint, plus `run_examples.sh` and `run_examples.ps1` that call them and save the answers in `sample/api/output`. |

Try the API samples while the server runs:

```bash
./sample/api/run_examples.sh                  # Linux and macOS
```

```powershell
.\sample\api\run_examples.ps1                # Windows
```

## Supported targets

Sigma Forge converts to **31 targets** across 19 platforms. Each one runs on a pySigma backend or on a backend that ships with Sigma Forge.

| Target | Language | Formats | Sample pack | Correlations |
|---|---|---|---|---|
| [Splunk SPL](#splunk) | spl | `default`, `savedsearches` | 42 of 44 | yes |
| [Splunk CIM](#splunk-cim) | spl | `default`, `savedsearches`, `data_model` | 40 of 44 | no |
| [Splunk SPL2](#splunk-spl2) | spl2 | `default`, `module` | 40 of 44 | no |
| [Elastic Lucene](#elastic-lucene) | lucene | `default`, `kibana_ndjson`, `dsl_lucene`, `siem_rule`, `siem_rule_ndjson` | 40 of 44 | no |
| [Elastic ES\|QL](#elastic-esql) | esql | `default`, `kibana_ndjson`, `siem_rule`, `siem_rule_ndjson` | 42 of 44 | yes |
| [Elastic EQL](#elastic-eql) | eql | `default`, `eqlapi`, `siem_rule`, `siem_rule_ndjson` | 42 of 44 | yes |
| [ElastAlert](#elastalert) | yaml | `default` | 42 of 44 | yes |
| [OpenSearch Lucene](#opensearch-lucene) | lucene | `default`, `dashboards_ndjson`, `monitor_rule`, `dsl_lucene` | 40 of 44 | no |
| [OpenSearch PPL](#opensearch-ppl) | ppl | `default` | 42 of 44 | yes |
| [Defender XDR (KQL)](#defender-xdr) | kql | `default` | 40 of 44 | no |
| [Sentinel ASIM (KQL)](#sentinel-asim) | kql | `default` | 40 of 44 | no |
| [Azure Monitor (KQL)](#azure-monitor) | kql | `default` | 40 of 44 | no |
| [CrowdStrike LogScale (Falcon)](#crowdstrike-falcon) | logscale | `default` | 40 of 44 | no |
| [CrowdStrike LogScale (FDR)](#crowdstrike-fdr) | logscale | `default` | 40 of 44 | no |
| [SentinelOne Deep Visibility](#sentinelone) | s1ql | `default`, `json` | 40 of 44 | no |
| [SentinelOne PowerQuery](#sentinelone-pq) | powerquery | `default`, `json` | 40 of 44 | no |
| [Cortex XDR (XQL)](#cortex-xdr) | xql | `default`, `json` | 40 of 44 | no |
| [Google SecOps (UDM)](#secops) | udm | `default`, `yara_l` | 40 of 44 | no |
| [Carbon Black Cloud](#carbon-black) | cbc | `default`, `json` | 40 of 44 | no |
| [IBM QRadar AQL](#qradar) | aql | `default` | 32 of 44 | no |
| [Logpoint](#logpoint) | lpql | `default` | 40 of 44 | no |
| [RSA NetWitness](#netwitness) | netwitness | `default` | 40 of 44 | no |
| [Sumo Logic CSE](#sumologic-cse) | json | `default`, `cse_rule` | 40 of 44 | no |
| [Panther (Python)](#panther) | python | `default`, `sdyaml`, `python`, `pantherflow` | 42 of 44 | no |
| [Trellix Helix (TQL)](#trellix-helix) | tql | `default` | 40 of 44 | no |
| [Grafana Loki (LogQL)](#loki) | logql | `default`, `ruler`, `grafana_alerting` | 42 of 44 | yes |
| [Quickwit](#quickwit) | quickwit | `default` | 40 of 44 | no |
| [ClickHouse SQL](#clickhouse) | sql | `default`, `clickdetect` | 42 of 44 | yes |
| [SQLite (Zircolite)](#sqlite) | sql | `default`, `zircolite` | 42 of 44 | yes |
| [SurrealDB (SurrealQL)](#surrealql) | surrealql | `default` | 39 of 44 | no |
| [Wazuh rules (XML)](#wazuh) | xml | `default` | 43 of 44 | yes |

Three backends (IBM QRadar, Trellix Helix and SurrealQL) were built for older pySigma versions. They still convert with pySigma 1.5, so the setup scripts install them from `requirements-legacy.txt` without their old version pins. A few other community backends (Datadog, InsightIDR, QRadar AQL and uberAgent) cannot load on pySigma 1.x and are left out.

To add another target, `pip install` its pySigma backend and add one `Target(...)` line to [`app/core/targets.py`](app/core/targets.py).

## Target guide

Every target below was tested with the working rules of the [sample pack](#sample-pack). "Sample pack" shows how many converted. Rules fail when a platform has no field for them or cannot do a feature (for example `fieldref` or case sensitive matching), and the card in the app tells you why.

### Splunk

<details id="splunk">
<summary><b>Splunk SPL</b>: Splunk Search Processing Language for Windows Event Log and Sysmon data</summary>

| | |
|---|---|
| Target id | `splunk` |
| Engine | pySigma backend `splunk` |
| Pipelines | `sysmon`, `splunk_windows` |
| Formats | `default`, `savedsearches` |
| Sample pack | 42 of 44 converted, 2 skipped |
| Correlations | supported |
| Most common failures | none |

**Tips:** Paste the query in Search, or pick the savedsearches format to get a savedsearches.conf stanza.

Example for `windows/proc_creation_whoami_recon.yml`:

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\whoami.exe" OR OriginalFileName="whoami.exe" CommandLine="* -priv*" OR CommandLine="* /priv*" OR CommandLine="* –priv*" OR CommandLine="* —priv*" OR CommandLine="* ―priv*" OR CommandLine="* -groups*" OR CommandLine="* /groups*" OR CommandLine="* –groups*" OR CommandLine="* —groups*" OR CommandLine="* ―groups*" OR CommandLine="* -all*" OR ...
```

</details>

<details id="splunk-cim">
<summary><b>Splunk CIM</b>: tstats searches over the Common Information Model data models</summary>

| | |
|---|---|
| Target id | `splunk_cim` |
| Engine | pySigma backend `splunk` |
| Pipelines | `splunk_cim` |
| Formats | `default`, `savedsearches`, `data_model` |
| Sample pack | 40 of 44 converted, 0 skipped |
| Correlations | not supported |
| Most common failures | Rule type not yet supported by the Splunk data model CIM pipeline! (4) |

**Tips:** Use the data_model format. Needs accelerated CIM data models such as Endpoint.Processes.

Example for `windows/proc_creation_whoami_recon.yml`:

```spl
| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_path="*\\whoami.exe" OR Processes.original_file_name="whoami.exe" Processes.process="* -priv*" OR Processes.process="* /priv*" OR Processes.process="* –priv*" OR Processes.process="* —priv*" OR Processes.process="* ―priv*" OR Process ...
```

</details>

<details id="splunk-spl2">
<summary><b>Splunk SPL2</b>: Next generation SPL2 syntax for Splunk Cloud and Edge Processor</summary>

| | |
|---|---|
| Target id | `splunk_spl2` |
| Engine | pySigma backend `splunk_spl2` |
| Pipelines | `sysmon`, `splunk_windows` |
| Formats | `default`, `module` |
| Sample pack | 40 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | Splunk SPL2 cannot convert correlation rules. Splunk SPL, Elastic ES\|QL, EQL, ElastAlert, OpenSearch PPL, Graf (2) |

**Tips:** SPL2 starts with FROM main. Change the index name to yours.

Example for `windows/proc_creation_whoami_recon.yml`:

```sql
FROM main WHERE source="WinEventLog:Microsoft-Windows-Sysmon/Operational" AND EventCode=1 AND Image LIKE "%\whoami.exe" OR OriginalFileName="whoami.exe" AND CommandLine LIKE "% -priv%" OR CommandLine LIKE "% /priv%" OR CommandLine LIKE "% –priv%" OR CommandLine LIKE "% —priv%" OR CommandLine LIKE "% ―priv%" OR CommandLine LIKE "% -groups%" OR CommandLine LIKE "% /groups%" OR CommandLine LIKE "% –groups%" OR CommandLi ...
```

</details>

### Elastic

<details id="elastic-lucene">
<summary><b>Elastic Lucene</b>: Kibana query bar and detection rules with Elastic Common Schema (ECS) fields</summary>

| | |
|---|---|
| Target id | `elastic_lucene` |
| Engine | pySigma backend `lucene` |
| Pipelines | `ecs_windows` |
| Formats | `default`, `kibana_ndjson`, `dsl_lucene`, `siem_rule`, `siem_rule_ndjson` |
| Sample pack | 40 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | Elastic Lucene cannot convert correlation rules. Splunk SPL, Elastic ES\|QL, EQL, ElastAlert, OpenSearch PPL, G (2) |

**Tips:** Pick siem_rule_ndjson to import straight into Elastic Security rules.

Example for `windows/proc_creation_whoami_recon.yml`:

```text
(process.executable.caseless:*\\whoami.exe OR process.pe.original_file_name:whoami.exe) AND (process.command_line:(*\ \-priv* OR *\ \/priv* OR *\ –priv* OR *\ —priv* OR *\ ―priv*) OR process.command_line:(*\ \-groups* OR *\ \/groups* OR *\ –groups* OR *\ —groups* OR *\ ―groups*) OR process.command_line:(*\ \-all* OR *\ \/all* OR *\ –all* OR *\ —all* OR *\ ―all*))
```

</details>

<details id="elastic-esql">
<summary><b>Elastic ES|QL</b>: Elasticsearch Query Language with ECS fields, supports correlations</summary>

| | |
|---|---|
| Target id | `elastic_esql` |
| Engine | pySigma backend `esql` |
| Pipelines | `ecs_windows` |
| Formats | `default`, `kibana_ndjson`, `siem_rule`, `siem_rule_ndjson` |
| Sample pack | 42 of 44 converted, 2 skipped |
| Correlations | supported |
| Most common failures | none |

**Tips:** Replace 'from *' with your index pattern, for example logs-*.

Example for `windows/proc_creation_whoami_recon.yml`:

```sql
from * metadata _id, _index, _version | where (ends_with(process.executable.caseless, "\\whoami.exe") or process.pe.original_file_name=="whoami.exe") and (process.command_line like "* -priv*" or process.command_line like "* /priv*" or process.command_line like "* –priv*" or process.command_line like "* —priv*" or process.command_line like "* ―priv*" or process.command_line like "* -groups*" or process.command_line li ...
```

</details>

<details id="elastic-eql">
<summary><b>Elastic EQL</b>: Event Query Language with ECS fields</summary>

| | |
|---|---|
| Target id | `elastic_eql` |
| Engine | pySigma backend `eql` |
| Pipelines | `ecs_windows` |
| Formats | `default`, `eqlapi`, `siem_rule`, `siem_rule_ndjson` |
| Sample pack | 42 of 44 converted, 2 skipped |
| Correlations | supported |
| Most common failures | none |



Example for `windows/proc_creation_whoami_recon.yml`:

```sql
any where (process.executable.caseless:"*\\whoami.exe" or process.pe.original_file_name:"whoami.exe") and (process.command_line like~ ("* -priv*", "* /priv*", "* –priv*", "* —priv*", "* ―priv*") or process.command_line like~ ("* -groups*", "* /groups*", "* –groups*", "* —groups*", "* ―groups*") or process.command_line like~ ("* -all*", "* /all*", "* –all*", "* —all*", "* ―all*"))
```

</details>

<details id="elastalert">
<summary><b>ElastAlert</b>: ElastAlert 2 rule files with ECS fields</summary>

| | |
|---|---|
| Target id | `elastalert` |
| Engine | pySigma backend `elastalert` |
| Pipelines | `ecs_windows` |
| Formats | `default` |
| Sample pack | 42 of 44 converted, 2 skipped |
| Correlations | supported |
| Most common failures | none |

**Tips:** Add index, alert and other required keys to each rule before loading it in ElastAlert 2.

Example for `windows/proc_creation_whoami_recon.yml`:

```yaml
description: Detects whoami used to list privileges or groups, often run right after
  initial access.
filter:
- query:
    query_string:
      query: "(process.executable.caseless:*\\\\whoami.exe OR process.pe.original_file_name:whoami.exe)
        AND (process.command_line:(*\\ \\-priv* OR *\\ \\/priv* OR *\\ \u2013priv*
        OR *\\ \u2014priv* OR *\\ \u2015priv*) OR process.command_line:(*\\ \\-groups* ...
```

</details>

### OpenSearch

<details id="opensearch-lucene">
<summary><b>OpenSearch Lucene</b>: OpenSearch Dashboards queries and monitor rules with ECS fields</summary>

| | |
|---|---|
| Target id | `opensearch_lucene` |
| Engine | pySigma backend `opensearch_lucene` |
| Pipelines | `ecs_windows` |
| Formats | `default`, `dashboards_ndjson`, `monitor_rule`, `dsl_lucene` |
| Sample pack | 40 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | OpenSearch Lucene cannot convert correlation rules. Splunk SPL, Elastic ES\|QL, EQL, ElastAlert, OpenSearch PPL (2) |

**Tips:** Pick monitor_rule to get OpenSearch Alerting monitors.

Example for `windows/proc_creation_whoami_recon.yml`:

```text
(process.executable.caseless:*\\whoami.exe OR process.pe.original_file_name:whoami.exe) AND (process.command_line:(*\ \-priv* OR *\ \/priv* OR *\ –priv* OR *\ —priv* OR *\ ―priv*) OR process.command_line:(*\ \-groups* OR *\ \/groups* OR *\ –groups* OR *\ —groups* OR *\ ―groups*) OR process.command_line:(*\ \-all* OR *\ \/all* OR *\ –all* OR *\ —all* OR *\ ―all*))
```

</details>

<details id="opensearch-ppl">
<summary><b>OpenSearch PPL</b>: OpenSearch Piped Processing Language</summary>

| | |
|---|---|
| Target id | `opensearch_ppl` |
| Engine | pySigma backend `open_search_ppl` |
| Pipelines | built in to the backend |
| Formats | `default` |
| Sample pack | 42 of 44 converted, 2 skipped |
| Correlations | supported |
| Most common failures | none |

**Tips:** The source index is named after the log source, like windows-process_creation-*. Change it to your index.

Example for `windows/proc_creation_whoami_recon.yml`:

```sql
source=windows-process_creation-* | where (LIKE(Image, "%whoami.exe") OR OriginalFileName="whoami.exe") AND (LIKE(CommandLine, "% -priv%") OR LIKE(CommandLine, "% /priv%") OR LIKE(CommandLine, "% –priv%") OR LIKE(CommandLine, "% —priv%") OR LIKE(CommandLine, "% ―priv%") OR LIKE(CommandLine, "% -groups%") OR LIKE(CommandLine, "% /groups%") OR LIKE(CommandLine, "% –groups%") OR LIKE(CommandLine, "% —groups%") OR LIKE(C ...
```

</details>

### Microsoft

<details id="defender-xdr">
<summary><b>Defender XDR (KQL)</b>: Kusto Query Language (KQL) for advanced hunting tables like DeviceProcessEvents</summary>

| | |
|---|---|
| Target id | `defender_xdr` |
| Engine | pySigma backend `kusto` |
| Pipelines | `microsoft_xdr` |
| Formats | `default` |
| Sample pack | 40 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | Unable to determine table name from rule.  The query table is determined in the following order of priority:
  (16); Backend does not support correlation rules. (2); Case-sensitive string matching is not supported by backend. (1) |



Example for `windows/proc_creation_whoami_recon.yml`:

```kql
DeviceProcessEvents
| where (FolderPath endswith "\\whoami.exe" or ProcessVersionInfoOriginalFileName =~ "whoami.exe") and (ProcessCommandLine contains " -priv" or ProcessCommandLine contains " /priv" or ProcessCommandLine contains " –priv" or ProcessCommandLine contains " —priv" or ProcessCommandLine contains " ―priv" or ProcessCommandLine contains " -groups" or ProcessCommandLine contains " /groups" or ProcessComma ...
```

</details>

<details id="sentinel-asim">
<summary><b>Sentinel ASIM (KQL)</b>: KQL over Advanced Security Information Model parsers like imProcessCreate</summary>

| | |
|---|---|
| Target id | `sentinel_asim` |
| Engine | pySigma backend `kusto` |
| Pipelines | `sentinel_asim` |
| Formats | `default` |
| Sample pack | 40 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | Unable to determine table name from rule.  The query table is determined in the following order of priority:
  (16); Backend does not support correlation rules. (2); Invalid SigmaDetectionItem field name encountered: TargetProcessFilename. Invalid SigmaDetectionItem field nam (2) |



Example for `windows/proc_creation_whoami_recon.yml`:

```kql
ERROR Invalid SigmaDetectionItem field name encountered: TargetProcessFilename. Please use valid fields for the imProcessCreate table, or the following fields that have fieldmappings in this pipeline:
ActingProcessCommandLine, ActingProcessCreationTime, ActingProcessFileCompany, ActingProcessFileDescription, ActingProcessFileInternalName, ActingProcessFileOriginalName, ActingProcessFileProduct, ActingProcessFileSize, ...
```

</details>

<details id="azure-monitor">
<summary><b>Azure Monitor (KQL)</b>: KQL for Log Analytics tables like SecurityEvent</summary>

| | |
|---|---|
| Target id | `azure_monitor` |
| Engine | pySigma backend `kusto` |
| Pipelines | `azure_monitor` |
| Formats | `default` |
| Sample pack | 40 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | Unable to determine table name from rule.  The query table is determined in the following order of priority:
  (16); Backend does not support correlation rules. (2); Invalid SigmaDetectionItem field name encountered: OriginalFileName. Invalid SigmaDetectionItem field name enc (2) |



Example for `windows/proc_creation_whoami_recon.yml`:

```kql
ERROR Invalid SigmaDetectionItem field name encountered: OriginalFileName. Please use valid fields for the SecurityEvent table, or the following fields that have fieldmappings in this pipeline:
AccessList, AccessMask, Account, AccountDomain, AccountExpires, AccountName, AccountSessionIdentifier, AccountType, Activity, AdditionalInfo, AdditionalInfo2, AllowedToDelegateTo, Attributes, AuditPolicyChanges, AuditsDiscarde ...
```

</details>

### CrowdStrike

<details id="crowdstrike-falcon">
<summary><b>CrowdStrike LogScale (Falcon)</b>: Falcon LogScale (Humio) queries over Falcon sensor events like ProcessRollup2</summary>

| | |
|---|---|
| Target id | `crowdstrike_falcon` |
| Engine | pySigma backend `log_scale` |
| Pipelines | `crowdstrike_falcon` |
| Formats | `default` |
| Sample pack | 40 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | CrowdStrike LogScale (Falcon) cannot convert correlation rules. Splunk SPL, Elastic ES\|QL, EQL, ElastAlert, Op (2) |

**Tips:** Run it in Falcon Next-Gen SIEM or Event Search. CIDR lists joined with OR are not supported yet.

Example for `windows/proc_creation_whoami_recon.yml`:

```text
event_platform=/^Win$/i #event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i ImageFileName=/\\whoami\.exe$/i or OriginalFilename=/^whoami\.exe$/i CommandLine=/ -priv/i or CommandLine=/ \/priv/i or CommandLine=/ –priv/i or CommandLine=/ —priv/i or CommandLine=/ ―priv/i or CommandLine=/ -groups/i or CommandLine=/ \/groups/i or CommandLine=/ –groups/i or CommandLine=/ —groups/i or Comm ...
```

</details>

<details id="crowdstrike-fdr">
<summary><b>CrowdStrike LogScale (FDR)</b>: LogScale queries over Falcon Data Replicator field names</summary>

| | |
|---|---|
| Target id | `crowdstrike_fdr` |
| Engine | pySigma backend `log_scale` |
| Pipelines | `crowdstrike_fdr` |
| Formats | `default` |
| Sample pack | 40 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | CrowdStrike LogScale (FDR) cannot convert correlation rules. Splunk SPL, Elastic ES\|QL, EQL, ElastAlert, OpenS (2) |



Example for `windows/proc_creation_whoami_recon.yml`:

```text
event_platform=/^Win$/i event_simpleName=/^ProcessRollup2$/i or event_simpleName=/^SyntheticProcessRollup2$/i ImageFileName=/\\whoami\.exe$/i or OriginalFilename=/^whoami\.exe$/i CommandLine=/ -priv/i or CommandLine=/ \/priv/i or CommandLine=/ –priv/i or CommandLine=/ —priv/i or CommandLine=/ ―priv/i or CommandLine=/ -groups/i or CommandLine=/ \/groups/i or CommandLine=/ –groups/i or CommandLine=/ —groups/i or Comman ...
```

</details>

### SentinelOne

<details id="sentinelone">
<summary><b>SentinelOne Deep Visibility</b>: SentinelOne Deep Visibility queries (S1QL)</summary>

| | |
|---|---|
| Target id | `sentinelone` |
| Engine | pySigma backend `sentinel_one` |
| Pipelines | built in to the backend |
| Formats | `default`, `json` |
| Sample pack | 40 of 44 converted, 0 skipped |
| Correlations | not supported |
| Most common failures | Invalid SigmaDetectionItem field name encountered: EventID. Invalid SigmaDetectionItem field name encountered: (4) |

**Tips:** Only Windows, Linux and macOS endpoint log sources are mapped.

Example for `windows/proc_creation_whoami_recon.yml`:

```text
ERROR Invalid SigmaDetectionItem field name encountered: OriginalFileName. Invalid SigmaDetectionItem field name encountered: EventID. Invalid SigmaDetectionItem field name encountered: Provider_Name. Invalid SigmaDetectionItem field name encountered: EventID. Invalid SigmaDetectionItem field name encountered: EventID. Invalid SigmaDetectionItem field name encountered: ScriptBlockText. Invalid SigmaDetectionItem fiel ...
```

</details>

<details id="sentinelone-pq">
<summary><b>SentinelOne PowerQuery</b>: SentinelOne Singularity Data Lake PowerQuery</summary>

| | |
|---|---|
| Target id | `sentinelone_pq` |
| Engine | pySigma backend `sentinel_one_pq` |
| Pipelines | built in to the backend |
| Formats | `default`, `json` |
| Sample pack | 40 of 44 converted, 0 skipped |
| Correlations | not supported |
| Most common failures | Invalid SigmaDetectionItem field name encountered: EventID. Invalid SigmaDetectionItem field name encountered: (4) |



Example for `windows/proc_creation_whoami_recon.yml`:

```text
ERROR Invalid SigmaDetectionItem field name encountered: OriginalFileName. Invalid SigmaDetectionItem field name encountered: EventID. Invalid SigmaDetectionItem field name encountered: Provider_Name. Invalid SigmaDetectionItem field name encountered: EventID. Invalid SigmaDetectionItem field name encountered: EventID. Invalid SigmaDetectionItem field name encountered: ScriptBlockText. Invalid SigmaDetectionItem fiel ...
```

</details>

### Palo Alto

<details id="cortex-xdr">
<summary><b>Cortex XDR (XQL)</b>: Palo Alto Networks Cortex XDR Query Language over xdr_data</summary>

| | |
|---|---|
| Target id | `cortex_xdr` |
| Engine | pySigma backend `cortex_xdr` |
| Pipelines | built in to the backend |
| Formats | `default`, `json` |
| Sample pack | 40 of 44 converted, 0 skipped |
| Correlations | not supported |
| Most common failures | Rule type not yet supported by the Cortex XDR Sigma backend (4) |

**Tips:** Only endpoint log sources are mapped. Network and cloud rules show an error.

Example for `windows/proc_creation_whoami_recon.yml`:

```text
ERROR Invalid SigmaDetectionItem field name encountered: OriginalFileName. Invalid SigmaDetectionItem field name encountered: OriginalFileName. Invalid SigmaDetectionItem field name encountered: OriginalFileName. Invalid SigmaDetectionItem field name encountered: None. Invalid SigmaDetectionItem field name encountered: OriginalFileName. This pipeline only supports the following fields for process activity:
{User}, {C ...
```

</details>

### Google

<details id="secops">
<summary><b>Google SecOps (UDM)</b>: Google Security Operations (Chronicle) Unified Data Model search</summary>

| | |
|---|---|
| Target id | `secops` |
| Engine | pySigma backend `secops` |
| Pipelines | `secops_udm` |
| Formats | `default`, `yara_l` |
| Sample pack | 40 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | Google SecOps (UDM) cannot convert correlation rules. Splunk SPL, Elastic ES\|QL, EQL, ElastAlert, OpenSearch P (2) |

**Tips:** Pick the yara_l format to get YARA-L 2.0 detection rules.

Example for `windows/proc_creation_whoami_recon.yml`:

```text
(metadata.event_type = "PROCESS_LAUNCH") AND ((target.process.file.full_path = /\\whoami\.exe$/ nocase OR target.process.file.names = "whoami.exe" nocase) AND (target.process.command_line = / -priv/ nocase OR target.process.command_line = / \/priv/ nocase OR target.process.command_line = / –priv/ nocase OR target.process.command_line = / —priv/ nocase OR target.process.command_line = / ―priv/ nocase OR target.process ...
```

</details>

### Broadcom

<details id="carbon-black">
<summary><b>Carbon Black Cloud</b>: Carbon Black Cloud Enterprise EDR process search</summary>

| | |
|---|---|
| Target id | `carbon_black` |
| Engine | pySigma backend `carbon_black` |
| Pipelines | `carbonblack` |
| Formats | `default`, `json` |
| Sample pack | 40 of 44 converted, 0 skipped |
| Correlations | not supported |
| Most common failures | Invalid SigmaDetectionItem field name encountered: EventID. Invalid SigmaDetectionItem field name encountered: (2); Invalid SigmaDetectionItem field name encountered: EventID. The supported fields are: {CommandLine}, {Company} (2) |



Example for `windows/proc_creation_whoami_recon.yml`:

```text
device_os:WINDOWS ((process_name:\\whoami.exe OR process_original_filename:whoami.exe) (process_cmdline:\ \-priv* OR process_cmdline:\ \/priv* OR process_cmdline:\ –priv* OR process_cmdline:\ —priv* OR process_cmdline:\ ―priv* OR process_cmdline:\ \-groups* OR process_cmdline:\ \/groups* OR process_cmdline:\ –groups* OR process_cmdline:\ —groups* OR process_cmdline:\ ―groups* OR process_cmdline:\ \-all* OR process_cm ...
```

</details>

### IBM

<details id="qradar">
<summary><b>IBM QRadar AQL</b>: Ariel Query Language (AQL) searches for QRadar</summary>

| | |
|---|---|
| Target id | `qradar` |
| Engine | pySigma backend `qradar` |
| Pipelines | built in to the backend |
| Formats | `default` |
| Sample pack | 32 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | The QRadar savedsearches Sigma backend supports only the following fields for process_creation log source (8); IBM QRadar AQL cannot convert correlation rules. Splunk SPL, Elastic ES\|QL, EQL, ElastAlert, OpenSearch PPL, G (2) |

**Tips:** Uses the legacy QRadar backend (installed from requirements-legacy.txt). Field names follow QRadar default properties.

Example for `windows/proc_creation_whoami_recon.yml`:

```sql
SELECT UTF8(payload) as search_payload from events where ("Image" ILIKE '%\whoami.exe' OR "ImageName"='whoami.exe') AND ("Process CommandLine" ILIKE '% -priv%' OR "Process CommandLine" ILIKE '% /priv%' OR "Process CommandLine" ILIKE '% –priv%' OR "Process CommandLine" ILIKE '% —priv%' OR "Process CommandLine" ILIKE '% ―priv%' OR "Process CommandLine" ILIKE '% -groups%' OR "Process CommandLine" ILIKE '% /groups%' OR " ...
```

</details>

### Logpoint

<details id="logpoint">
<summary><b>Logpoint</b>: Logpoint Query Language with Logpoint Windows taxonomy</summary>

| | |
|---|---|
| Target id | `logpoint` |
| Engine | pySigma backend `logpoint` |
| Pipelines | `logpoint_windows` |
| Formats | `default` |
| Sample pack | 40 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | Logpoint cannot convert correlation rules. Splunk SPL, Elastic ES\|QL, EQL, ElastAlert, OpenSearch PPL, Grafana (2) |



Example for `windows/proc_creation_whoami_recon.yml`:

```text
label="Create" label="Process" "process"="*\whoami.exe" OR file="whoami.exe" command="* -priv*" OR command="* /priv*" OR command="* –priv*" OR command="* —priv*" OR command="* ―priv*" OR command="* -groups*" OR command="* /groups*" OR command="* –groups*" OR command="* —groups*" OR command="* ―groups*" OR command="* -all*" OR command="* /all*" OR command="* –all*" OR command="* —all*" OR command="* ―all*"
```

</details>

### RSA

<details id="netwitness">
<summary><b>RSA NetWitness</b>: NetWitness query syntax for Windows log sources</summary>

| | |
|---|---|
| Target id | `netwitness` |
| Engine | pySigma backend `net_witness` |
| Pipelines | `netwitness_windows` |
| Formats | `default` |
| Sample pack | 40 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | RSA NetWitness cannot convert correlation rules. Splunk SPL, Elastic ES\|QL, EQL, ElastAlert, OpenSearch PPL, G (2) |



Example for `windows/proc_creation_whoami_recon.yml`:

```text
device.type = 'windows' && (reference.id = '4688' && ((process ends '\whoami.exe' || OriginalFileName = 'whoami.exe') && (param contains ' -priv',' /priv',' –priv',' —priv',' ―priv',' -groups',' /groups',' –groups',' —groups',' ―groups',' -all',' /all',' –all',' —all',' ―all')))
```

</details>

### Sumo Logic

<details id="sumologic-cse">
<summary><b>Sumo Logic CSE</b>: Sumo Logic Cloud SIEM rule JSON</summary>

| | |
|---|---|
| Target id | `sumologic_cse` |
| Engine | pySigma backend `sumologic_cse` |
| Pipelines | `sumologic_cse` |
| Formats | `default`, `cse_rule` |
| Sample pack | 40 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | Backend does not support correlation rules. (2); Conversion failed: Unbound value expressions (keywords) are not supported.

Unsupported Sigma pattern:
  detec (1); Case-sensitive string matching is not supported by backend. (1) |

**Tips:** Import the JSON with the Cloud SIEM API. Keyword only rules are not supported.

Example for `windows/proc_creation_whoami_recon.yml`:

```json
{
    "content_type": "RULE",
    "enabled": true,
    "is_prototype": false,
    "name": "Whoami With Privilege Or Group Flags",
    "name_expression": "Whoami With Privilege Or Group Flags",
    "rule_source": "user",
    "summary_expression": "",
    "pattern_type": "templated_match",
    "stream": "record",
    "description_expression": "Detects whoami used to list privileges or groups, often run right after init ...
```

</details>

### Panther

<details id="panther">
<summary><b>Panther (Python)</b>: Panther detections as Python rule functions</summary>

| | |
|---|---|
| Target id | `panther` |
| Engine | pySigma backend `panther` |
| Pipelines | built in to the backend |
| Formats | `default`, `sdyaml`, `python`, `pantherflow` |
| Sample pack | 42 of 44 converted, 0 skipped |
| Correlations | not supported |
| Most common failures | Panther (Python) cannot convert correlation rules. Splunk SPL, Elastic ES\|QL, EQL, ElastAlert, OpenSearch PPL, (2) |

**Tips:** Pick sdyaml for Panther simple detections or pantherflow for PantherFlow queries.

Example for `windows/proc_creation_whoami_recon.yml`:

```python
def rule(event):
    if all(
        [
            any(
                [
                    event.deep_get("Image", default="").endswith("\\whoami.exe"),
                    event.deep_get("OriginalFileName", default="") == "whoami.exe",
                ]
            ),
            any(
                [
                    any(
                        [
                            " -priv" in event.deep_get("Comma ...
```

</details>

### Trellix

<details id="trellix-helix">
<summary><b>Trellix Helix (TQL)</b>: Trellix Helix Query Language</summary>

| | |
|---|---|
| Target id | `trellix_helix` |
| Engine | pySigma backend `tql` |
| Pipelines | built in to the backend |
| Formats | `default` |
| Sample pack | 40 of 44 converted, 0 skipped |
| Correlations | not supported |
| Most common failures | Rule type not yet supported by the Helix Sigma backend (6); Invalid fieldname encounter: eventSource.This pipeline only supports the following fields:
{AccountDomain}, {A (1); Invalid fieldname encounter: ResultType.Invalid fieldname encounter: eventSource.This pipeline only supports t (1) |

**Tips:** Uses a legacy backend (requirements-legacy.txt). Only a set of Helix fields is mapped.

Example for `windows/proc_creation_whoami_recon.yml`:

```text
(category : ["process create (rule: processcreate)","process creation"]) AND (metaclass:"windows" AND ((process:"*\\whoami.exe" OR original_file_name:"whoami.exe") AND (args : " -priv" OR args : " /priv" OR args : " –priv" OR args : " —priv" OR args : " ―priv" OR args : " -groups" OR args : " /groups" OR args : " –groups" OR args : " —groups" OR args : " ―groups" OR args : " -all" OR args : " /all" OR args : " –all" ...
```

</details>

### Grafana

<details id="loki">
<summary><b>Grafana Loki (LogQL)</b>: LogQL queries for Grafana Loki</summary>

| | |
|---|---|
| Target id | `loki` |
| Engine | pySigma backend `loki` |
| Pipelines | built in to the backend |
| Formats | `default`, `ruler`, `grafana_alerting` |
| Sample pack | 42 of 44 converted, 2 skipped |
| Correlations | supported |
| Most common failures | none |

**Tips:** Pick ruler to get Loki ruler alert files. Change the stream selector to your labels.

Example for `windows/proc_creation_whoami_recon.yml`:

```text
{job=~"eventlog|winlog|windows|fluentbit.*"} | json | (Image=~`(?i).*\\whoami\.exe$` or OriginalFileName=~`(?i)^whoami\.exe$`) and (CommandLine=~`(?i).*\ \-priv.*` or CommandLine=~`(?i).*\ /priv.*` or CommandLine=~`(?i).*\ –priv.*` or CommandLine=~`(?i).*\ —priv.*` or CommandLine=~`(?i).*\ ―priv.*` or CommandLine=~`(?i).*\ \-groups.*` or CommandLine=~`(?i).*\ /groups.*` or CommandLine=~`(?i).*\ –groups.*` or CommandL ...
```

</details>

### Quickwit

<details id="quickwit">
<summary><b>Quickwit</b>: Quickwit search queries</summary>

| | |
|---|---|
| Target id | `quickwit` |
| Engine | pySigma backend `quickwit` |
| Pipelines | `quickwit_windows` |
| Formats | `default` |
| Sample pack | 40 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | Quickwit cannot convert correlation rules. Splunk SPL, Elastic ES\|QL, EQL, ElastAlert, OpenSearch PPL, Grafana (2) |



Example for `windows/proc_creation_whoami_recon.yml`:

```text
EventID:1 AND Image:"*\\whoami.exe" OR OriginalFileName:"whoami.exe" AND CommandLine:"* -priv*" OR CommandLine:"* /priv*" OR CommandLine:"* –priv*" OR CommandLine:"* —priv*" OR CommandLine:"* ―priv*" OR CommandLine:"* -groups*" OR CommandLine:"* /groups*" OR CommandLine:"* –groups*" OR CommandLine:"* —groups*" OR CommandLine:"* ―groups*" OR CommandLine:"* -all*" OR CommandLine:"* /all*" OR CommandLine:"* –all*" OR Co ...
```

</details>

### Databases

<details id="clickhouse">
<summary><b>ClickHouse SQL</b>: SQL for logs stored in ClickHouse</summary>

| | |
|---|---|
| Target id | `clickhouse` |
| Engine | pySigma backend `clickhouse` |
| Pipelines | built in to the backend |
| Formats | `default`, `clickdetect` |
| Sample pack | 42 of 44 converted, 2 skipped |
| Correlations | supported |
| Most common failures | none |

**Tips:** The table is named logs. Change it to your table.

Example for `windows/proc_creation_whoami_recon.yml`:

```sql
SELECT * FROM logs WHERE (Image ILIKE '%\\\\whoami.exe' OR OriginalFileName='whoami.exe') AND (CommandLine ILIKE '% -priv%' OR CommandLine ILIKE '% /priv%' OR CommandLine ILIKE '% –priv%' OR CommandLine ILIKE '% —priv%' OR CommandLine ILIKE '% ―priv%' OR CommandLine ILIKE '% -groups%' OR CommandLine ILIKE '% /groups%' OR CommandLine ILIKE '% –groups%' OR CommandLine ILIKE '% —groups%' OR CommandLine ILIKE '% ―groups% ...
```

</details>

<details id="sqlite">
<summary><b>SQLite (Zircolite)</b>: SQLite queries, and Zircolite rule packs for offline EVTX hunting</summary>

| | |
|---|---|
| Target id | `sqlite` |
| Engine | pySigma backend `sqlite` |
| Pipelines | built in to the backend |
| Formats | `default`, `zircolite` |
| Sample pack | 42 of 44 converted, 2 skipped |
| Correlations | supported |
| Most common failures | none |

**Tips:** Pick the zircolite format to build a rule pack for Zircolite.

Example for `windows/proc_creation_whoami_recon.yml`:

```sql
SELECT * FROM logs WHERE (Image LIKE '%\\whoami.exe' ESCAPE '\' OR OriginalFileName='whoami.exe') AND (CommandLine LIKE '% -priv%' ESCAPE '\' OR CommandLine LIKE '% /priv%' ESCAPE '\' OR CommandLine LIKE '% –priv%' ESCAPE '\' OR CommandLine LIKE '% —priv%' ESCAPE '\' OR CommandLine LIKE '% ―priv%' ESCAPE '\' OR CommandLine LIKE '% -groups%' ESCAPE '\' OR CommandLine LIKE '% /groups%' ESCAPE '\' OR CommandLine LIKE '% ...
```

</details>

<details id="surrealql">
<summary><b>SurrealDB (SurrealQL)</b>: SurrealQL queries for SurrealDB</summary>

| | |
|---|---|
| Target id | `surrealql` |
| Engine | pySigma backend `surreal_ql` |
| Pipelines | built in to the backend |
| Formats | `default` |
| Sample pack | 39 of 44 converted, 2 skipped |
| Correlations | not supported |
| Most common failures | SurrealDB (SurrealQL) cannot convert correlation rules. Splunk SPL, Elastic ES\|QL, EQL, ElastAlert, OpenSearch (2); Case-sensitive string matching is not supported by backend. (1) |

**Tips:** Replace <TABLE_NAME> with your table. Uses a legacy backend (requirements-legacy.txt).

Example for `windows/proc_creation_whoami_recon.yml`:

```sql
SELECT * FROM <TABLE_NAME> WHERE ((Image IS NOT NONE AND string::ends_with(Image,'\\whoami.exe')) OR OriginalFileName='whoami.exe') AND ((CommandLine IS NOT NONE AND string::contains(CommandLine,' -priv')) OR (CommandLine IS NOT NONE AND string::contains(CommandLine,' /priv')) OR (CommandLine IS NOT NONE AND string::contains(CommandLine,' –priv')) OR (CommandLine IS NOT NONE AND string::contains(CommandLine,' —priv') ...
```

</details>

### Wazuh

<details id="wazuh">
<summary><b>Wazuh rules (XML)</b>: Wazuh XML rules for Windows eventchannel and Sysmon data</summary>

| | |
|---|---|
| Target id | `wazuh` |
| Engine | Sigma Forge Wazuh backend |
| Pipelines | built in to the backend |
| Formats | `default` |
| Sample pack | 43 of 44 converted, 0 skipped |
| Correlations | supported |
| Most common failures | Wazuh only supports event_count correlations, not value_count (1) |



Example for `windows/proc_creation_whoami_recon.yml`:

```xml
<group name="sigma,">
  <rule id="100100" level="3">
    <if_group>sysmon</if_group>
    <field name="win.system.eventID" type="pcre2">(?s)^1$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?is)(?:(?: -priv| /priv| –priv| —priv| ―priv)|(?: -groups| /groups| –groups| —groups| ―groups)|(?: -all| /all| –all| —all| ―all))</field>
    <field name="win.eventdata.image" type="pcre2">(?is)\\\\whoami\.exe$< ...
```


#### How the Wazuh backend works

There is no maintained pySigma backend for Wazuh, so Sigma Forge ships its own in [`app/core/wazuh`](app/core/wazuh). It reads the condition tree that pySigma builds and writes Wazuh XML rules.

```mermaid
flowchart TD
    A[Sigma rule] --> B[pySigma parser<br/>condition tree]
    B --> C[Push NOT down<br/>to single values]
    C --> D[Merge OR on the same field<br/>into one regex]
    D --> E[Expand into AND groups<br/>one Wazuh rule each]
    E --> F[Group values by field<br/>build pcre2 regex]
    F --> G[Add parent group, channel,<br/>event id and MITRE ids]
    G --> H[Wazuh XML rule group]
```

**Field mapping.** For Windows rules, Sysmon and Security fields become Wazuh eventchannel fields: `Image` becomes `win.eventdata.image`, `CommandLine` becomes `win.eventdata.commandLine`, and `EventID` becomes `win.system.eventID`. System fields such as `Channel`, `Provider_Name` and `Computer` map to `win.system.*`.

**Parent and event filter.** The log source decides the parent and extra filters:

| Sigma log source | Wazuh rule gets |
|---|---|
| `category: process_creation` (and other Sysmon categories) | `<if_group>sysmon</if_group>` and the Sysmon event id, for example `1` |
| `category: ps_script` / `ps_module` | `<if_group>windows</if_group>`, the PowerShell channel and event `4104` / `4103` |
| `service: security`, `system`, `powershell` and more | `<if_group>windows</if_group>` and the channel name |
| Other products (Linux and so on) | No parent. Field names stay as they are and a warning is shown |

**Logic.** Wazuh rules are a list of conditions that must all match, so Sigma logic is rewritten:

* Values joined by OR on the same field become one regex such as `(?:\\powershell\.exe|\\pwsh\.exe)$`.
* OR across different fields becomes several Wazuh rules with the same description. The split is capped (default 64) so a rule never explodes.
* AND on the same field, such as `contains|all`, becomes one regex with lookaheads.
* NOT becomes `negate="yes"` or a negative lookahead.
* Matching is case insensitive like Sigma, unless the rule uses the `cased` modifier.

**Example output** for the sample rule `dns_query_tunnel_tools.yml`

```xml
<group name="sigma,">
  <rule id="100100" level="8">
    <if_group>sysmon</if_group>
    <field name="win.system.eventID" type="pcre2">(?s)^22$</field>
    <field name="win.eventdata.queryName" type="pcre2">(?is)(?:\.ngrok\.io|\.ngrok-free\.app|\.trycloudflare\.com|\.loca\.lt)$</field>
    <description>Sigma: DNS Query For Known Tunneling Service Domains</description>
    <info type="text">Sigma rule id 6f708192-a3b4-4c5d-9e6f-708192a3b4c5</info>
    <mitre>
      <id>T1572</id>
    </mitre>
    <group>sigma,sigma_medium,</group>
  </rule>
</group>
```

**Options** (on the Convert page or in the API):

| Option | Default | Why |
|---|---|---|
| First rule id | `100100` | Custom Wazuh rules should use ids from 100000 up |
| Match doubled backslashes | on | Wazuh eventchannel fields keep Windows paths with escaped backslashes (`C:\\Windows`). Turn it off if your decoder gives single backslashes |
| Add if_group parent | on | Ties the rule to the Sysmon or Windows rule tree |

Sigma levels map to Wazuh levels like this: informational 3, low 5, medium 8, high 12, critical 15.

**Install the rules.** Download the `.xml` from the Convert page, copy it to `/var/ossec/etc/rules/` on the manager, and restart it:

```bash
sudo cp sigma-forge_wazuh.xml /var/ossec/etc/rules/sigma_forge_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/sigma_forge_rules.xml
sudo systemctl restart wazuh-manager
```

#### Correlations in Wazuh

For Wazuh, every converted rule gets a group like `sigma_ref_<name>`. The correlation becomes a rule with `frequency`, `timeframe`, `<if_matched_group>` and `<same_field>` for each `group-by` field:

```xml
<rule id="100101" level="12" frequency="10" timeframe="300">
  <if_matched_group>sigma_ref_sf_failed_logon</if_matched_group>
  <same_field>win.eventdata.ipAddress</same_field>
  <description>Sigma correlation: Brute Force From One Source Address</description>
</rule>
```

#### Test the rules on a real manager

[`tools/wazuh_check.py`](tools/wazuh_check.py) uploads the rules through the Wazuh API (Application Programming Interface), restarts the manager and runs test events through the `logtest` endpoint.

```bash
.venv/bin/python tools/wazuh_check.py \
  --url https://WAZUH_MANAGER:55000 \
  --user wazuh --password 'YOUR_PASSWORD' \
  --rules sigma-forge_wazuh.xml \
  --events sample/wazuh/events.jsonl \
  --insecure
```

On Windows use `.venv\Scripts\python.exe` instead. The password can also come from the `WAZUH_API_PASSWORD` variable. Use `--insecure` only for lab managers with self signed certificates.

Each line of the events file is one test:

```json
{"name": "Certutil download", "expect": "Certutil Used To Download A File", "event": {"win": {"system": {"eventID": "1"}, "eventdata": {"image": "C:\\Windows\\System32\\certutil.exe"}}}}
```

`expect` can be a rule id (`100104`), part of the rule title, or `none` for events that must not fire a Sigma rule. The tool prints PASS or FAIL for each line and exits with code 1 if any test fails, so you can use it in a pipeline.

</details>

## Automatic fallbacks

Many platforms cannot do every Sigma feature, or have no field mapping for some log sources. Instead of failing, Sigma Forge tries again with the closest thing the platform can do, and puts a note on the rule's card so you know what changed:

| Problem | What Sigma Forge does |
|---|---|
| No field or table mapping for the log source | Converts with the original Sigma field names, so you only need to rename fields |
| `cased` not supported | Drops it, so the query matches any case |
| CIDR lists not supported | Turns each range into an IP prefix match |
| Keyword (full text) search not supported | Matches the words against a `message` field |
| `exists` or `null` not supported | Uses a match on any value, or on an empty string |
| Number values break the backend | Sends them as text |
| No Splunk CIM data model for the log source | Falls back to a plain SPL search |

Rules that still fail show the reason on their card. Most of these are platform limits, like QRadar's field list for some log sources.

## Correlation rules

Sigma correlation rules join events from other rules, like "ten failed logons from one address in five minutes". Sigma Forge reads them from the same file as the rules they use.

| Target | Correlation support |
|---|---|
| Splunk SPL | Supported (tested with `event_count` and `value_count`) |
| Elastic ES\|QL | Supported (tested with `event_count` and `value_count`) |
| Elastic EQL | Supported (tested with `event_count` and `value_count`) |
| ElastAlert | Supported (tested with `event_count` and `value_count`) |
| OpenSearch PPL | Supported (tested with `event_count` and `value_count`) |
| Grafana Loki (LogQL) | Supported (tested with `event_count` and `value_count`) |
| ClickHouse SQL | Supported (tested with `event_count` and `value_count`) |
| SQLite (Zircolite) | Supported (tested with `event_count` and `value_count`) |
| Wazuh | `event_count` with `gte` or `gt`, as a `frequency` rule |
| Others | Not supported by their backend. The card shows the reason |

A base rule that is only used by a correlation has no query of its own, so it is shown as **skipped**. Add `generate: true` to the base rule if you also want it alone.

## ATT&CK coverage

The ATT&CK Enterprise data lives in [`data/attack/attack.json`](data/attack/attack.json), a small file (about 130 KB) built from the official [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data). It is included in the repo, so coverage works offline.

Refresh it at any time:

```bash
./setup.sh --update-attack                 # Linux and macOS
.\setup.ps1 -UpdateAttack                  # Windows
.venv/bin/python tools/fetch_attack.py     # direct
```

How tags are read:

* `attack.t1059.001` counts for T1059.001, and rolls up to T1059 on the heat map.
* `attack.execution` style tags count per tactic.
* Revoked techniques are moved to their new id. For example, ATT&CK v20 replaced `T1562.001` with `T1685`. The rule gets a finding and the coverage counts the new id.
* Tags that do not exist at all are listed as unknown.

Below the map, **Coverage by log source** lists every log source your rules use, with rule counts, techniques and levels. When the SigmaHQ library is synced, **Biggest gaps** shows the techniques SigmaHQ covers and you do not, ranked by how many community rules exist for them, and the log sources that would close the most gaps. Click one to open those rules in the library. The technique drawer also lists SigmaHQ rules for that technique with an **Add** button.

## Threat groups, log readiness and reports

The Coverage page has three more tools next to the search box.

* **Threat group.** Pick one of the 174 groups in ATT&CK. A card shows how much of what the group uses you cover (covered, partial when only the parent or another sub technique has a rule, missing), and the missing techniques to write rules for first. On the map, the group's techniques get a green, yellow or red border and the rest fade out. Group data comes from the same STIX file as the matrix and is stored in [`data/attack/groups.json`](data/attack/groups.json).
* **Log readiness.** Tick the log sources your SIEM really receives. The map then counts only rules whose log source you collect, so it shows what you can detect today. Techniques that are covered on paper but whose logs you do not collect are marked **blind** (a striped yellow border), and the drawer lists the log sources to start collecting. Your choice is kept in the browser.
* **Report.** Downloads one standalone HTML file: KPIs, coverage per tactic, readiness, the chosen threat group, the biggest SigmaHQ gaps and every rule with its quality grade. Open it in any browser and print to PDF.

Each technique drawer also lists the [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests for that technique and its sub techniques, from a local index in [`data/atomic/atomics.json`](data/atomic/atomics.json). Run them on a lab machine, collect the logs, and drop them on the Test page to prove your rules fire. Refresh the index with `tools/fetch_atomic.py`.

## Testing rules on logs

The Test page runs your rules on real events without a SIEM:

```mermaid
flowchart LR
    F[EVTX, JSON, JSON lines] --> P[Parse and flatten<br/>EventData, nested keys]
    P --> L[Detect log source<br/>channel and event id]
    L --> DB[(SQLite in memory)]
    R[Your rules] --> C[Convert to SQLite<br/>with fallbacks]
    C --> Q[Run each query<br/>with a time limit]
    DB --> Q
    Q --> H[Hits, alerts and<br/>matching events]
```

* **Formats.** `.evtx` files are read with the [evtx](https://github.com/omerbenamram/pyevtx-rs) parser. JSON can be one object, an array, an object with `events`, `records`, `logs` or `Records` (CloudTrail), an Elasticsearch `hits` answer, or one event per line. Wazuh `win.*` events and Elastic `_source` wrappers are unwrapped.
* **Fields.** Nested keys are flattened to their last name (`EventData.CommandLine` becomes `CommandLine`) and also kept with their full dotted path (`userIdentity.arn`), so both Windows and cloud rules find their fields. Field names are matched without case. The raw event is kept in a `message` column for keyword searches.
* **Log sources.** For Windows events the channel and event id give the product, service and category (Sysmon event 1 is `process_creation`, PowerShell 4104 is `ps_script` and so on). Other logs can carry a `logsource` object. Three modes decide how strict this is: **auto** only filters events whose log source is known, **strict** always filters, **off** runs every rule on every event.
* **Correlations** run as real SQLite window queries over the event `timestamp`, and each alert shows its group, window and count.
* Limits: 64 MB and 250,000 events per run, and 10 seconds per query. See [configuration](#configuration).

## Noise check and filters

A rule that fires 500 times a day is as useless as a rule that never fires. Load a normal week of logs (the **Load baseline week** button loads a sample week of Sysmon events with known noise from an inventory agent and Google Update) and run the test.

* Each rule that fired gets a level: **quiet** (2 hits or fewer), **busy**, or **noisy** (50 or more per 1000 events, or 20 hits or more). A **Noisy** tab lists them.
* **Details** shows the top values of the rule's fields and of context fields like `ParentImage`, `User` and `Computer`, plus the most common path ending.
* When one value explains most hits and is not already in the rule, it becomes a **suggested filter**. **Add filter, open in editor** adds a `filter_sf_noise` block, changes the condition to `(old) and not filter_sf_noise`, adds a false positive note, and opens the rule in the editor so you can check and save it.

**Generate test events** on the Test page reads the detection logic of the selected rules and builds events that should match each one, with the right log source, field values that satisfy every modifier (`contains`, `startswith`, `endswith`, `re`, `cidr`, numbers) and values that avoid every `not` filter. Correlation rules get enough events in one group and time window. It is a quick way to check that a rule does what you think, and the GitHub Action uses it to fail a pull request when a rule can never fire.

## Building rules: from a query, from an event

**From a query.** In the editor, **From query or event** takes a search you already have and turns it into a Sigma rule:

| Language | Example |
|---|---|
| Splunk SPL | `index=win EventCode=1 Image="*\\certutil.exe" (CommandLine="*urlcache*" OR CommandLine="*-decode*") \| stats count` |
| Sentinel or Defender KQL | `DeviceProcessEvents \| where FileName in~ ("rundll32.exe") and ProcessCommandLine contains "http"` |
| Kibana or Lucene | `event.code:1 AND process.name:("mshta.exe" OR "wscript.exe") AND NOT user.name:SYSTEM` |
| Elastic EQL | `process where process.name : "vssadmin.exe" and process.args : ("delete", "shadows")` |
| Elastic ES\|QL | `FROM logs-* \| WHERE process.executable LIKE "*\\schtasks.exe"` |

The language is detected for you. Filters with `AND`, `OR`, `NOT`, brackets, wildcards, `in`, `contains`, `has`, `startswith`, `endswith`, `like`, regex, number compares and null checks are read. Common field names from ECS, Splunk CIM, Sentinel and Defender are mapped back to Sigma names (`process.command_line` and `ProcessCommandLine` become `CommandLine`, `process.name` becomes `Image|endswith`), and the log source is guessed from the table, the index, the event id or the fields. Steps that do not filter (`stats`, `table`, `project`) are skipped with a note. The result is checked with pySigma before you see it. From the command line: `sigma-forge from-query 'your query'`.

**From an event.** On the Test page, every matching event has **Make a rule from this event**. In the editor you can also paste one event as JSON. You pick the fields that make the event stand out. Paths become `endswith` on the file name, long command lines become `contains|all` of the most telling parts, numbers stay exact.

## Rule quality score and version history

Every rule gets a quality score from 0 to 100:

| Check | Points |
|---|---|
| ATT&CK technique tag | 14 |
| Description of 40 or more characters | 12 |
| No medium or higher findings from the validators | 12 |
| At least one reference | 10 |
| Real false positives (not just "Unknown") | 10 |
| Title of 10 or more characters | 8 |
| Filters out known noise (a `not` in the condition) | 8 |
| Valid UUID id, level, status test or stable | 6 each |
| Author, date | 4 each |

Grades: A at 85 and up, B at 70, C at 55, D at 40, F below. The grade shows in the Rules table (sortable and filterable), the rule drawer, the editor checks, the workspace overview and the coverage report. `sigma-forge validate --min-quality 70` fails a CI run when a rule scores lower.

**Version history.** Every time you save in the editor (Ctrl+S or **Save to workspace**), the file's content is kept as a version, up to 30 per file name, in your browser. **History** lists them with a count of added and removed lines, shows a line diff against what is in the editor, and restores any version. Restoring keeps the current text as a version too, so nothing is lost.

## Hunt: scan this machine

The Hunt page scans the computer Sigma Forge is running on. Scans only run when the browser is on the same machine as the server (set `SIGMA_FORGE_ALLOW_REMOTE_HUNT=1` to allow other machines).

* **Live event logs** (Windows). Pick the logs (Sysmon, Security, System, PowerShell, Defender, Task Scheduler, WMI, BITS, DNS client, Code Integrity, Firewall, RDP sessions), a time range and a limit. Sigma Forge reads them with `wevtutil`, turns each event into fields, and runs your Sigma rules on them with the same engine and noise check as the Test page. The Security log needs Sigma Forge to run as administrator. Sysmon gives the best results. Without it, turn on process creation auditing (event 4688) with command lines.
* **Upload .evtx.** Export a log on any Windows machine (`wevtutil epl Security C:\Temp\Security.evtx`) and drop it here. Works on every platform.
* **YARA folder scan.** Paste folders or files, one per line (environment variables like `%TEMP%` work), pick a size limit and optional extensions, and scan them with all your YARA rules. Matches open a drawer with the strings that hit.

From the command line: `sigma-forge hunt rules/ --channels sysmon security --hours 24` and `sigma-forge yara yara_rules/ --scan C:\Users\Public`.

> Live event logs need Sigma Forge to run directly on Windows, not in Docker. On Linux and macOS use **Upload .evtx** and the YARA folder scan.

## YARA

The YARA page keeps YARA rules in your browser next to your Sigma rules.

* An editor with line numbers that checks the rule with the real YARA engine ([yara-python](https://github.com/VirusTotal/yara-python)) as you type, and shows each rule and its string count, or the error line.
* **Load samples** adds five sample rule files (ransom notes, shadow copy deletion, encoded PowerShell, PE (Portable Executable) headers and high entropy blobs, cloud keys). **Load sample files** adds files each rule matches, plus one clean file.
* **Scan with all rules** scans the files you drop (64 MB in total, 30 seconds per file). Each match shows the rule, tags, meta, and every string hit with its offset, text and hex.
* Folders on this machine are scanned from the Hunt page.

## Deploy to your SIEM

**Deploy** on the Convert page converts the selected rules and sends them to your platform:

| Platform | What it creates | Settings |
|---|---|---|
| Splunk | One scheduled saved search per rule (`POST /servicesNS/<owner>/<app>/saved/searches`, updated if it exists) | Management URL (port 8089), token or user and password, app, owner, name prefix, cron schedule, search window |
| Elastic Security | Detection rules through Kibana **Import rules** (`POST /api/detection_engine/rules/_import?overwrite=true`) | Kibana URL, API key or user and password, space |
| Microsoft Sentinel | Scheduled analytics rules (`PUT .../alertRules/<id>`) with tactics and techniques | Subscription, resource group, workspace, a bearer token from `az account get-access-token`, frequency and look back |
| Wazuh | One rules XML file uploaded to the manager (`PUT /rules/files/<name>?overwrite=true`), with an optional restart | Manager API URL (port 55000), user and password or a JWT (JSON Web Token) |

Rules are uploaded turned off unless you tick **Turn the rules on after upload**. **Dry run** builds every request and shows the method, URL and body without sending anything, with the auth header masked. Tokens and passwords are never saved; other settings are kept in the browser. Use **Check the TLS certificate** off only for lab servers with self signed certificates.

## GitHub sync

The **GitHub** tab on the Workspace page pulls Sigma rules from a public repository. Type `owner/repo`, or paste a link to a folder like `https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation`. You can also set a branch or tag and a folder. Sigma Forge downloads the repository archive, keeps the `.yml` files that have a `detection` or `correlation` block, and adds them as `github/<owner>/<repo>/<path>`. Each pull is saved as a source. **Sync** downloads it again and replaces the old rules from that source, so deleted rules go away too. The limit is 5,000 rules per pull.

## Command line and GitHub Action

Every check also runs without the web app. Use the `sigma-forge` script (Linux and macOS) or `sigma-forge.ps1` (Windows) from the project folder, or `python -m app.cli`.

```bash
./sigma-forge validate rules/ --fail-on high --min-quality 70
./sigma-forge test rules/ --generate --mode strict --expect-all
./sigma-forge test rules/ --logs Security.evtx sysmon.jsonl
./sigma-forge convert rules/ -t splunk -o out/splunk
./sigma-forge coverage rules/ --navigator layer.json --report report.html --group APT29 --min-coverage 40
./sigma-forge export rules/ -t elastic_esql -o elastic.zip
./sigma-forge from-query 'DeviceProcessEvents | where FileName =~ "certutil.exe"' -o certutil.yml
./sigma-forge hunt rules/ --channels sysmon security powershell --hours 24
./sigma-forge yara yara_rules/ --scan ~/Downloads --fail-on-hit
```

Every command exits with 1 when a check fails and writes a Markdown summary to `--summary` (or to the GitHub job summary when it runs in GitHub Actions).

The repository is also a GitHub Action. Add this workflow to your detection repository (a full example is in [`sample/github/sigma-forge.yml`](sample/github/sigma-forge.yml)):

```yaml
name: Detections
on: [push, pull_request]
jobs:
  sigma:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: qays3/Sigma-Forge@main
        with:
          rules: rules
          min-quality: "60"
          fail-on: high
          test-generated: "true"
          convert-to: "splunk sentinel_asim"
          min-coverage: "0"
          yara-rules: yara
      - uses: actions/upload-artifact@v4
        with:
          name: sigma-forge
          path: sigma-forge-output
```

It validates the rules, fails a pull request when a rule can never fire on its own generated events, converts them, builds a Navigator layer and an HTML coverage report in `sigma-forge-output/`, and checks your YARA rules.

## SigmaHQ library

**Sync now** downloads `sigma_all_rules.zip` from the latest [SigmaHQ release](https://github.com/SigmaHQ/sigma/releases) and indexes it by title, technique, log source, level and status. The files are stored in `data/sigmahq` (a Docker volume when you use compose). On a machine without internet, download the zip yourself and use **Upload zip**. Rules you add are stored as `sigmahq/<path>` in your workspace, so you can tell them apart from your own.

## Field mapping

A mapping profile renames Sigma fields before conversion, for example `CommandLine` to `process.command_line`. Renames apply to detections, `fields` and correlation `group-by`, `aliases` and value fields. Presets for Elastic ECS, Wazuh event data and Splunk CIM are included. **Add fields from workspace** lists every field your rules use, so you only fill in your names. Profiles can be imported from JSON, a pySigma `fieldmappings` block or simple `field: name` lines, and exported as JSON. They are stored in your browser.

## Export packages

**Export package** on the Convert page builds a zip for the current target. Every zip has a `README.md` with install steps and a list of converted, skipped and failed rules, and a `manifest.json` with each rule's file, techniques and warnings.

| Target | Package |
|---|---|
| Splunk SPL, Splunk CIM | Splunk app with `app.conf`, `savedsearches.conf` (one scheduled search per rule, turned off until you enable it) and `default.meta` |
| Splunk SPL2 | One SPL2 module |
| Elastic Lucene, ES\|QL, EQL | `rules.ndjson` for Kibana **Import rules** |
| ElastAlert | One rule file per Sigma rule |
| OpenSearch Lucene | One alerting monitor per rule |
| Sentinel ASIM, Azure Monitor, Defender XDR | `azuredeploy.json` ARM template with scheduled analytics rules, tactics and techniques |
| Google SecOps | One YARA-L 2.0 rule per file |
| Grafana Loki | Loki ruler `rules.yml`, or Grafana alert rules |
| Sumo Logic CSE | Cloud SIEM rules JSON |
| Panther | Simple detection YAML per rule |
| ClickHouse | ClickDetect rules |
| SQLite | Zircolite rule pack |
| Wazuh | One rules XML file for `/var/ossec/etc/rules/` |
| Every target | Query files: one file per rule in the target language |

Correlation rules and rules that needed a fallback go into the main file when its format allows it. Otherwise they are written to an `extra` folder as plain queries and the README says so.

## API

All endpoints take and return JSON, except `/api/test`, `/api/yara/scan` and `/api/library/upload` (multipart form), `/api/export` (returns a zip) and `/api/report` (returns HTML). The `/api/hunt` endpoints only answer requests from the same machine.

| Method | Path | What it does |
|---|---|---|
| `GET` | `/api/health` | App version, pySigma version and ATT&CK data version |
| `GET` | `/api/targets` | Targets with their formats and whether they are installed |
| `GET` | `/api/samples` | Built in sample rules |
| `GET` | `/api/attack` | ATT&CK Enterprise matrix used by the heat map |
| `POST` | `/api/analyze` | Parse and validate rules, return metadata and findings |
| `POST` | `/api/convert` | Convert rules to a target and format |
| `POST` | `/api/coverage` | ATT&CK coverage for the rules, with an optional threat `group` and `collected` log sources |
| `POST` | `/api/coverage/navigator` | ATT&CK Navigator layer JSON |
| `POST` | `/api/coverage/gaps` | Techniques and log sources SigmaHQ covers that the rules do not |
| `POST` | `/api/compare` | Convert the same rules for several targets |
| `POST` | `/api/fields` | Every field the rules use, with counts |
| `GET` | `/api/export/packages` | Export packages offered for each target |
| `POST` | `/api/export` | Build a package zip |
| `POST` | `/api/test` | Run rules on uploaded log files |
| `GET` | `/api/samples/logs` | Built in sample logs |
| `GET` | `/api/library/status` | Library state, release and counts |
| `POST` | `/api/library/sync` | Download the latest SigmaHQ release in the background |
| `POST` | `/api/library/upload` | Load a `sigma_all_rules.zip` you downloaded |
| `GET` | `/api/library/search` | Search by `q`, `technique`, `product`, `category`, `service`, `level`, `status`, `group` |
| `POST` | `/api/library/rules` | Get the content of library rules by path |
| `GET` | `/api/groups` | ATT&CK threat groups with their technique counts |
| `GET` | `/api/atomic/{technique}` | Atomic Red Team tests for a technique and its sub techniques |
| `POST` | `/api/report` | Standalone HTML coverage report (takes `title`, `group`, `collected`) |
| `GET` | `/api/samples/logs?set=baseline` | The normal baseline week for the noise check |
| `POST` | `/api/generate-events` | Events that each rule should match, as JSON lines |
| `POST` | `/api/rulegen` | Draft a rule from an event and a list of fields |
| `POST` | `/api/rules/add-filter` | Add a noise filter block to a rule |
| `GET` | `/api/querygen/languages` | Query languages the query to rule tool reads |
| `POST` | `/api/querygen` | Turn a SIEM query into a Sigma rule |
| `GET` | `/api/deploy/kinds` | Platforms you can deploy to |
| `POST` | `/api/deploy` | Deploy rules, or plan the requests with `dry_run` (the default) |
| `POST` | `/api/git/fetch` | Download Sigma rules from a GitHub repository |
| `GET` | `/api/yara/status` | Whether YARA is installed, and its version |
| `GET` | `/api/samples/yara` | Sample YARA rules and files |
| `POST` | `/api/yara/check` | Compile YARA rules and list them |
| `POST` | `/api/yara/scan` | Scan uploaded files with YARA rules (multipart form) |
| `GET` | `/api/hunt/status` | This machine: platform, admin rights, event logs and suggested folders |
| `POST` | `/api/hunt/events` | Run rules on this Windows machine's live event logs |
| `POST` | `/api/hunt/yara` | Scan folders on this machine with YARA rules |

Rules are always sent as a list of `{name, content}` objects:

```bash
curl -s http://127.0.0.1:8000/api/convert \
  -H "Content-Type: application/json" \
  -d '{
        "target": "defender_xdr",
        "format": "default",
        "rules": [{"name": "whoami.yml", "content": "title: Whoami\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  sel:\n    Image|endswith: \"\\\\whoami.exe\"\n  condition: sel\nlevel: low"}]
      }'
```

Targets with extra settings take them in `options`:

```json
{"target": "wazuh", "rules": [], "options": {"wazuh_rule_id_start": 110000, "wazuh_double_backslash": false, "wazuh_parent_group": true}}
```

`/api/convert`, `/api/compare` and `/api/export` also take a `field_mapping` object, for example `{"CommandLine": "process.command_line"}`. Export takes `package` (an id from `/api/export/packages`, or `auto`) and `name`.

Test rules on logs with a multipart form:

```bash
curl -s http://127.0.0.1:8000/api/test \
  -F 'rules=[{"name":"r.yml","content":"..."}]' \
  -F mode=auto \
  -F files=@sample/logs/windows_sysmon.jsonl \
  -F files=@Security.evtx
```

## Configuration

Set these as environment variables. See [`.env.example`](.env.example).

| Variable | Default | Meaning |
|---|---|---|
| `SIGMA_FORGE_HOST` | `127.0.0.1` | Bind address (`0.0.0.0` in Docker) |
| `SIGMA_FORGE_PORT` | `8000` | Port |
| `SIGMA_FORGE_MAX_RULES` | `5000` | Most files per request |
| `SIGMA_FORGE_MAX_RULE_BYTES` | `262144` | Largest file size per rule file |
| `SIGMA_FORGE_WAZUH_ID_START` | `100100` | Default first Wazuh rule id |
| `SIGMA_FORGE_WAZUH_MAX_SPLIT` | `64` | Most Wazuh rules made from one Sigma rule |
| `SIGMA_FORGE_MAX_LOG_BYTES` | `67108864` | Largest total upload for a log test (64 MB) |
| `SIGMA_FORGE_MAX_LOG_EVENTS` | `250000` | Most events in one log test |
| `SIGMA_FORGE_LOG_QUERY_SECONDS` | `10` | Time limit for each rule query in a log test |
| `SIGMA_FORGE_SIGMAHQ_DIR` | `data/sigmahq` | Where the SigmaHQ library is stored |
| `SIGMA_FORGE_SIGMAHQ_URL` | latest release zip | Where **Sync now** downloads the library from |
| `SIGMA_FORGE_ALLOW_REMOTE_HUNT` | off | Set to `1` to let other machines start Hunt scans on this server |
| `WAZUH_API_URL` | `https://127.0.0.1:55000` | Used by `wazuh_check.py` |
| `WAZUH_API_USER` | `wazuh` | Used by `wazuh_check.py` |
| `WAZUH_API_PASSWORD` | none | Used by `wazuh_check.py` |

## Architecture

```mermaid
flowchart LR
    subgraph Browser
        UI[SPA<br/>vanilla JS modules]
        DB[(IndexedDB<br/>your rules)]
        UI <--> DB
    end
    subgraph Server[FastAPI server]
        R[API routes]
        P[Parser and validators<br/>pySigma]
        C[Converter]
        W[Sigma Forge backends]
        V[Coverage engine]
        A[(ATT&CK data<br/>attack.json)]
        T[Log test engine]
        S[(SQLite<br/>in memory)]
        X[Export packer]
        LB[(SigmaHQ library<br/>data/sigmahq)]
        TG[(Groups and Atomic<br/>Red Team index)]
        Q[Query to rule<br/>and rule from event]
        G[Event generator]
        H[Hunt<br/>wevtutil, folders]
        Y[YARA engine]
        D[Deploy]
        R --> P
        R --> C
        C --> PB[pySigma backends<br/>Splunk, Elastic, Kusto]
        C --> W
        R --> V
        V --> A
        V --> LB
        R --> T
        T --> C
        T --> S
        R --> X
        X --> C
        R --> LB
        V --> TG
        R --> Q
        R --> G
        R --> H
        H --> T
        H --> Y
        R --> Y
        R --> D
        D --> C
    end
    UI <-- JSON --> R
    D -- HTTPS --> SIEM[Splunk, Elastic,<br/>Sentinel, Wazuh]
    CLI[sigma-forge CLI<br/>and GitHub Action] --> P
    CLI --> T
```

* The server never stores your rules. Each request carries the rules it needs. The only thing it keeps on disk is the SigmaHQ library you sync. Mapping profiles, YARA rules, version history, log readiness, GitHub sources and the editor draft live in your browser.
* ATT&CK data for the Elastic SIEM rule formats comes from the local `attack.json`, so no conversion needs internet.
* The SPA uses the History API for clean URLs (`/convert`, `/coverage`, `/editor`, `/test`, `/hunt`, `/yara`, `/library` and so on). FastAPI returns `index.html` for any path that is not an API route or an asset.
* All colors come from [`web/assets/css/root.css`](web/assets/css/root.css). The rest of the CSS only uses its variables, so changing that one file restyles the whole app, both themes included.

## Project layout

```text
Sigma-Forge/
├── app/
│   ├── main.py                  FastAPI app, static files, SPA fallback
│   ├── config.py                Paths and environment settings
│   ├── schemas.py               Request models
│   ├── cli.py                   sigma-forge command line
│   ├── api/
│   │   └── routes.py            /api endpoints
│   └── core/
│       ├── parsing.py           Load YAML into pySigma rules
│       ├── analyzer.py          Metadata and validators
│       ├── converter.py         Run every conversion
│       ├── targets.py           Target list, backends and pipelines
│       ├── coverage.py          ATT&CK coverage and Navigator layer
│       ├── attack.py            ATT&CK data and tag helpers
│       ├── offline_attack.py    Feeds local ATT&CK data to pySigma
│       ├── fieldmap.py          Custom field mapping
│       ├── logtest.py           EVTX and JSON loading, SQLite test runs
│       ├── library.py           SigmaHQ sync, index and search
│       ├── export.py            Ready to deploy packages
│       ├── eventgen.py          Test events built from each rule
│       ├── rulegen.py           Rule from an event, noise filters
│       ├── querygen.py          SIEM query to Sigma rule
│       ├── threat.py            Threat groups, Atomic Red Team, log readiness
│       ├── report.py            HTML coverage report
│       ├── deploy.py            Splunk, Elastic, Sentinel and Wazuh APIs
│       ├── gitsync.py           Rules from GitHub
│       ├── hunt.py              Live Windows event logs, folder walking
│       ├── yara_engine.py       YARA check and scan
│       └── wazuh/
│           ├── backend.py       Sigma to Wazuh XML
│           └── mapping.py       Log source and field mapping
├── web/
│   ├── index.html               SPA shell
│   └── assets/
│       ├── css/
│       │   ├── root.css         Theme tokens (the only place with colors)
│       │   └── app.css          Layout and components
│       ├── js/
│       │   ├── app.js           Startup, theme, header
│       │   ├── router.js        History API router
│       │   ├── api.js           API client
│       │   ├── store.js         IndexedDB rule store
│       │   ├── state.js         Shared cache
│       │   ├── ui.js            Helpers, drawer, toasts, skeletons
│       │   ├── mappings.js      Field mapping profiles
│       │   ├── shared.js        History, diff, quality and editor helpers
│       │   └── views/           workspace, convert, coverage, rules, editor,
│       │                        compare, test, hunt, yara, library, mappings,
│       │                        results (shared test results), yarakit
│       └── img/                 Animated logo (logo.gif), logo, banners, screenshots
├── data/
│   ├── attack/                  Compact ATT&CK Enterprise data and threat groups
│   └── atomic/atomics.json      Atomic Red Team test index
├── media/                       Demo video and its preview picture
├── sample/
│   ├── rules/                   Sample pack by feature (windows, linux, network,
│   │                            cloud, modifiers, correlation, collections, broken)
│   │                            and the ATT&CK pack (attack, 227 rules)
│   ├── logs/                    Sample logs for the Test page, baseline/ week for
│   │                            the noise check
│   ├── yara/                    Sample YARA rules and files they match
│   ├── github/sigma-forge.yml   Example workflow for the GitHub Action
│   ├── wazuh/events.jsonl       Wazuh logtest events
│   └── api/                     API request bodies and run_examples scripts
├── tools/
│   ├── fetch_attack.py          Build attack.json and groups.json from MITRE STIX
│   ├── fetch_atomic.py          Build the Atomic Red Team index
│   └── wazuh_check.py           Upload and test rules on a Wazuh manager
├── tests/                       pytest suite
├── setup.sh                     Linux and macOS setup
├── setup.ps1                    Windows setup
├── sigma-forge, sigma-forge.ps1 Command line wrappers
├── action.yml                   GitHub Action
├── Dockerfile
├── docker-compose.yml
├── requirements.txt             Core packages and 20 pySigma backends
├── requirements-legacy.txt      Older backends installed with --no-deps
└── requirements-dev.txt
```

## Development

```bash
./setup.sh --dev            # or .\setup.ps1 -Dev
.venv/bin/python -m pytest -q
.venv/bin/python -m uvicorn app.main:app --reload
```

The tests cover the API, every target, error handling, correlations, coverage, the ATT&CK pack, log tests, generated events (every sample rule must fire on its own events), the noise check, query to rule for each language, threat groups, reports, deploy against a mock server, GitHub sync, YARA, the Hunt endpoints, field mapping, compare and every export package format. The backend tests compile the generated regex and check it against real looking field values, so they catch broken escaping and wrong logic, not only bad XML.

Adding a sample rule is as simple as dropping a `.yml` file anywhere under `sample/rules/`. It shows up under **Load samples** right away.

## Known limits

* **Feature support differs per target.** Some backends cannot do number compare, `fieldref`, `cidr`, case sensitive matching or keyword search. Those rules show the reason on their card. The [target guide](#target-guide) lists the most common failures for each target.
* **Correlation rules** only convert on targets whose backend supports them (see [correlation rules](#correlation-rules)). Base rules must be in the same file.
* **Log tests** use SQLite, so they show whether a rule's logic matches an event, not how a given SIEM parses your logs. Field names in your logs must match the rule (or a mapping profile). Regex follows Python rules.
* **The ATT&CK pack** covers every parent technique. Sub techniques are covered where a rule targets one, not one by one.
* **Pipelines** only know the log sources their authors mapped. Rules for other log sources show the pySigma error on their card.
* **Query to rule** reads filters, not pipelines. Joins, `stats`, `eval`, lookups and sub searches are skipped, and EQL sequences are not supported yet. Always check the field names and the log source of the result.
* **Live event logs** need Windows and read up to 50,000 events per scan. The Security log needs administrator rights.
* **Deploy** was built against the public API docs of each platform. Try a dry run and a small set of rules first on your version.
* **Elastic Lucene** regex is not PCRE (Perl Compatible Regular Expressions), so rules with complex `re` values may need a manual check.

## Credits

* [SigmaHQ](https://github.com/SigmaHQ) for the Sigma format and [pySigma](https://github.com/SigmaHQ/pySigma) with its backends and pipelines.
* [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) by Red Canary for the test index, and [YARA](https://virustotal.github.io/yara/) by VirusTotal.
* [MITRE ATT&CK®](https://attack.mitre.org/). © The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
* Splunk, Elastic, OpenSearch, Microsoft, CrowdStrike, SentinelOne, Palo Alto Networks, Google, Broadcom, IBM, Logpoint, RSA, Sumo Logic, Panther, Trellix, Grafana, Quickwit, ClickHouse, SurrealDB and Wazuh are trademarks of their owners. Sigma Forge is not tied to any of them.

<div align="center">
<sub>Built by <a href="https://qayssarayra.com">Qays Sarayra</a></sub>
</div>
