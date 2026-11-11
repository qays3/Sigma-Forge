from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, List, Optional

from sigma.plugins import InstalledSigmaPlugins
from sigma.processing.resolver import ProcessingPipelineResolver


@dataclass(frozen=True)
class Target:
    id: str
    name: str
    family: str
    language: str
    backend: Optional[str]
    pipelines: List[str] = field(default_factory=list)
    description: str = ""
    notes: List[str] = field(default_factory=list)
    hide_formats: tuple = ()


T = Target

TARGETS: List[Target] = [
    T("splunk", "Splunk SPL", "Splunk", "spl", "splunk", ["sysmon", "splunk_windows"],
      "Splunk Search Processing Language for Windows Event Log and Sysmon data",
      ["Paste the query in Search, or pick the savedsearches format to get a savedsearches.conf stanza."],
      ("data_model",)),
    T("splunk_cim", "Splunk CIM", "Splunk", "spl", "splunk", ["splunk_cim"],
      "tstats searches over the Common Information Model data models",
      ["Use the data_model format. Needs accelerated CIM data models such as Endpoint.Processes."]),
    T("splunk_spl2", "Splunk SPL2", "Splunk", "spl2", "splunk_spl2", ["sysmon", "splunk_windows"],
      "Next generation SPL2 syntax for Splunk Cloud and Edge Processor",
      ["SPL2 starts with FROM main. Change the index name to yours."]),
    T("elastic_lucene", "Elastic Lucene", "Elastic", "lucene", "lucene", ["ecs_windows"],
      "Kibana query bar and detection rules with Elastic Common Schema (ECS) fields",
      ["Pick siem_rule_ndjson to import straight into Elastic Security rules."]),
    T("elastic_esql", "Elastic ES|QL", "Elastic", "esql", "esql", ["ecs_windows"],
      "Elasticsearch Query Language with ECS fields, supports correlations",
      ["Replace 'from *' with your index pattern, for example logs-*."]),
    T("elastic_eql", "Elastic EQL", "Elastic", "eql", "eql", ["ecs_windows"],
      "Event Query Language with ECS fields", []),
    T("elastalert", "ElastAlert", "Elastic", "yaml", "elastalert", ["ecs_windows"],
      "ElastAlert 2 rule files with ECS fields",
      ["Add index, alert and other required keys to each rule before loading it in ElastAlert 2."]),
    T("opensearch_lucene", "OpenSearch Lucene", "OpenSearch", "lucene", "opensearch_lucene", ["ecs_windows"],
      "OpenSearch Dashboards queries and monitor rules with ECS fields",
      ["Pick monitor_rule to get OpenSearch Alerting monitors."]),
    T("opensearch_ppl", "OpenSearch PPL", "OpenSearch", "ppl", "open_search_ppl", [],
      "OpenSearch Piped Processing Language",
      ["The source index is named after the log source, like windows-process_creation-*. Change it to your index."],
      ("kibana",)),
    T("defender_xdr", "Defender XDR (KQL)", "Microsoft", "kql", "kusto", ["microsoft_xdr"],
      "Kusto Query Language (KQL) for advanced hunting tables like DeviceProcessEvents", []),
    T("sentinel_asim", "Sentinel ASIM (KQL)", "Microsoft", "kql", "kusto", ["sentinel_asim"],
      "KQL over Advanced Security Information Model parsers like imProcessCreate", []),
    T("azure_monitor", "Azure Monitor (KQL)", "Microsoft", "kql", "kusto", ["azure_monitor"],
      "KQL for Log Analytics tables like SecurityEvent", []),
    T("crowdstrike_falcon", "CrowdStrike LogScale (Falcon)", "CrowdStrike", "logscale", "log_scale", ["crowdstrike_falcon"],
      "Falcon LogScale (Humio) queries over Falcon sensor events like ProcessRollup2",
      ["Run it in Falcon Next-Gen SIEM or Event Search. CIDR lists joined with OR are not supported yet."]),
    T("crowdstrike_fdr", "CrowdStrike LogScale (FDR)", "CrowdStrike", "logscale", "log_scale", ["crowdstrike_fdr"],
      "LogScale queries over Falcon Data Replicator field names", []),
    T("sentinelone", "SentinelOne Deep Visibility", "SentinelOne", "s1ql", "sentinel_one", [],
      "SentinelOne Deep Visibility queries (S1QL)",
      ["Only Windows, Linux and macOS endpoint log sources are mapped."]),
    T("sentinelone_pq", "SentinelOne PowerQuery", "SentinelOne", "powerquery", "sentinel_one_pq", [],
      "SentinelOne Singularity Data Lake PowerQuery", []),
    T("cortex_xdr", "Cortex XDR (XQL)", "Palo Alto", "xql", "cortex_xdr", [],
      "Palo Alto Networks Cortex XDR Query Language over xdr_data",
      ["Only endpoint log sources are mapped. Network and cloud rules show an error."]),
    T("secops", "Google SecOps (UDM)", "Google", "udm", "secops", ["secops_udm"],
      "Google Security Operations (Chronicle) Unified Data Model search",
      ["Pick the yara_l format to get YARA-L 2.0 detection rules."]),
    T("carbon_black", "Carbon Black Cloud", "Broadcom", "cbc", "carbon_black", ["carbonblack"],
      "Carbon Black Cloud Enterprise EDR process search", []),
    T("qradar", "IBM QRadar AQL", "IBM", "aql", "qradar", [],
      "Ariel Query Language (AQL) searches for QRadar",
      ["Uses the legacy QRadar backend (installed from requirements-legacy.txt). Field names follow QRadar default properties."]),
    T("logpoint", "Logpoint", "Logpoint", "lpql", "logpoint", ["logpoint_windows"],
      "Logpoint Query Language with Logpoint Windows taxonomy", []),
    T("netwitness", "RSA NetWitness", "RSA", "netwitness", "net_witness", ["netwitness_windows"],
      "NetWitness query syntax for Windows log sources", []),
    T("sumologic_cse", "Sumo Logic CSE", "Sumo Logic", "json", "sumologic_cse", ["sumologic_cse"],
      "Sumo Logic Cloud SIEM rule JSON",
      ["Import the JSON with the Cloud SIEM API. Keyword only rules are not supported."]),
    T("panther", "Panther (Python)", "Panther", "python", "panther", [],
      "Panther detections as Python rule functions",
      ["Pick sdyaml for Panther simple detections or pantherflow for PantherFlow queries."]),
    T("trellix_helix", "Trellix Helix (TQL)", "Trellix", "tql", "tql", [],
      "Trellix Helix Query Language",
      ["Uses a legacy backend (requirements-legacy.txt). Only a set of Helix fields is mapped."]),
    T("loki", "Grafana Loki (LogQL)", "Grafana", "logql", "loki", [],
      "LogQL queries for Grafana Loki",
      ["Pick ruler to get Loki ruler alert files. Change the stream selector to your labels."]),
    T("quickwit", "Quickwit", "Quickwit", "quickwit", "quickwit", ["quickwit_windows"],
      "Quickwit search queries", []),
    T("clickhouse", "ClickHouse SQL", "Databases", "sql", "clickhouse", [],
      "SQL for logs stored in ClickHouse",
      ["The table is named logs. Change it to your table."]),
    T("sqlite", "SQLite (Zircolite)", "Databases", "sql", "sqlite", [],
      "SQLite queries, and Zircolite rule packs for offline EVTX hunting",
      ["Pick the zircolite format to build a rule pack for Zircolite."]),
    T("surrealql", "SurrealDB (SurrealQL)", "Databases", "surrealql", "surreal_ql", [],
      "SurrealQL queries for SurrealDB",
      ["Replace <TABLE_NAME> with your table. Uses a legacy backend (requirements-legacy.txt)."]),
    T("wazuh", "Wazuh rules (XML)", "Wazuh", "xml", None, [],
      "Wazuh XML rules for Windows eventchannel and Sysmon data", []),
]

TARGET_MAP: Dict[str, Target] = {t.id: t for t in TARGETS}


@lru_cache(maxsize=1)
def plugins() -> InstalledSigmaPlugins:
    try:
        return InstalledSigmaPlugins.autodiscover()
    except Exception:
        return _safe_discover()


def _safe_discover() -> InstalledSigmaPlugins:
    import importlib
    import pkgutil

    import sigma.backends
    import sigma.pipelines

    backends, pipelines = {}, {}
    for base, store in ((sigma.backends, backends), (sigma.pipelines, pipelines)):
        for mod in pkgutil.iter_modules(base.__path__, base.__name__ + "."):
            try:
                module = importlib.import_module(mod.name)
            except Exception:
                continue
            found = getattr(module, "backends" if store is backends else "pipelines", None)
            if isinstance(found, dict):
                store.update(found)
    return InstalledSigmaPlugins(backends=backends, pipelines=pipelines, validators={})


@lru_cache(maxsize=1)
def resolver() -> ProcessingPipelineResolver:
    return ProcessingPipelineResolver(dict(plugins().pipelines))


def backend_class(target: Target):
    if target.backend is None:
        return None
    return plugins().backends.get(target.backend)


def target_formats(target: Target) -> Dict[str, str]:
    if target.backend is None:
        return {"default": "One Wazuh rule group per Sigma rule"}
    cls = backend_class(target)
    if cls is None:
        return {}
    return {k: v for k, v in getattr(cls, "formats", {"default": "Default"}).items() if k not in target.hide_formats}


def available_targets() -> List[Dict]:
    out = []
    for t in TARGETS:
        installed = t.backend is None or backend_class(t) is not None
        missing = [p for p in t.pipelines if p not in plugins().pipelines]
        out.append({
            "id": t.id,
            "name": t.name,
            "family": t.family,
            "language": t.language,
            "description": t.description,
            "pipelines": t.pipelines,
            "backend": t.backend or "sigma-forge-wazuh",
            "notes": t.notes,
            "formats": target_formats(t) if installed else {},
            "available": installed and not missing,
        })
    return out


def build_backend(target: Target):
    cls = backend_class(target)
    if cls is None:
        raise ValueError(f"Backend for {target.name} is not installed")
    pipeline = resolver().resolve(target.pipelines) if target.pipelines else None
    return cls(processing_pipeline=pipeline) if pipeline is not None else cls()
