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


TARGETS: List[Target] = [
    Target("splunk", "Splunk SPL (Sysmon and Windows)", "Splunk", "spl", "splunk", ["sysmon", "splunk_windows"],
           "Windows Event Log and Sysmon sources with EventCode filters"),
    Target("splunk_cim", "Splunk CIM data models", "Splunk", "spl", "splunk", ["splunk_cim"],
           "tstats searches over CIM data models. Use the data_model format"),
    Target("elastic_lucene", "Elastic Lucene (ECS)", "Elastic", "lucene", "lucene", ["ecs_windows"],
           "Kibana query bar and detection rules with Elastic Common Schema fields"),
    Target("elastic_esql", "Elastic ES|QL (ECS)", "Elastic", "esql", "esql", ["ecs_windows"],
           "Elasticsearch Query Language with ECS fields"),
    Target("elastic_eql", "Elastic EQL (ECS)", "Elastic", "eql", "eql", ["ecs_windows"],
           "Event Query Language with ECS fields"),
    Target("defender_xdr", "Microsoft Defender XDR (KQL)", "Microsoft", "kql", "kusto", ["microsoft_xdr"],
           "Advanced hunting tables like DeviceProcessEvents"),
    Target("sentinel_asim", "Microsoft Sentinel ASIM (KQL)", "Microsoft", "kql", "kusto", ["sentinel_asim"],
           "Advanced Security Information Model parsers like imProcessCreate"),
    Target("azure_monitor", "Azure Monitor (KQL)", "Microsoft", "kql", "kusto", ["azure_monitor"],
           "Log Analytics tables like SecurityEvent"),
    Target("wazuh", "Wazuh rules (XML)", "Wazuh", "xml", None, [],
           "Custom Sigma Forge backend for Windows eventchannel and Sysmon fields"),
]

TARGET_MAP: Dict[str, Target] = {t.id: t for t in TARGETS}


@lru_cache(maxsize=1)
def plugins() -> InstalledSigmaPlugins:
    return InstalledSigmaPlugins.autodiscover()


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
    return dict(getattr(cls, "formats", {"default": "Default"}))


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
