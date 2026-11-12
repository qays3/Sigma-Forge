from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class RuleInput(BaseModel):
    name: str = Field(default="rule.yml", max_length=512)
    content: str


class RulesRequest(BaseModel):
    rules: List[RuleInput]


class ConvertOptions(BaseModel):
    wazuh_rule_id_start: Optional[int] = Field(default=None, ge=1, le=999999)
    wazuh_double_backslash: bool = True
    wazuh_parent_group: bool = True


class ConvertRequest(BaseModel):
    rules: List[RuleInput]
    target: str
    format: str = "default"
    options: ConvertOptions = ConvertOptions()
    field_mapping: Dict[str, str] = Field(default_factory=dict)
    allowlist: List[Dict[str, Any]] = Field(default_factory=list)


class NavigatorRequest(BaseModel):
    rules: List[RuleInput]
    name: str = Field(default="Sigma Forge coverage", max_length=200)
    colors: List[str] = Field(default_factory=list, max_length=3)


class CompareRequest(BaseModel):
    rules: List[RuleInput]
    targets: List[str] = Field(min_length=1, max_length=6)
    options: ConvertOptions = ConvertOptions()
    field_mapping: Dict[str, str] = Field(default_factory=dict)
    allowlist: List[Dict[str, Any]] = Field(default_factory=list)


class ExportRequest(BaseModel):
    rules: List[RuleInput]
    target: str
    format: str = "default"
    options: ConvertOptions = ConvertOptions()
    field_mapping: Dict[str, str] = Field(default_factory=dict)
    package: str = Field(default="auto", max_length=40)
    name: str = Field(default="sigma-forge", max_length=80)
    allowlist: List[Dict[str, Any]] = Field(default_factory=list)


class LibraryAddRequest(BaseModel):
    paths: List[str] = Field(min_length=1, max_length=500)


class CoverageRequest(BaseModel):
    rules: List[RuleInput]
    group: Optional[str] = Field(default=None, max_length=80)
    collected: Optional[List[str]] = None


class ReportRequest(BaseModel):
    rules: List[RuleInput]
    title: str = Field(default="", max_length=200)
    group: Optional[str] = Field(default=None, max_length=80)
    collected: Optional[List[str]] = None


class RuleGenRequest(BaseModel):
    event: Dict[str, Any]
    logsource: Optional[Dict[str, str]] = None
    fields: Optional[List[str]] = None
    title: str = Field(default="", max_length=200)


class AddFilterRequest(BaseModel):
    content: str
    title: str = Field(default="", max_length=300)
    filters: List[Dict[str, Any]] = Field(min_length=1, max_length=20)


class DeployRequest(BaseModel):
    rules: List[RuleInput]
    kind: str = Field(max_length=20)
    target: str = Field(default="", max_length=40)
    settings: Dict[str, Any] = Field(default_factory=dict)
    options: ConvertOptions = ConvertOptions()
    field_mapping: Dict[str, str] = Field(default_factory=dict)
    dry_run: bool = True
    allowlist: List[Dict[str, Any]] = Field(default_factory=list)


class GitFetchRequest(BaseModel):
    repo: str = Field(max_length=300)
    ref: str = Field(default="", max_length=120)
    path: str = Field(default="", max_length=300)


class ErrorResponse(BaseModel):
    detail: str


JSONDict = Dict[str, Any]


class QueryGenRequest(BaseModel):
    query: str = Field(min_length=1, max_length=20000)
    language: str = "auto"
    title: str = Field(default="", max_length=300)
    level: str = "medium"
    logsource: Optional[Dict[str, str]] = None


class HuntEventsRequest(BaseModel):
    rules: List[RuleInput]
    channels: List[str] = Field(min_length=1, max_length=20)
    hours: float = Field(default=24, gt=0, le=720)
    max_events: int = Field(default=20000, ge=100, le=50000)
    mode: str = "auto"
    field_mapping: Dict[str, Any] = Field(default_factory=dict)
    allowlist: List[Dict[str, Any]] = Field(default_factory=list)


class HuntYaraRequest(BaseModel):
    rules: List[RuleInput]
    paths: List[str] = Field(min_length=1, max_length=20)
    recursive: bool = True
    max_files: int = Field(default=20000, ge=1, le=200000)
    max_size_mb: int = Field(default=32, ge=1, le=512)
    extensions: List[str] = Field(default_factory=list)



class HuntReportRequest(BaseModel):
    result: Dict[str, Any]
    title: str = Field(default="", max_length=200)
    scope: str = Field(default="", max_length=400)


class ScheduleRequest(BaseModel):
    enabled: bool = False
    every_minutes: int = Field(default=15, ge=5, le=1440)
    channels: List[str] = Field(default_factory=list, max_length=20)
    rules: Optional[List[RuleInput]] = None
    min_level: str = "medium"
    kind: str = "slack"
    url: Optional[str] = Field(default=None, max_length=2000)


class ProcessScanRequest(BaseModel):
    rules: List[RuleInput]
    pids: List[int] = Field(default_factory=list, max_length=5000)


class IocRequest(BaseModel):
    text: str = Field(min_length=1, max_length=500000)
    name: str = Field(default="", max_length=80)


class AutofixRequest(BaseModel):
    content: str = Field(min_length=1, max_length=262144)
    name: str = Field(default="", max_length=300)


class PurpleRequestMeta(BaseModel):
    techniques: List[str] = Field(default_factory=list)
