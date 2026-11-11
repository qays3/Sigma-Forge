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


class NavigatorRequest(BaseModel):
    rules: List[RuleInput]
    name: str = Field(default="Sigma Forge coverage", max_length=200)
    colors: List[str] = Field(default_factory=list, max_length=3)


class ErrorResponse(BaseModel):
    detail: str


JSONDict = Dict[str, Any]
