from dataclasses import dataclass
from typing import Iterable, List, Optional

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

from app.config import MAX_RULE_BYTES, MAX_RULES


@dataclass
class ParsedRule:
    file: str
    index: int
    rule: Optional[SigmaRule]
    error: Optional[str]
    kind: str = "rule"

    @property
    def key(self) -> str:
        return f"{self.file}#{self.index}"


class InputLimitError(ValueError):
    pass


def check_limits(inputs: Iterable) -> None:
    items = list(inputs)
    if len(items) > MAX_RULES:
        raise InputLimitError(f"Too many files: {len(items)} (limit {MAX_RULES})")
    for item in items:
        if len(item.content.encode("utf-8")) > MAX_RULE_BYTES:
            raise InputLimitError(f"File {item.name} is larger than {MAX_RULE_BYTES} bytes")


def _first_error(errors) -> Optional[str]:
    if not errors:
        return None
    return "; ".join(str(e) for e in errors)


def parse_file(name: str, content: str) -> List[ParsedRule]:
    try:
        collection = SigmaCollection.from_yaml(content, collect_errors=True)
    except Exception as exc:
        return [ParsedRule(file=name, index=0, rule=None, error=f"YAML error: {exc}")]

    parsed: List[ParsedRule] = []
    for index, item in enumerate(collection.rules):
        if not isinstance(item, SigmaRule):
            kind = type(item).__name__.replace("Sigma", "").lower() or "unknown"
            parsed.append(ParsedRule(file=name, index=index, rule=None, error=f"Unsupported Sigma document type: {kind}", kind=kind))
            continue
        parsed.append(ParsedRule(file=name, index=index, rule=item, error=_first_error(item.errors)))

    if not parsed:
        errors = getattr(collection, "errors", None)
        parsed.append(ParsedRule(file=name, index=0, rule=None, error=_first_error(errors) or "No Sigma rule found in file"))
    return parsed


def parse_inputs(inputs) -> List[ParsedRule]:
    items = list(inputs)
    check_limits(items)
    result: List[ParsedRule] = []
    for item in items:
        result.extend(parse_file(item.name, item.content))
    return result
