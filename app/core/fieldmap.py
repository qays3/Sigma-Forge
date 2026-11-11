import re
from typing import Dict, Iterable, List, Tuple

import yaml

MAX_MAPPINGS = 2000
FIELD_RE = re.compile(r"^[^|]+")


class MappingError(ValueError):
    pass


def clean_mapping(mapping: Dict[str, str]) -> Dict[str, str]:
    if not mapping:
        return {}
    if len(mapping) > MAX_MAPPINGS:
        raise MappingError(f"Too many field mappings. The limit is {MAX_MAPPINGS}.")
    out = {}
    for key, value in mapping.items():
        key = str(key).strip()
        value = str(value).strip()
        if not key or not value or key == value:
            continue
        if "|" in key or "|" in value:
            raise MappingError(f"Field names cannot contain '|': {key} -> {value}")
        out[key] = value
    return out


def _rename_key(key: str, mapping: Dict[str, str], used: Dict[str, int]) -> str:
    if not isinstance(key, str):
        return key
    head, sep, rest = key.partition("|")
    target = mapping.get(head)
    if target is None:
        return key
    used[head] = used.get(head, 0) + 1
    return target + sep + rest


def _rename_detection(node, mapping, used):
    if isinstance(node, dict):
        return {_rename_key(k, mapping, used): v for k, v in node.items()}
    if isinstance(node, list):
        return [_rename_detection(item, mapping, used) if isinstance(item, dict) else item for item in node]
    return node


def _rename_list(values, mapping, used):
    if isinstance(values, str):
        return _rename_key(values, mapping, used)
    if isinstance(values, list):
        return [_rename_key(v, mapping, used) if isinstance(v, str) else v for v in values]
    return values


def apply_to_document(doc, mapping, used):
    if not isinstance(doc, dict):
        return doc
    detection = doc.get("detection")
    if isinstance(detection, dict):
        doc["detection"] = {
            name: (value if name in ("condition", "timeframe") else _rename_detection(value, mapping, used))
            for name, value in detection.items()
        }
    if "fields" in doc:
        doc["fields"] = _rename_list(doc["fields"], mapping, used)
    corr = doc.get("correlation")
    if isinstance(corr, dict):
        if "group-by" in corr:
            corr["group-by"] = _rename_list(corr["group-by"], mapping, used)
        condition = corr.get("condition")
        if isinstance(condition, dict) and isinstance(condition.get("field"), (str, list)):
            condition["field"] = _rename_list(condition["field"], mapping, used)
        aliases = corr.get("aliases")
        if isinstance(aliases, dict):
            for alias in aliases.values():
                if isinstance(alias, dict):
                    for rule_name, field in list(alias.items()):
                        alias[rule_name] = _rename_key(field, mapping, used) if isinstance(field, str) else field
    return doc


def apply_mapping(content: str, mapping: Dict[str, str]) -> Tuple[str, Dict[str, int]]:
    used: Dict[str, int] = {}
    if not mapping:
        return content, used
    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError:
        return content, used
    docs = [apply_to_document(d, mapping, used) for d in docs]
    if not used:
        return content, used
    text = yaml.safe_dump_all(docs, sort_keys=False, allow_unicode=True, default_flow_style=False, width=4096)
    return text, used


def map_inputs(inputs: Iterable, mapping: Dict[str, str]) -> Tuple[List, Dict[str, int]]:
    from app.schemas import RuleInput

    mapping = clean_mapping(mapping)
    items = list(inputs)
    if not mapping:
        return items, {}
    total: Dict[str, int] = {}
    out = []
    for item in items:
        text, used = apply_mapping(item.content, mapping)
        for k, v in used.items():
            total[k] = total.get(k, 0) + v
        out.append(RuleInput(name=item.name, content=text))
    return out, total
