from dataclasses import dataclass, field
from itertools import product as cartesian
from typing import Dict, List, Optional, Tuple
from xml.sax.saxutils import escape as xml_escape

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

from app.core.attack import split_attack_tags
from app.core.wazuh.mapping import map_field, resolve_parent

LEVELS = {"informational": 3, "low": 5, "medium": 8, "high": 12, "critical": 15}
REGEX_SPECIAL = set("\\^$.|?*+()[]{}")
KEYWORD = None


class WazuhConversionError(Exception):
    pass


@dataclass(frozen=True)
class Literal:
    field: Optional[str]
    body: Tuple[str, ...]
    insensitive: bool
    negated: bool

    def flip(self) -> "Literal":
        return Literal(self.field, self.body, self.insensitive, not self.negated)


@dataclass
class WazuhOptions:
    rule_id_start: int = 100100
    double_backslash: bool = True
    parent_group: bool = True
    max_split: int = 64


@dataclass
class WazuhResult:
    xml: str
    rule_ids: List[int]
    warnings: List[str] = field(default_factory=list)


def escape_literal(text: str, double_backslash: bool) -> List[str]:
    tokens: List[str] = []
    for ch in text:
        if ch == "\\":
            tokens.append("\\\\\\\\" if double_backslash else "\\\\")
        elif ch in REGEX_SPECIAL:
            tokens.append("\\" + ch)
        elif ch == "\n":
            tokens.append("\\n")
        elif ch == "\t":
            tokens.append("\\t")
        else:
            tokens.append(ch)
    return ["".join(tokens)] if tokens else []


def string_tokens(value: SigmaString, double_backslash: bool) -> Tuple[str, ...]:
    tokens: List[str] = []
    for part in value.s:
        if isinstance(part, str):
            tokens.extend(escape_literal(part, double_backslash))
        elif part == SpecialChars.WILDCARD_MULTI:
            if not tokens or tokens[-1] != ".*":
                tokens.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            tokens.append(".")
        else:
            raise WazuhConversionError("Placeholders must be resolved before converting to Wazuh")
    return tuple(tokens)


class WazuhBackend:
    name = "Wazuh"

    def __init__(self, options: Optional[WazuhOptions] = None):
        self.options = options or WazuhOptions()
        self.next_id = self.options.rule_id_start
        self._cidrs: List[str] = []

    def convert_rule(self, rule: SigmaRule) -> WazuhResult:
        ls = rule.logsource
        product = (ls.product or "").lower()
        parent = resolve_parent(product, ls.category or "", ls.service or "")
        warnings: List[str] = []
        self._cidrs: List[str] = []
        if parent.note:
            warnings.append(parent.note)

        conjunctions: List[List[Literal]] = []
        for condition in rule.detection.parsed_condition:
            tree = condition.parsed
            normal = self._nnf(tree, False, product, warnings)
            conjunctions.extend(self._dnf(normal))
            if len(conjunctions) > self.options.max_split:
                raise WazuhConversionError(
                    f"Rule expands to more than {self.options.max_split} Wazuh rules. Simplify the condition or raise SIGMA_FORGE_WAZUH_MAX_SPLIT."
                )

        conjunctions = self._dedupe(conjunctions)
        prefix = self._prefix_literals(parent)
        level = LEVELS.get(rule.level.name.lower() if rule.level else "", 5)
        techniques, _ = split_attack_tags(rule.tags)
        blocks: List[str] = []
        ids: List[int] = []

        for conj in conjunctions:
            rule_id = self.next_id
            self.next_id += 1
            ids.append(rule_id)
            blocks.append(self._render_rule(rule, rule_id, level, parent, prefix + conj, techniques))

        if len(ids) > 1:
            warnings.append(f"OR logic was split into {len(ids)} Wazuh rules (ids {ids[0]} to {ids[-1]}).")
        if self._cidrs:
            warnings.append(f"CIDR values ({', '.join(dict.fromkeys(self._cidrs))}) became text prefix matches. Wazuh has no CIDR match for normal fields.")

        if not blocks:
            raise WazuhConversionError("Condition can never match, so no Wazuh rule was made")
        xml = '<group name="sigma,">\n' + "\n".join(blocks) + "\n</group>\n"
        return WazuhResult(xml=xml, rule_ids=ids, warnings=warnings)

    def _nnf(self, node, negated: bool, product: str, warnings: List[str]):
        if isinstance(node, ConditionNOT):
            return self._nnf(node.args[0], not negated, product, warnings)
        if isinstance(node, ConditionAND):
            kind = "or" if negated else "and"
            return (kind, [self._nnf(a, negated, product, warnings) for a in node.args])
        if isinstance(node, ConditionOR):
            kind = "and" if negated else "or"
            return self._merge((kind, [self._nnf(a, negated, product, warnings) for a in node.args]))
        if isinstance(node, ConditionFieldEqualsValueExpression):
            mapped, _ = map_field(node.field, product)
            return self._value_node(mapped, node.value, negated, warnings)
        if isinstance(node, ConditionValueExpression):
            return self._value_node(KEYWORD, node.value, negated, warnings)
        raise WazuhConversionError(f"Unsupported condition element: {type(node).__name__}")

    def _value_node(self, field_name, value, negated: bool, warnings: List[str]):
        if isinstance(value, SigmaExpansion):
            kind = "and" if negated else "or"
            return self._merge((kind, [self._value_node(field_name, v, negated, warnings) for v in value.values]))
        lit = self._literal(field_name, value, warnings)
        return ("lit", lit.flip() if negated else lit)

    @staticmethod
    def _merge(node):
        kind, children = node
        flat = []
        for child in children:
            if child[0] == kind:
                flat.extend(child[1])
            else:
                flat.append(child)
        if kind != "or":
            return (kind, flat)
        buckets: Dict[Optional[str], List[Literal]] = {}
        rest = []
        for child in flat:
            if child[0] == "lit" and not child[1].negated:
                buckets.setdefault(child[1].field, []).append(child[1])
            else:
                rest.append(child)
        merged = []
        for name, lits in buckets.items():
            lits = list(dict.fromkeys(lits))
            merged.append(("lit", lits[0] if len(lits) == 1 else WazuhBackend._union(name, lits)))
        out = merged + rest
        return out[0] if len(out) == 1 else ("or", out)

    @staticmethod
    def _union(name: Optional[str], lits: List[Literal]) -> Literal:
        bodies = [list(l.body) for l in lits]
        lead = all(b and b[0] == ".*" for b in bodies)
        trail = all(b and b[-1] == ".*" for b in bodies)
        same_case = len({l.insensitive for l in lits}) == 1
        alts = []
        for lit, body in zip(lits, bodies):
            core = body[1:] if lead else body
            core = core[:-1] if trail and core else core
            text = "".join(core)
            if not same_case:
                text = f"(?i:{text})" if lit.insensitive else f"(?-i:{text})"
            alts.append(text)
        tokens = ([".*"] if lead else []) + ["(?:" + "|".join(alts) + ")"] + ([".*"] if trail else [])
        return Literal(name, tuple(tokens), lits[0].insensitive if same_case else False, False)

    def _literal(self, field_name, value, warnings: List[str]) -> Literal:
        db = self.options.double_backslash
        if isinstance(value, SigmaString):
            insensitive = not isinstance(value, SigmaCasedString)
            return Literal(field_name, string_tokens(value, db), insensitive, False)
        if isinstance(value, SigmaNumber):
            return Literal(field_name, tuple(escape_literal(str(value.number), db)), False, False)
        if isinstance(value, SigmaBool):
            return Literal(field_name, ("true" if value.boolean else "false",), True, False)
        if isinstance(value, SigmaRegularExpression):
            flags = value.flags or set()
            inline = ""
            if SigmaRegularExpressionFlag.MULTILINE in flags:
                inline += "m"
            body = f"(?{inline}:{value.regexp})" if inline else f"(?:{value.regexp})"
            return Literal(field_name, (".*", body, ".*"), SigmaRegularExpressionFlag.IGNORECASE in flags, False)
        if isinstance(value, SigmaCIDRExpression):
            prefixes = value.expand(wildcard="*")
            alts = []
            for prefix in prefixes:
                tokens = string_tokens(SigmaString(prefix), db)
                alts.append("".join(tokens))
            self._cidrs.append(str(value.cidr))
            return Literal(field_name, ("(?:" + "|".join(alts) + ")",), False, False)
        if isinstance(value, SigmaExists):
            return Literal(field_name, (".+",), False, not value.exists)
        if isinstance(value, SigmaNull):
            return Literal(field_name, (".+",), False, True)
        if isinstance(value, SigmaCompareExpression):
            raise WazuhConversionError("Number compare modifiers (lt, lte, gt, gte) are not supported by Wazuh field matching")
        if isinstance(value, SigmaFieldReference):
            raise WazuhConversionError("Field reference modifier (fieldref) is not supported by Wazuh")
        raise WazuhConversionError(f"Unsupported value type: {type(value).__name__}")

    def _dnf(self, node) -> List[List[Literal]]:
        kind = node[0]
        if kind == "lit":
            return [[node[1]]]
        parts = [self._dnf(child) for child in node[1]]
        if kind == "or":
            out: List[List[Literal]] = []
            for p in parts:
                out.extend(p)
                if len(out) > self.options.max_split:
                    raise WazuhConversionError(f"Rule expands to more than {self.options.max_split} Wazuh rules")
            return out
        total = 1
        for p in parts:
            total *= max(len(p), 1)
            if total > self.options.max_split:
                raise WazuhConversionError(f"Rule expands to more than {self.options.max_split} Wazuh rules")
        out = []
        for combo in cartesian(*parts):
            merged: List[Literal] = []
            for group in combo:
                merged.extend(group)
            out.append(merged)
        return out

    @staticmethod
    def _dedupe(conjunctions: List[List[Literal]]) -> List[List[Literal]]:
        seen = set()
        result = []
        for conj in conjunctions:
            unique = list(dict.fromkeys(conj))
            pos = {(l.field, l.body, l.insensitive) for l in unique if not l.negated}
            neg = {(l.field, l.body, l.insensitive) for l in unique if l.negated}
            if pos & neg:
                continue
            key = frozenset(unique)
            if key in seen:
                continue
            seen.add(key)
            result.append(unique)
        return result

    def _prefix_literals(self, parent) -> List[Literal]:
        out: List[Literal] = []
        if parent.channel:
            out.append(Literal("win.system.channel", tuple(escape_literal(parent.channel, False)), True, False))
        if parent.event_ids:
            if len(parent.event_ids) == 1:
                body = (str(parent.event_ids[0]),)
            else:
                body = ("(?:" + "|".join(str(i) for i in parent.event_ids) + ")",)
            out.append(Literal("win.system.eventID", body, False, False))
        return out

    @staticmethod
    def _wrap(lit: Literal) -> str:
        core = "".join(lit.body)
        return f"(?i:{core})" if lit.insensitive else f"(?:{core})"

    def _field_regex(self, literals: List[Literal]) -> Tuple[str, bool]:
        positives = [l for l in literals if not l.negated]
        negatives = [l for l in literals if l.negated]

        if len(positives) == 1 and not negatives:
            lit = positives[0]
            body = list(lit.body)
            start, end = "^", "$"
            if body and body[0] == ".*":
                body = body[1:]
                start = ""
            if body and body[-1] == ".*":
                body = body[:-1]
                end = ""
            flags = "(?is)" if lit.insensitive else "(?s)"
            return f"{flags}{start}{''.join(body)}{end}", False

        if not positives:
            alts = "|".join(self._wrap(l) for l in negatives)
            return f"(?s)^(?:{alts})$", True

        parts = "".join(f"(?={self._wrap(l)}$)" for l in positives)
        parts += "".join(f"(?!{self._wrap(l)}$)" for l in negatives)
        return f"(?s)^{parts}", False

    def _render_rule(self, rule: SigmaRule, rule_id: int, level: int, parent, literals: List[Literal], techniques: List[str]) -> str:
        groups: Dict[Optional[str], List[Literal]] = {}
        for lit in literals:
            groups.setdefault(lit.field, []).append(lit)

        lines = [f'  <rule id="{rule_id}" level="{level}">']
        if self.options.parent_group and parent.group:
            lines.append(f"    <if_group>{parent.group}</if_group>")

        for name in sorted((k for k in groups if k is not None), key=lambda k: (not k.startswith("win.system"), k)):
            regex, negate = self._field_regex(groups[name])
            neg = ' negate="yes"' if negate else ""
            lines.append(f'    <field name="{xml_escape(name, {chr(34): "&quot;"})}" type="pcre2"{neg}>{xml_escape(regex)}</field>')

        if KEYWORD in groups:
            regex, negate = self._field_regex(groups[KEYWORD])
            neg = ' negate="yes"' if negate else ""
            lines.append(f'    <regex type="pcre2"{neg}>{xml_escape(regex)}</regex>')

        lines.append(f"    <description>Sigma: {xml_escape(rule.title or 'untitled')}</description>")
        if rule.id:
            lines.append(f'    <info type="text">Sigma rule id {xml_escape(str(rule.id))}</info>')
        if techniques:
            lines.append("    <mitre>")
            for tid in techniques:
                lines.append(f"      <id>{tid}</id>")
            lines.append("    </mitre>")
        level_name = rule.level.name.lower() if rule.level else "unknown"
        lines.append(f"    <group>sigma,sigma_{level_name},</group>")
        lines.append("  </rule>")
        return "\n".join(lines)
