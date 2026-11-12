import re
import uuid
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

import yaml

LANGS = {
    "auto": "Detect it for me",
    "splunk": "Splunk SPL",
    "kql": "Microsoft Sentinel / Defender KQL",
    "lucene": "Elastic Lucene / Kibana query",
    "eql": "Elastic EQL",
    "esql": "Elastic ES|QL",
}


class QueryError(ValueError):
    pass


FIELD_MAP = {
    "process.command_line": ("CommandLine", ""),
    "process.args": ("CommandLine", "args"),
    "process.executable": ("Image", ""),
    "process.name": ("Image", "name"),
    "process.parent.executable": ("ParentImage", ""),
    "process.parent.name": ("ParentImage", "name"),
    "process.parent.command_line": ("ParentCommandLine", ""),
    "process.pe.original_file_name": ("OriginalFileName", ""),
    "process.working_directory": ("CurrentDirectory", ""),
    "process.pid": ("ProcessId", ""),
    "user.name": ("User", ""),
    "host.name": ("Computer", ""),
    "host.hostname": ("Computer", ""),
    "event.code": ("EventID", ""),
    "winlog.event_id": ("EventID", ""),
    "winlog.channel": ("Channel", ""),
    "winlog.provider_name": ("Provider_Name", ""),
    "file.path": ("TargetFilename", ""),
    "file.name": ("TargetFilename", "name"),
    "registry.path": ("TargetObject", ""),
    "registry.key": ("TargetObject", ""),
    "registry.data.strings": ("Details", ""),
    "destination.ip": ("DestinationIp", ""),
    "destination.port": ("DestinationPort", ""),
    "destination.domain": ("DestinationHostname", ""),
    "source.ip": ("SourceIp", ""),
    "source.port": ("SourcePort", ""),
    "dns.question.name": ("QueryName", ""),
    "powershell.file.script_block_text": ("ScriptBlockText", ""),
    "dll.path": ("ImageLoaded", ""),
    "dll.name": ("ImageLoaded", "name"),
    "url.original": ("c-uri", ""),
    "process": ("CommandLine", ""),
    "process_name": ("Image", "name"),
    "process_path": ("Image", ""),
    "process_exec": ("Image", "name"),
    "parent_process": ("ParentCommandLine", ""),
    "parent_process_name": ("ParentImage", "name"),
    "parent_process_path": ("ParentImage", ""),
    "parent_process_exec": ("ParentImage", "name"),
    "original_file_name": ("OriginalFileName", ""),
    "user": ("User", ""),
    "dest": ("Computer", ""),
    "eventcode": ("EventID", ""),
    "file_path": ("TargetFilename", ""),
    "file_name": ("TargetFilename", "name"),
    "registry_path": ("TargetObject", ""),
    "registry_value_data": ("Details", ""),
    "query": ("QueryName", ""),
    "dest_ip": ("DestinationIp", ""),
    "dest_port": ("DestinationPort", ""),
    "src_ip": ("SourceIp", ""),
    "newprocessname": ("Image", ""),
    "parentprocessname": ("ParentImage", ""),
    "processcommandline": ("CommandLine", ""),
    "folderpath": ("Image", ""),
    "filename": ("Image", "name"),
    "initiatingprocessfolderpath": ("ParentImage", ""),
    "initiatingprocessfilename": ("ParentImage", "name"),
    "initiatingprocesscommandline": ("ParentCommandLine", ""),
    "processversioninfooriginalfilename": ("OriginalFileName", ""),
    "accountname": ("User", ""),
    "devicename": ("Computer", ""),
    "remoteip": ("DestinationIp", ""),
    "remoteport": ("DestinationPort", ""),
    "remoteurl": ("DestinationHostname", ""),
    "registrykey": ("TargetObject", ""),
    "registryvaluedata": ("Details", ""),
    "eventid": ("EventID", ""),
    "event_id": ("EventID", ""),
    "channel": ("Channel", ""),
}

META_FIELDS = {
    "index", "sourcetype", "source", "host", "earliest", "latest", "_time", "_index", "timegenerated", "timestamp",
    "@timestamp", "type", "event.category", "event.type", "event.dataset", "event.module", "event.kind",
    "data_stream.dataset", "data_stream.type", "data_stream.namespace", "tenantid", "sourcesystem", "_resourceid",
    "eventsourcename", "actiontype", "eventtype", "agent.type", "ecs.version",
}

SYSMON_IDS = {1: "process_creation", 3: "network_connection", 7: "image_load", 8: "create_remote_thread", 10: "process_access",
              11: "file_event", 12: "registry_event", 13: "registry_set", 14: "registry_event", 15: "create_stream_hash",
              17: "pipe_created", 22: "dns_query", 23: "file_delete", 6: "driver_load"}

CATEGORY_FIELDS = [
    ("ps_script", {"ScriptBlockText"}),
    ("registry_set", {"TargetObject", "Details"}),
    ("dns_query", {"QueryName"}),
    ("image_load", {"ImageLoaded"}),
    ("network_connection", {"DestinationIp", "DestinationPort", "DestinationHostname", "SourceIp"}),
    ("process_creation", {"CommandLine", "ParentImage", "ParentCommandLine", "OriginalFileName", "CurrentDirectory"}),
    ("file_event", {"TargetFilename"}),
    ("process_creation", {"Image"}),
]

TABLES = {
    "deviceprocessevents": ("windows", "", "process_creation"),
    "devicenetworkevents": ("windows", "", "network_connection"),
    "devicefileevents": ("windows", "", "file_event"),
    "deviceregistryevents": ("windows", "", "registry_event"),
    "deviceimageloadevents": ("windows", "", "image_load"),
    "securityevent": ("windows", "security", ""),
    "windowsevent": ("windows", "", ""),
    "sysmonevent": ("windows", "sysmon", ""),
    "event": ("windows", "", ""),
}

EQL_CATEGORIES = {"process": "process_creation", "network": "network_connection", "file": "file_event",
                  "registry": "registry_set", "library": "image_load", "dns": "dns_query"}

CHANNEL_SERVICE = {
    "security": "security", "system": "system", "application": "application",
    "microsoft-windows-powershell/operational": "powershell", "windows powershell": "powershell-classic",
    "microsoft-windows-sysmon/operational": "sysmon", "microsoft-windows-windows defender/operational": "windefend",
    "microsoft-windows-taskscheduler/operational": "taskscheduler",
}

WORD_OPS = {
    "contains": ("contains", False, False), "contains_cs": ("contains", False, True), "has": ("contains", False, False),
    "has_cs": ("contains", False, True), "startswith": ("startswith", False, False), "startswith_cs": ("startswith", False, True),
    "hasprefix": ("startswith", False, False), "endswith": ("endswith", False, False), "endswith_cs": ("endswith", False, True),
    "hassuffix": ("endswith", False, False), "has_any": ("contains", False, False), "has_all": ("contains_all", False, False),
    "in": ("in", False, False), "in~": ("in", False, False), "like": ("like", False, False), "like~": ("like", False, False),
    "rlike": ("re", False, False), "regex": ("re", False, False), "regex~": ("re", False, False), "matches": ("re", False, False),
    "notcontains": ("contains", True, False), "notcontains_cs": ("contains", True, True),
}

FUNCS = {"like", "match", "isnull", "isnotnull", "isempty", "isnotempty", "not", "startswith", "endswith", "contains",
         "searchmatch", "cidrmatch", "ipv4_is_in_range", "wildcard", "match_regex"}


class Tok:
    __slots__ = ("kind", "text", "space", "quoted")

    def __init__(self, kind, text, space=False, quoted=False):
        self.kind, self.text, self.space, self.quoted = kind, text, space, quoted

    def __repr__(self):
        return f"{self.kind}:{self.text}"


FIELDISH = re.compile(r"^[A-Za-z_@][\w.@\-]*$")
SPLIT_PIPE = re.compile(r"""\|(?=(?:[^"']|"[^"]*"|'[^']*')*$)""")


def _unquote(body: str, verbatim: bool) -> str:
    if verbatim:
        return body.replace('""', '"')
    return re.sub(r"\\([\"'\\])", r"\1", body)


def tokenize(text: str, lang: str) -> List[Tok]:
    toks: List[Tok] = []
    i, n = 0, len(text)
    value_next = False
    vdepth = 0
    space = False
    while i < n:
        c = text[i]
        if c.isspace():
            space = True
            i += 1
            continue
        if c == "@" and i + 1 < n and text[i + 1] == '"':
            j = i + 2
            buf = []
            while j < n:
                if text[j] == '"' and j + 1 < n and text[j + 1] == '"':
                    buf.append('"')
                    j += 2
                    continue
                if text[j] == '"':
                    break
                buf.append(text[j])
                j += 1
            toks.append(Tok("STR", "".join(buf), space, True))
            i, space = j + 1, False
            value_next = vdepth > 0
            continue
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            toks.append(Tok("STR", _unquote(text[i + 1:j], False), space, True))
            i, space = j + 1, False
            value_next = vdepth > 0
            continue
        if c == "(":
            toks.append(Tok("LP", "(", space))
            if vdepth:
                vdepth += 1
            elif value_next:
                vdepth = 1
            i, space = i + 1, False
            continue
        if c == ")":
            toks.append(Tok("RP", ")", space))
            if vdepth:
                vdepth -= 1
                value_next = vdepth > 0
            i, space = i + 1, False
            continue
        if c == ",":
            toks.append(Tok("COMMA", ",", space))
            i, space = i + 1, False
            continue
        two = text[i:i + 2]
        if not value_next and two in ("==", "!=", "=~", "!~", ">=", "<="):
            toks.append(Tok("OP", two, space))
            i, space, value_next = i + 2, False, True
            continue
        if not value_next and c in "=<>":
            toks.append(Tok("OP", c, space))
            i, space, value_next = i + 1, False, True
            continue
        if not value_next and c == ":" and toks and toks[-1].kind == "WORD" and (not space or (lang in ("eql", "lucene") and FIELDISH.match(toks[-1].text))):
            toks.append(Tok("OP", ":", space))
            i, space, value_next = i + 1, False, True
            continue
        j = i
        buf = []
        while j < n:
            ch = text[j]
            if ch == "\\" and j + 1 < n:
                buf.append(text[j:j + 2])
                j += 2
                continue
            if ch.isspace() or ch in "()\"'," or (ch == "@" and j + 1 < n and text[j + 1] == '"' and j == i):
                break
            if not value_next and ch in "=<>" and j > i:
                break
            if not value_next and ch == "!" and j > i:
                break
            if not value_next and ch == ":" and j > i and FIELDISH.match("".join(buf)):
                break
            buf.append(ch)
            j += 1
        word = "".join(buf)
        if not word:
            raise QueryError(f"Could not read the query near: {text[i:i + 20]}")
        toks.append(Tok("WORD", word, space))
        i, space = j, False
        if value_next and not vdepth:
            value_next = False
        elif not value_next and word.lower() in WORD_OPS or word.lower().lstrip("!") in WORD_OPS:
            value_next = True
    return toks


class Parser:
    def __init__(self, toks: List[Tok], lang: str):
        self.t = toks
        self.i = 0
        self.lang = lang
        self.warnings: List[str] = []

    def peek(self, k=0) -> Optional[Tok]:
        j = self.i + k
        return self.t[j] if j < len(self.t) else None

    def take(self) -> Tok:
        tok = self.t[self.i]
        self.i += 1
        return tok

    def kw(self, tok: Optional[Tok], *names) -> bool:
        return tok is not None and tok.kind == "WORD" and tok.text.upper() in names

    def parse(self):
        node = self.or_()
        if self.i < len(self.t):
            rest = " ".join(t.text for t in self.t[self.i:self.i + 6])
            raise QueryError(f"Did not understand the query near: {rest}")
        return node

    def or_(self):
        parts = [self.and_()]
        while self.kw(self.peek(), "OR") or (self.peek() and self.peek().kind == "WORD" and self.peek().text == "||"):
            self.take()
            parts.append(self.and_())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def and_(self):
        parts = [self.not_()]
        while True:
            tok = self.peek()
            if tok is None or tok.kind in ("RP", "COMMA") or self.kw(tok, "OR") or tok.text == "||":
                break
            if self.kw(tok, "AND") or tok.text == "&&":
                self.take()
            parts.append(self.not_())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def not_(self):
        tok = self.peek()
        if self.kw(tok, "NOT") and not (self.peek(1) and self.peek(1).kind == "LP" and not self.peek(1).space and tok.text == "not" and False):
            self.take()
            return ("not", self.not_())
        if tok and tok.kind == "WORD" and tok.text.startswith("-") and len(tok.text) > 1 and self.lang == "lucene":
            tok.text = tok.text[1:]
            return ("not", self.primary())
        return self.primary()

    def primary(self):
        tok = self.peek()
        if tok is None:
            raise QueryError("The query ends too early")
        if tok.kind == "LP":
            self.take()
            node = self.or_()
            self.expect("RP")
            return node
        if tok.kind == "WORD" and self.peek(1) and self.peek(1).kind == "LP" and not self.peek(1).space and tok.text.lower() in FUNCS:
            return self.func()
        if tok.kind == "WORD" and not tok.quoted:
            nxt = self.peek(1)
            if nxt and nxt.kind == "OP":
                return self.comparison()
            if nxt and nxt.kind == "WORD" and self._word_op(nxt) is not None:
                return self.comparison()
            if nxt and self.kw(nxt, "IS"):
                return self.comparison()
            if nxt and self.kw(nxt, "NOT") and self.peek(2) and self._word_op(self.peek(2)) is not None:
                return self.comparison()
        if tok.kind in ("WORD", "STR"):
            self.take()
            if tok.text.upper() == "_EXISTS_":
                return ("leaf", {"field": "", "mod": "exists", "values": [True]})
            return ("kw", tok.text)
        raise QueryError(f"Did not expect '{tok.text}' here")

    def expect(self, kind):
        tok = self.peek()
        if tok is None or tok.kind != kind:
            raise QueryError(f"Missing a closing bracket near token {self.i + 1}")
        return self.take()

    def _word_op(self, tok: Tok):
        if tok.kind != "WORD" or tok.quoted:
            return None
        low = tok.text.lower()
        neg = low.startswith("!")
        base = low.lstrip("!")
        if base in WORD_OPS:
            mod, extra_neg, cs = WORD_OPS[base]
            return mod, neg or extra_neg, cs
        return None

    def values(self) -> Tuple[List[Any], bool]:
        tok = self.peek()
        if tok and tok.kind == "LP":
            self.take()
            vals = []
            while self.peek() and self.peek().kind != "RP":
                t = self.take()
                if t.kind == "COMMA":
                    continue
                vals.append(self._value(t))
            self.expect("RP")
            return vals, True
        t = self.take()
        if t.kind == "WORD" and self.peek() and self.peek().kind == "LP" and not self.peek().space:
            depth = 0
            text = t.text
            while self.peek():
                x = self.take()
                text += x.text
                if x.kind == "LP":
                    depth += 1
                elif x.kind == "RP":
                    depth -= 1
                    if depth == 0:
                        break
            return [{"func": text}], False
        return [self._value(t)], False

    def _value(self, t: Tok):
        if t.kind not in ("WORD", "STR"):
            raise QueryError(f"Expected a value but found '{t.text}'")
        if t.quoted:
            return {"text": t.text, "quoted": True}
        text = t.text
        if self.lang == "lucene":
            text = re.sub(r"\\([^*?])", r"\1", text)
        elif self.lang == "splunk":
            text = text.replace("\\\\", "\\")
        return {"text": text, "quoted": False}

    def comparison(self):
        field = self.take().text
        tok = self.take()
        neg = False
        if self.kw(tok, "IS"):
            if self.kw(self.peek(), "NOT"):
                self.take()
                neg = True
            nul = self.take()
            if not self.kw(nul, "NULL"):
                raise QueryError("Expected NULL after IS")
            leaf = ("leaf", {"field": field, "mod": "exists", "values": [True]})
            return leaf if neg else ("not", leaf)
        if self.kw(tok, "NOT"):
            neg = True
            tok = self.take()
        if tok.kind == "OP":
            op = tok.text
            if op == ":" and self.peek() and self.peek().kind == "LP":
                return self.value_group(field)
            vals, _ = self.values()
            if op in ("!=", "!~"):
                neg = True
            if op in (">", "<", ">=", "<="):
                mod = {">": "gt", "<": "lt", ">=": "gte", "<=": "lte"}[op]
            elif op in ("=", ":", "!="):
                mod = "wild"
            else:
                mod = "eq"
            if self.lang in ("kql",) and op in ("=",):
                mod = "eq"
            leaf = ("leaf", {"field": field, "mod": mod, "values": vals})
            return ("not", leaf) if neg else leaf
        info = self._word_op(tok)
        if info is None:
            raise QueryError(f"Unknown operator '{tok.text}'")
        mod, wneg, cs = info
        if mod == "re" and self.kw(self.peek(), "REGEX"):
            self.take()
        vals, _ = self.values()
        neg = neg or wneg
        if mod == "in":
            mod = "wild" if self.lang in ("splunk", "lucene") else "eq"
        elif mod == "like":
            mod = "like"
        leaf = {"field": field, "mod": mod, "values": vals}
        if mod == "contains_all":
            leaf.update(mod="contains", all=True)
        if cs:
            leaf["cs"] = True
        return ("not", ("leaf", leaf)) if neg else ("leaf", leaf)

    def value_group(self, field):
        self.take()
        node = self._vg_or(field)
        self.expect("RP")
        return node

    def _vg_or(self, field):
        parts = [self._vg_and(field)]
        while self.kw(self.peek(), "OR") or (self.peek() and self.peek().kind == "COMMA"):
            self.take()
            parts.append(self._vg_and(field))
        return parts[0] if len(parts) == 1 else ("or", parts)

    def _vg_and(self, field):
        parts = [self._vg_not(field)]
        while self.peek() and self.peek().kind not in ("RP", "COMMA") and not self.kw(self.peek(), "OR"):
            if self.kw(self.peek(), "AND"):
                self.take()
            parts.append(self._vg_not(field))
        return parts[0] if len(parts) == 1 else ("and", parts)

    def _vg_not(self, field):
        if self.kw(self.peek(), "NOT"):
            self.take()
            return ("not", self._vg_not(field))
        if self.peek() and self.peek().kind == "LP":
            self.take()
            node = self._vg_or(field)
            self.expect("RP")
            return node
        return ("leaf", {"field": field, "mod": "wild", "values": [self._value(self.take())]})

    def func(self):
        name = self.take().text.lower()
        self.expect("LP")
        args: List[List[Tok]] = [[]]
        depth = 0
        while self.peek():
            t = self.peek()
            if t.kind == "LP":
                depth += 1
            elif t.kind == "RP":
                if depth == 0:
                    break
                depth -= 1
            elif t.kind == "COMMA" and depth == 0:
                self.take()
                args.append([])
                continue
            args[-1].append(self.take())
        self.expect("RP")
        if name == "not":
            inner = Parser([t for a in args for t in a], self.lang)
            node = inner.parse()
            self.warnings += inner.warnings
            return ("not", node)
        first = args[0][0].text if args and args[0] else ""
        second = args[1][0] if len(args) > 1 and args[1] else None
        if name in ("isnotnull", "isnotempty"):
            return ("leaf", {"field": first, "mod": "exists", "values": [True]})
        if name in ("isnull", "isempty"):
            return ("not", ("leaf", {"field": first, "mod": "exists", "values": [True]}))
        if second is None:
            self.warnings.append(f"Skipped function {name}(): it needs two values")
            return ("drop", name)
        val = {"text": second.text, "quoted": second.quoted}
        if name == "like":
            return ("leaf", {"field": first, "mod": "like", "values": [val]})
        if name in ("match", "match_regex"):
            return ("leaf", {"field": first, "mod": "re", "values": [val]})
        if name == "wildcard":
            return ("leaf", {"field": first, "mod": "wild", "values": [val]})
        if name in ("startswith", "endswith", "contains"):
            return ("leaf", {"field": first, "mod": name, "values": [val]})
        if name in ("cidrmatch", "ipv4_is_in_range"):
            if name == "cidrmatch":
                first, val = second.text, {"text": args[0][0].text if args[0] else "", "quoted": True}
            return ("leaf", {"field": first, "mod": "cidr", "values": [val]})
        self.warnings.append(f"Skipped function {name}()")
        return ("drop", name)


def detect(query: str) -> str:
    q = query.strip()
    low = q.lower()
    if re.match(r"^from\s+\S+", low) and re.search(r"\|\s*where\b", low):
        return "esql"
    if re.match(r"^(any|process|network|file|registry|library|dns|sequence)\s+(where|by)\b", low) or low.startswith("sequence"):
        return "eql"
    if re.search(r"\|\s*where\b", low) and (re.search(r"==|=~|\bhas\b|\bcontains\b|\bin~?\s*\(|\bstartswith\b|\bendswith\b", low)) and not re.search(r"\b(index|sourcetype)\s*=", low):
        return "kql"
    if re.match(r"^[A-Za-z_]\w*\s*(\||$)", q) and not re.search(r"[=:]", q.split("|")[0]):
        return "kql"
    if re.search(r"\b(index|sourcetype|source|eventcode)\s*=", low) or re.search(r"\|\s*(search|stats|table|eval|rex)\b", low):
        return "splunk"
    if re.search(r"[\w.]+\s*:\s*", q) and not re.search(r"(?<![=!<>])=(?!=)", q.replace("\\=", "")):
        return "lucene"
    return "splunk"


def _pipes(query: str) -> List[str]:
    return [p.strip() for p in SPLIT_PIPE.split(query.replace("\r", " ").replace("\n", " "))]


def extract(query: str, lang: str) -> Tuple[str, Dict[str, Any], List[str]]:
    hints: Dict[str, Any] = {}
    warnings: List[str] = []
    q = query.strip()
    if lang == "eql":
        m = re.match(r"^\s*(\w+)\s+where\s+(.*)$", q, re.S | re.I)
        if not m:
            raise QueryError("EQL sequences are not supported yet. Paste a single 'category where ...' query.")
        hints["eql_category"] = m.group(1).lower()
        return m.group(2), hints, warnings
    parts = _pipes(q)
    filters: List[str] = []
    if lang in ("kql", "esql"):
        head = parts[0]
        if lang == "esql":
            m = re.match(r"^from\s+(.+)$", head, re.I)
            hints["index"] = m.group(1).strip() if m else ""
        elif re.match(r"^[A-Za-z_]\w*$", head):
            hints["table"] = head
        elif head:
            filters.append(re.sub(r"^search\s+", "", head, flags=re.I))
        for p in parts[1:]:
            m = re.match(r"^(where|search|filter)\s+(.*)$", p, re.I | re.S)
            if m:
                filters.append(m.group(2))
            elif p:
                warnings.append(f"Ignored the step: {p.split()[0]}")
    else:
        if lang == "splunk":
            head = re.sub(r"^search\s+", "", parts[0], flags=re.I)
            macros = re.findall(r"`([^`]+)`", head)
            if macros:
                hints.setdefault("meta", {}).setdefault("macro", []).extend(macros)
                head = re.sub(r"`[^`]+`", " ", head).strip()
            if head:
                filters.append(head)
            for p in parts[1:]:
                m = re.match(r"^(search|where)\s+(.*)$", p, re.I | re.S)
                if m:
                    filters.append(m.group(2))
                elif p:
                    warnings.append(f"Ignored the step: {p.split()[0]}")
        else:
            filters.append(q)
    if not filters:
        raise QueryError("No filter found in the query. Add a where clause or search terms.")
    text = " AND ".join(f"({f})" for f in filters) if len(filters) > 1 else filters[0]
    return text, hints, warnings


def _shape(text: str, escapes: bool = True) -> Tuple[str, str]:
    if text == "*":
        return "exists", ""
    if not escapes:
        text = text.replace("\\*", "\\\\*").replace("\\?", "\\\\?")
        if text.endswith("\\\\*") and text.startswith("*") and "*" not in text[1:-3] and "?" not in text:
            return "contains", text[1:-2]
        if text.endswith("\\\\*") and "*" not in text[:-3] and "?" not in text:
            return "startswith", text[:-2]
    stars = [m.start() for m in re.finditer(r"(?<!\\)\*", text)]
    if not stars and not re.search(r"(?<!\\)\?", text):
        return "eq", text
    inner_lead = text.startswith("*")
    inner_tail = text.endswith("*") and not text.endswith("\\*")
    core = text[1 if inner_lead else 0: len(text) - (1 if inner_tail else 0)]
    if not re.search(r"(?<!\\)[*?]", core) and core:
        if inner_lead and inner_tail:
            return "contains", core
        if inner_lead:
            return "endswith", core
        if inner_tail:
            return "startswith", core
    return "eq", text


def _escape_wild(text: str) -> str:
    return re.sub(r"([*?])", r"\\\1", text)


def _num(text: str):
    if re.fullmatch(r"-?\d+", text):
        try:
            return int(text)
        except ValueError:
            return text
    return text


def normalize(node, warnings: List[str], escapes: bool = True):
    kind = node[0]
    if kind in ("and", "or"):
        kids = []
        for k in node[1]:
            nk = normalize(k, warnings, escapes)
            if nk[0] == kind:
                kids.extend(nk[1])
            else:
                kids.append(nk)
        kids = [k for k in kids if k[0] != "drop"]
        if not kids:
            return ("drop", "empty")
        if kind == "or" and len(kids) < len(node[1]):
            warnings.append("Removed a part of an OR group that could not be converted. Check the logic.")
        return kids[0] if len(kids) == 1 else (kind, kids)
    if kind == "not":
        inner = normalize(node[1], warnings, escapes)
        return inner if inner[0] == "drop" else ("not", inner)
    if kind == "kw":
        return ("leaf", {"field": "", "mod": "kw", "values": [node[1]]})
    if kind == "drop":
        return node
    leaf = dict(node[1])
    if any(isinstance(v, dict) and "func" in v for v in leaf["values"]):
        warnings.append(f"Skipped {leaf['field']}: it uses a function value")
        return ("drop", leaf["field"])
    if leaf["mod"] == "exists":
        return ("leaf", leaf)
    raw = [v if not isinstance(v, dict) else v for v in leaf["values"]]
    mod = leaf["mod"]
    groups: Dict[str, List[Any]] = {}
    for v in raw:
        text = v["text"] if isinstance(v, dict) else str(v)
        quoted = v.get("quoted") if isinstance(v, dict) else False
        if mod == "like":
            t = text
            if "%" in t or "_" in t and "*" not in t:
                t = _escape_wild(t).replace("%", "*").replace("_", "?")
            shape, val = _shape(t, escapes)
        elif mod == "wild":
            shape, val = _shape(text, escapes)
        elif mod == "eq":
            shape, val = "eq", _escape_wild(text)
        elif mod in ("contains", "startswith", "endswith"):
            shape, val = mod, _escape_wild(text)
        elif mod in ("gt", "gte", "lt", "lte"):
            n = _num(text)
            if not isinstance(n, int):
                warnings.append(f"Skipped {leaf['field']} {mod} {text}: not a number")
                continue
            shape, val = mod, n
        else:
            shape, val = mod, text
        if shape == "eq" and not quoted:
            val = _num(val)
        groups.setdefault(shape, []).append(val)
    if not groups:
        return ("drop", leaf["field"])
    leaves = []
    for shape, vals in groups.items():
        nl = {k: v for k, v in leaf.items() if k not in ("values", "mod")}
        nl["mod"] = shape
        nl["values"] = [True] if shape == "exists" else vals
        leaves.append(("leaf", nl))
    if leaf.get("all") and len(leaves) > 1:
        return ("and", leaves)
    return leaves[0] if len(leaves) == 1 else ("or", leaves)


def map_fields(node, mapped: Dict[str, str], hints: Dict[str, Any]):
    kind = node[0]
    if kind in ("and", "or"):
        kids = [map_fields(k, mapped, hints) for k in node[1]]
        kids = [k for k in kids if k[0] != "drop"]
        if not kids:
            return ("drop", "meta")
        return kids[0] if len(kids) == 1 else (kind, kids)
    if kind == "not":
        inner = map_fields(node[1], mapped, hints)
        return inner if inner[0] == "drop" else ("not", inner)
    if kind != "leaf":
        return node
    leaf = dict(node[1])
    field = leaf["field"]
    low = field.lower()
    if low in META_FIELDS:
        hints.setdefault("meta", {}).setdefault(low, []).extend(str(v) for v in leaf["values"])
        return ("drop", "meta")
    if low.startswith("winlog.event_data."):
        target, kind_ = field.split(".", 2)[2], ""
    elif low in FIELD_MAP:
        target, kind_ = FIELD_MAP[low]
    else:
        target, kind_ = field, ""
    if target != field and field:
        mapped[field] = target
    leaf["field"] = target
    if kind_ == "name":
        vals = []
        for v in leaf["values"]:
            s = str(v)
            vals.append(s if s.startswith("\\") or leaf["mod"] in ("re", "exists") else "\\" + s)
        if leaf["mod"] == "eq":
            leaf.update(mod="endswith", values=vals)
        elif leaf["mod"] == "startswith":
            leaf.update(mod="contains", values=vals)
    if kind_ == "args" and leaf["mod"] == "eq":
        leaf["mod"] = "contains"
    return ("leaf", leaf)


def _leaves(node, out, neg=False):
    if node[0] == "leaf":
        out.append((node[1], neg))
    elif node[0] == "not":
        _leaves(node[1], out, not neg)
    elif node[0] in ("and", "or"):
        for k in node[1]:
            _leaves(k, out, neg)


def guess_logsource(node, hints: Dict[str, Any], lang: str) -> Tuple[Dict[str, str], Optional[int]]:
    leaves: List[Tuple[Dict, bool]] = []
    _leaves(node, leaves)
    fields = {l["field"] for l, _ in leaves}
    meta = hints.get("meta", {})
    event_ids = [v for l, n in leaves if l["field"] == "EventID" and not n and l["mod"] == "eq" for v in l["values"]]
    channels = [str(v).lower() for l, n in leaves if l["field"] == "Channel" and not n for v in l["values"]]
    text_meta = " ".join(" ".join(v) for v in meta.values()).lower() + " " + str(hints.get("index", "")).lower()
    product, service, category = "", "", ""
    table = str(hints.get("table", "")).lower()
    if table in TABLES:
        product, service, category = TABLES[table]
    if hints.get("eql_category") in EQL_CATEGORIES:
        product, category = "windows", EQL_CATEGORIES[hints["eql_category"]]
    for c in channels:
        if c in CHANNEL_SERVICE:
            product, service = "windows", CHANNEL_SERVICE[c]
    if "sysmon" in text_meta:
        product, service = "windows", service or "sysmon"
    elif "wineventlog:security" in text_meta or "wineventlog security" in text_meta:
        product, service = "windows", service or "security"
    elif "powershell" in text_meta:
        product = "windows"
    for cat in meta.get("event.category", []):
        if cat.lower() in EQL_CATEGORIES and not category:
            product, category = "windows", EQL_CATEGORIES[cat.lower()]
    drop_id = None
    ids = [v for v in event_ids if isinstance(v, int)]
    if not category and ids:
        eid = ids[0]
        if service == "sysmon" or (eid in SYSMON_IDS and service != "security" and fields & {"Image", "CommandLine", "TargetFilename", "TargetObject", "QueryName", "DestinationIp", "ImageLoaded"}):
            if eid in SYSMON_IDS:
                category, product = SYSMON_IDS[eid], "windows"
                drop_id = eid
        elif eid == 4688:
            category, product, drop_id = "process_creation", "windows", 4688
        elif eid == 4104:
            category, product, drop_id = "ps_script", "windows", 4104
        elif eid == 4103:
            category, product, drop_id = "ps_module", "windows", 4103
        elif 4600 <= eid < 5200 or eid in (1102,):
            product, service = "windows", service or "security"
        elif eid in (7045, 7036, 7040, 104):
            product, service = "windows", service or "system"
    elif category and ids:
        expected = {v: k for k, v in SYSMON_IDS.items()}.get(category)
        if ids[0] in (expected, 4688 if category == "process_creation" else -1, 4104 if category == "ps_script" else -1):
            drop_id = ids[0]
    if not category and not service:
        for cat, keys in CATEGORY_FIELDS:
            if fields & keys:
                category, product = cat, product or "windows"
                break
    if category:
        service = ""
    ls = {}
    if category:
        ls["category"] = category
    if product:
        ls["product"] = product
    if service:
        ls["service"] = service
    return ls, drop_id


def drop_fields(node, should_drop):
    kind = node[0]
    if kind in ("and", "or"):
        kids = [drop_fields(k, should_drop) for k in node[1]]
        kids = [k for k in kids if k[0] != "drop"]
        if not kids:
            return ("drop", "x")
        return kids[0] if len(kids) == 1 else (kind, kids)
    if kind == "not":
        inner = drop_fields(node[1], should_drop)
        return inner if inner[0] == "drop" else ("not", inner)
    if kind == "leaf" and should_drop(node[1]):
        return ("drop", "x")
    return node


class Builder:
    def __init__(self):
        self.det: Dict[str, Any] = {}
        self.counts = {"selection": 0, "filter": 0, "keywords": 0}

    def name(self, base):
        self.counts[base] += 1
        n = self.counts[base]
        if base == "selection":
            return "selection" if n == 1 else f"selection_{n}"
        if base == "keywords":
            return "keywords" if n == 1 else f"keywords_{n}"
        return f"filter_{n}"

    @staticmethod
    def key(leaf) -> str:
        if leaf["mod"] == "kw":
            return ""
        parts = [leaf["field"]]
        mod = leaf["mod"]
        if mod in ("contains", "startswith", "endswith", "re", "gt", "gte", "lt", "lte", "exists", "cidr"):
            parts.append(mod)
        if leaf.get("all"):
            parts.append("all")
        if leaf.get("cs"):
            parts.append("cased")
        return "|".join(parts)

    @staticmethod
    def value(leaf):
        vals = leaf["values"]
        if leaf["mod"] == "exists":
            return True
        return vals[0] if len(vals) == 1 else list(vals)

    def merge_or(self, kids):
        out = []
        index: Dict[str, int] = {}
        for k in kids:
            if k[0] == "leaf" and not k[1].get("all"):
                key = self.key(k[1]) or "__kw__"
                if key in index and k[1]["mod"] != "exists":
                    prev = out[index[key]][1]
                    prev["values"] = list(prev["values"]) + [v for v in k[1]["values"] if v not in prev["values"]]
                    continue
                index[key] = len(out)
                out.append(("leaf", dict(k[1], values=list(k[1]["values"]))))
            else:
                out.append(k)
        return out

    def emit(self, node, negated=False) -> str:
        kind = node[0]
        if kind == "leaf":
            leaf = node[1]
            if leaf["mod"] == "kw":
                name = self.name("keywords")
                self.det[name] = list(leaf["values"])
                return name
            name = self.name("filter" if negated else "selection")
            self.det[name] = {self.key(leaf): self.value(leaf)}
            return name
        if kind == "not":
            inner = node[1]
            if inner[0] == "or":
                kids = self.merge_or(inner[1])
                if len(kids) == 1:
                    return "not " + self.emit(kids[0], True)
                return "not (" + " or ".join(self._wrap(self.emit(k, True)) for k in kids) + ")"
            return "not " + self._wrap(self.emit(inner, True))
        if kind == "or":
            kids = self.merge_or(node[1])
            names = [self._wrap(self.emit(k, negated)) for k in kids]
            return names[0] if len(names) == 1 else " or ".join(names)
        if kind == "and":
            kids = list(node[1])
            mergeable: List[Dict] = []
            rest = []
            neg_groups: Dict[str, Dict] = {}
            for k in kids:
                if k[0] == "or":
                    m = self.merge_or(k[1])
                    k = m[0] if len(m) == 1 else ("or", m)
                if k[0] == "leaf" and k[1]["mod"] != "kw":
                    mergeable.append(k[1])
                elif k[0] == "not" and k[1][0] == "leaf" and k[1][1]["mod"] != "kw":
                    key = self.key(k[1][1])
                    if key in neg_groups:
                        neg_groups[key]["values"] = list(neg_groups[key]["values"]) + list(k[1][1]["values"])
                    else:
                        neg_groups[key] = dict(k[1][1], values=list(k[1][1]["values"]))
                else:
                    rest.append(k)
            parts = []
            if mergeable:
                maps: List[Dict[str, Any]] = [{}]
                for leaf in mergeable:
                    key = self.key(leaf)
                    placed = False
                    for mp in maps:
                        if key not in mp:
                            mp[key] = self.value(leaf)
                            placed = True
                            break
                        if leaf["mod"] in ("contains",) and len(leaf["values"]) == 1 and not leaf.get("all") and not isinstance(mp[key], list):
                            allkey = key + "|all" if "|cased" not in key else key.replace("|cased", "|all|cased")
                            if allkey not in mp:
                                mp[allkey] = [mp.pop(key), leaf["values"][0]]
                                placed = True
                                break
                            if isinstance(mp[allkey], list):
                                mp[allkey].append(leaf["values"][0])
                                placed = True
                                break
                    if not placed:
                        maps.append({key: self.value(leaf)})
                for mp in maps:
                    name = self.name("filter" if negated else "selection")
                    self.det[name] = mp
                    parts.append(name)
            for k in rest:
                parts.append(self._wrap(self.emit(k, negated)))
            for leaf in neg_groups.values():
                name = self.name("filter")
                self.det[name] = {self.key(leaf): self.value(leaf)}
                parts.append("not " + name)
            return " and ".join(parts)
        raise QueryError("Nothing left to convert after removing unsupported parts")

    @staticmethod
    def _wrap(expr: str) -> str:
        return f"({expr})" if (" or " in expr or " and " in expr) else expr


def _title(det: Dict[str, Any], ls: Dict[str, str]) -> str:
    for name, body in det.items():
        if name.startswith("selection") and isinstance(body, dict):
            for key, val in body.items():
                v = val[0] if isinstance(val, list) else val
                if key.startswith(("Image", "OriginalFileName", "TargetFilename", "ImageLoaded")) and isinstance(v, str):
                    return f"Suspicious {v.replace(chr(92), '/').split('/')[-1]}"
                if key.startswith(("CommandLine", "ScriptBlockText", "QueryName", "TargetObject")) and isinstance(v, str):
                    return f"Suspicious {ls.get('category', 'event').replace('_', ' ')} with {v[:40]}"
    return f"Converted {ls.get('category') or ls.get('service') or 'query'} detection"


def convert_query(query: str, lang: str = "auto", title: str = "", level: str = "medium", logsource: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    q = (query or "").strip()
    if not q:
        raise QueryError("Paste a query first")
    if len(q) > 20000:
        raise QueryError("The query is too long. The limit is 20000 characters.")
    if lang not in LANGS or lang == "auto":
        lang = detect(q)
    text, hints, warnings = extract(q, lang)
    parser = Parser(tokenize(text, lang), lang)
    tree = parser.parse()
    warnings += parser.warnings
    tree = normalize(tree, warnings, lang == "lucene")
    if tree[0] == "drop":
        raise QueryError("Nothing in this query could be turned into a detection")
    mapped: Dict[str, str] = {}
    tree = map_fields(tree, mapped, hints)
    if tree[0] == "drop":
        raise QueryError("The query only filters on index or time fields. Add a field filter.")
    ls, drop_id = guess_logsource(tree, hints, lang)
    if logsource:
        ls = {k: v for k, v in logsource.items() if v}
    if drop_id is not None:
        trimmed = drop_fields(tree, lambda l: l["field"] == "EventID" and l["mod"] == "eq" and l["values"] == [drop_id])
        if trimmed[0] != "drop":
            tree = trimmed
    if ls.get("service") or ls.get("category"):
        trimmed = drop_fields(tree, lambda l: l["field"] == "Channel" and l["mod"] == "eq")
        if trimmed[0] != "drop":
            tree = trimmed
    if not ls:
        warnings.append("Could not tell the log source. Set it in the rule before you use it.")
        ls = {"product": "windows"}
    builder = Builder()
    condition = builder.emit(tree)
    det = dict(builder.det)
    det["condition"] = condition
    rule = {
        "title": title.strip() or _title(builder.det, ls),
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": f"Converted from a {LANGS[lang]} query by Sigma Forge. Check the fields and the log source before you use it.",
        "author": "Sigma Forge",
        "date": date.today().isoformat(),
        "tags": [],
        "logsource": ls,
        "detection": det,
        "falsepositives": ["Unknown"],
        "level": level if level in ("informational", "low", "medium", "high", "critical") else "medium",
    }
    if not rule["tags"]:
        rule.pop("tags")
    text_yaml = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=200)
    error = ""
    try:
        from sigma.collection import SigmaCollection

        coll = SigmaCollection.from_yaml(text_yaml)
        for r in coll.rules:
            for e in getattr(r, "errors", []) or []:
                error = str(e)
        if not error:
            for r in coll.rules:
                _ = r.detection.parsed_condition[0].parsed
    except Exception as exc:
        error = str(exc)
    return {
        "yaml": text_yaml,
        "language": lang,
        "language_name": LANGS[lang],
        "logsource": ls,
        "mapped": mapped,
        "warnings": list(dict.fromkeys(warnings)),
        "condition": condition,
        "error": error,
    }
