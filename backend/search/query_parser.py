"""
query_parser.py — Parst die EASM-Query-Syntax in ein strukturiertes Objekt.

Unterstützte Syntax:
  severity:critical                  Exakter Match
  severity:critical,high             Mehrere Werte (OR)
  -severity:low                      Negation
  tool:nuclei                        Tool-Filter
  cat:mcp  / tag:mcp-exposure        Kategorie
  has:cve / has:kev / has:no-ticket  Feld-Flags
  status:open                        Status
  cvss:>=9 / cvss:7..10              Score-Vergleiche
  epss:>=0.9                         EPSS-Filter
  age:<7 / age:>30                   Alter in Tagen
  port:6274                          Port offen (Asset-Join)
  subdomain:*.example.de             FQDN-Wildcard
  ip:203.0.113.0/24                  IP-Range (CIDR)
  org:hetzner                        Hosting-Organisation
  cve:CVE-2024-3400                  Spezifische CVE
  asset:vpn.example.de               Asset-String
  title:globalprotect                Im Titel
  A OR B                             Logisches ODER
  "freier text"                      Freitext-Phrase
"""

import re
from dataclasses import dataclass, field
from typing import Optional


class ParseError(Exception):
    """Unbekannter oder ungültiger Filter."""
    def __init__(self, message: str, suggestion: str = ""):
        self.message = message
        self.suggestion = suggestion
        super().__init__(message)


@dataclass
class Filter:
    field:    str
    op:       str   # eq | neq | in | nin | exists | not_exists | gt | gte | lt | lte | between | like | cidr
    value:    object = None
    negate:   bool = False

    def __repr__(self):
        neg = "NOT " if self.negate else ""
        return f"Filter({neg}{self.field} {self.op} {self.value!r})"


@dataclass
class ParsedQuery:
    filters:  list[Filter] = field(default_factory=list)
    freetext: str = ""
    logic:    str = "AND"   # top-level logic between filter groups
    raw:      str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.filters and not self.freetext.strip()

    @property
    def has_scope(self) -> set[str]:
        """Which scopes (findings/assets) this query touches."""
        scopes = set()
        asset_fields = {"port", "subdomain", "ip", "org", "fqdn"}
        finding_fields = {"severity", "status", "category", "tool", "cvss",
                          "epss", "cve", "has", "age", "title", "asset"}
        for f in self.filters:
            if f.field in asset_fields:
                scopes.add("assets")
            if f.field in finding_fields:
                scopes.add("findings")
        if not scopes:
            scopes = {"findings", "assets"}
        return scopes


# ── Token patterns ────────────────────────────────────────────────────────────

# Alias resolution
FIELD_ALIASES = {
    "tag":        "category",
    "cat":        "category",
    "sev":        "severity",
    "s":          "severity",
    "t":          "tool",
    "c":          "category",
    "fqdn":       "subdomain",
    "domain":     "subdomain",
    "host":       "asset",
    "score":      "cvss",
    "kev":        "has",
}

# Valid fields and their value patterns
FIELD_SPECS = {
    "severity":   {"type": "enum",   "values": {"critical","high","medium","low","info"}},
    "status":     {"type": "enum",   "values": {"open","acknowledged","in_progress","resolved","accepted_risk"}},
    "category":   {"type": "slug",   "aliases": {
                        "mcp": "mcp_exposure", "cve": "cve", "credential": "credential_leak",
                        "credentials": "credential_leak", "subdomain": "subdomain_risk",
                        "exposure": "exposure", "port": "port", "http": "http",
                        "ssl": "ssl_issue", "email": "email_security", "dns": "dns_issue",
                    }},
    "tool":       {"type": "enum",   "values": {"subfinder","naabu","theharvester","httpx","nuclei","ramparts"}},
    "has":        {"type": "flag",   "values": {
                        "cve": ("cve_id",    "exists"),
                        "kev": ("cisa_kev",  "true"),
                        "ticket": ("ticket_ref", "exists"),
                        "no-ticket": ("ticket_ref", "not_exists"),
                        "epss": ("epss_score", "exists"),
                        "cvss": ("cvss_score", "exists"),
                        "screenshot": ("screenshot_url", "exists"),
                    }},
    "cvss":       {"type": "numeric", "col": "cvss_score",  "min": 0.0, "max": 10.0},
    "epss":       {"type": "numeric", "col": "epss_score",  "min": 0.0, "max": 1.0},
    "age":        {"type": "age"},
    "port":       {"type": "port"},
    "subdomain":  {"type": "text_pattern"},
    "ip":         {"type": "cidr"},
    "org":        {"type": "ilike"},
    "cve":        {"type": "exact",  "col": "cve_id"},
    "asset":      {"type": "ilike",  "col": "asset"},
    "title":      {"type": "ilike",  "col": "title"},
}

# Regex: key:value token (handles negation with -)
TOKEN_RE = re.compile(
    r'(-?)(\w+):((?:"[^"]*"|[^\s]+))',
    re.IGNORECASE
)
QUOTED_RE = re.compile(r'"([^"]*)"')
NUMERIC_RANGE_RE = re.compile(r'^([\d.]+)\.\.([\d.]+)$')
NUMERIC_CMP_RE   = re.compile(r'^(>=|<=|>|<|=)([\d.]+)$')


class QueryParser:

    def parse(self, raw: str) -> ParsedQuery:
        pq = ParsedQuery(raw=raw)
        if not raw or not raw.strip():
            return pq

        text = raw.strip()

        # Detect top-level OR (between space-separated groups)
        if re.search(r'\bOR\b', text, re.IGNORECASE):
            pq.logic = "OR"
            text = re.sub(r'\bOR\b', ' ', text, flags=re.IGNORECASE)

        # Extract quoted freetext phrases
        for m in QUOTED_RE.finditer(text):
            pq.freetext += (" " + m.group(1)).strip()
        text = QUOTED_RE.sub("", text)

        # Extract key:value tokens
        remaining = text
        for m in TOKEN_RE.finditer(text):
            negate_str, key, value = m.group(1), m.group(2).lower(), m.group(3)
            negate = negate_str == "-"
            key = FIELD_ALIASES.get(key, key)
            remaining = remaining.replace(m.group(0), "", 1)

            try:
                filters = self._parse_token(key, value, negate)
                pq.filters.extend(filters)
            except ParseError as e:
                pq.warnings.append(f"{e.message}" + (f" — {e.suggestion}" if e.suggestion else ""))

        # Remainder is freetext
        leftover = remaining.replace("AND", "").strip()
        if leftover:
            pq.freetext = (pq.freetext + " " + leftover).strip()

        return pq

    def _parse_token(self, key: str, value: str, negate: bool) -> list[Filter]:
        spec = FIELD_SPECS.get(key)
        if spec is None:
            valid = ", ".join(sorted(FIELD_SPECS))
            raise ParseError(
                f"Unbekannter Filter '{key}'",
                f"Verfügbare Filter: {valid}"
            )

        t = spec["type"]
        filters = []

        # ── enum ─────────────────────────────────────────────────────────────
        if t == "enum":
            vals = [v.strip().lower() for v in value.split(",")]
            allowed = spec["values"]
            for v in vals:
                if v not in allowed:
                    raise ParseError(
                        f"Ungültiger Wert '{v}' für '{key}'",
                        f"Erlaubte Werte: {', '.join(sorted(allowed))}"
                    )
            op = "in" if len(vals) > 1 else "eq"
            val = [v.upper() if key == "severity" else v for v in vals]
            filters.append(Filter(field=key, op=op, value=val if len(vals) > 1 else val[0], negate=negate))

        # ── slug/category ─────────────────────────────────────────────────────
        elif t == "slug":
            v = value.lower()
            resolved = spec.get("aliases", {}).get(v, v)
            filters.append(Filter(field=key, op="eq", value=resolved, negate=negate))

        # ── flag (has:) ───────────────────────────────────────────────────────
        elif t == "flag":
            v = value.lower()
            flags = spec["values"]
            if v not in flags:
                raise ParseError(
                    f"Unbekanntes Flag 'has:{v}'",
                    f"Verfügbare Flags: {', '.join(sorted(flags))}"
                )
            col, flag_op = flags[v]
            if flag_op == "true":
                filters.append(Filter(field=col, op="eq", value=True, negate=negate))
            elif flag_op == "exists":
                filters.append(Filter(field=col, op="not_exists" if negate else "exists", value=None))
            elif flag_op == "not_exists":
                filters.append(Filter(field=col, op="exists" if negate else "not_exists", value=None))

        # ── numeric (cvss, epss) ──────────────────────────────────────────────
        elif t == "numeric":
            col = spec["col"]
            range_m = NUMERIC_RANGE_RE.match(value)
            cmp_m   = NUMERIC_CMP_RE.match(value)
            if range_m:
                lo, hi = float(range_m.group(1)), float(range_m.group(2))
                filters.append(Filter(field=col, op="between", value=(lo, hi), negate=negate))
            elif cmp_m:
                op_str, num = cmp_m.group(1), float(cmp_m.group(2))
                op_map = {">=": "gte", "<=": "lte", ">": "gt", "<": "lt", "=": "eq"}
                filters.append(Filter(field=col, op=op_map[op_str], value=num, negate=negate))
            else:
                try:
                    num = float(value)
                    filters.append(Filter(field=col, op="eq", value=num, negate=negate))
                except ValueError:
                    raise ParseError(f"Ungültiger Zahlenwert '{value}' für '{key}'",
                                     f"Beispiel: {key}:>=7  oder  {key}:7..10")

        # ── age ───────────────────────────────────────────────────────────────
        elif t == "age":
            cmp_m = NUMERIC_CMP_RE.match(value)
            if cmp_m:
                op_str, days = cmp_m.group(1), int(float(cmp_m.group(2)))
                op_map = {"<": "age_lt", ">": "age_gt", "<=": "age_lte", ">=": "age_gte", "=": "age_eq"}
                filters.append(Filter(field="age", op=op_map.get(op_str, "age_lt"), value=days, negate=negate))
            else:
                try:
                    days = int(value)
                    filters.append(Filter(field="age", op="age_eq", value=days, negate=negate))
                except ValueError:
                    raise ParseError(f"Ungültiges Alter '{value}'", "Beispiel: age:<7  oder  age:>30")

        # ── port ──────────────────────────────────────────────────────────────
        elif t == "port":
            try:
                port = int(value)
                if not (1 <= port <= 65535):
                    raise ValueError
                filters.append(Filter(field="port", op="port_open", value=port, negate=negate))
            except ValueError:
                raise ParseError(f"Ungültiger Port '{value}'", "Ports: 1–65535")

        # ── text_pattern (subdomain) ───────────────────────────────────────────
        elif t == "text_pattern":
            pattern = value.replace("*", "%")
            if not pattern.startswith("%"):
                pattern = "%" + pattern
            filters.append(Filter(field="fqdn", op="like", value=pattern, negate=negate))

        # ── cidr (ip) ────────────────────────────────────────────────────────
        elif t == "cidr":
            import ipaddress
            try:
                ipaddress.ip_network(value, strict=False)
                filters.append(Filter(field="ip", op="cidr", value=value, negate=negate))
            except ValueError:
                # Try single IP
                try:
                    ipaddress.ip_address(value)
                    filters.append(Filter(field="ip", op="eq", value=value, negate=negate))
                except ValueError:
                    raise ParseError(f"Ungültige IP/CIDR '{value}'", "Beispiel: ip:203.0.113.0/24")

        # ── ilike / exact ─────────────────────────────────────────────────────
        elif t in ("ilike", "exact"):
            col = spec.get("col", key)
            op  = "ilike" if t == "ilike" else "eq"
            val = f"%{value}%" if t == "ilike" else value
            filters.append(Filter(field=col, op=op, value=val, negate=negate))

        return filters
