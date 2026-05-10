"""
query_builder.py — Übersetzt ParsedQuery in parametrisierte SQL-Fragmente.
Kein String-Concat, kein SQL-Injection-Risiko.
"""

from .query_parser import ParsedQuery, Filter
from datetime import datetime, timedelta, timezone


class QueryBuilder:
    """
    Baut SQL-WHERE-Clauses und PARAMS-Dicts aus einer ParsedQuery.
    Gibt immer (where_sql: str, params: dict) zurück.
    """

    def build_findings(self, pq: ParsedQuery, tenant_id: str) -> tuple[str, dict]:
        clauses = ["f.tenant_id = :tenant_id"]
        params  = {"tenant_id": tenant_id}
        idx     = [0]  # mutable counter für unique param names

        def p(name: str, value) -> str:
            """Registriert Parameter, gibt Platzhalter zurück."""
            key = f"{name}_{idx[0]}"
            idx[0] += 1
            params[key] = value
            return f":{key}"

        asset_filters = []  # Port-Filter gehen auf assets JOIN

        for f in pq.filters:
            clause = self._filter_to_finding_sql(f, p, asset_filters)
            if clause:
                if f.negate and not clause.startswith("NOT "):
                    clause = f"NOT ({clause})"
                clauses.append(clause)

        # Port filter → EXISTS subquery on assets
        if asset_filters:
            port_clauses = []
            for port in asset_filters:
                pk = p("port", port)
                port_clauses.append(f"{pk} = ANY(a.ports)")
            port_sql = " OR ".join(port_clauses)
            clauses.append(
                f"EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = f.tenant_id "
                f"AND a.fqdn = split_part(f.asset, ':', 1) AND ({port_sql}))"
            )

        # Freetext → pg_trgm similarity on title + asset
        if pq.freetext.strip():
            ft_key = p("ft", f"%{pq.freetext.strip()}%")
            clauses.append(
                f"(f.title ILIKE {ft_key} OR f.asset ILIKE {ft_key} "
                f"OR f.description ILIKE {ft_key})"
            )

        logic = f" {pq.logic} " if pq.logic == "OR" and len(clauses) > 1 else " AND "
        # First clause (tenant_id) is always AND
        tenant_clause = clauses[0]
        rest = logic.join(clauses[1:]) if len(clauses) > 1 else ""

        where = tenant_clause + (" AND (" + rest + ")" if rest else "")
        return where, params

    def build_assets(self, pq: ParsedQuery, tenant_id: str) -> tuple[str, dict]:
        clauses = ["a.tenant_id = :tenant_id"]
        params  = {"tenant_id": tenant_id}
        idx     = [0]

        def p(name: str, value) -> str:
            key = f"{name}_{idx[0]}"
            idx[0] += 1
            params[key] = value
            return f":{key}"

        for f in pq.filters:
            clause = self._filter_to_asset_sql(f, p)
            if clause:
                if f.negate and not clause.startswith("NOT "):
                    clause = f"NOT ({clause})"
                clauses.append(clause)

        if pq.freetext.strip():
            ft_key = p("ft", f"%{pq.freetext.strip()}%")
            clauses.append(f"(a.fqdn ILIKE {ft_key} OR a.org ILIKE {ft_key} OR a.ip::text ILIKE {ft_key})")

        logic = f" {pq.logic} " if pq.logic == "OR" and len(clauses) > 1 else " AND "
        tenant_clause = clauses[0]
        rest = logic.join(clauses[1:]) if len(clauses) > 1 else ""
        where = tenant_clause + (" AND (" + rest + ")" if rest else "")
        return where, params

    # ── Findings field mapping ─────────────────────────────────────────────────

    def _filter_to_finding_sql(self, f: Filter, p, asset_filters: list) -> str:
        field, op, val = f.field, f.op, f.value

        # Direct column mapping
        COL = {
            "severity":    "f.severity",
            "status":      "f.status",
            "category":    "f.category",
            "tool":        "f.tool",
            "cve_id":      "f.cve_id",
            "cvss_score":  "f.cvss_score",
            "epss_score":  "f.epss_score",
            "cisa_kev":    "f.cisa_kev",
            "ticket_ref":  "f.ticket_ref",
            "screenshot_url": "f.screenshot_url",
            "title":       "f.title",
            "asset":       "f.asset",
        }

        col = COL.get(field)

        # Numeric ops
        if col and op in ("eq","neq","gt","gte","lt","lte"):
            op_map = {"eq":"=","neq":"!=","gt":">","gte":">=","lt":"<","lte":"<="}
            return f"{col} {op_map[op]} {p(field, val)}"

        if col and op == "in":
            placeholders = ", ".join(p(f"{field}_v", v) for v in val)
            return f"{col} IN ({placeholders})"

        if col and op == "between":
            return f"{col} BETWEEN {p(field+'_lo', val[0])} AND {p(field+'_hi', val[1])}"

        if col and op == "exists":
            return f"{col} IS NOT NULL"

        if col and op == "not_exists":
            return f"{col} IS NULL"

        if col and op in ("like","ilike"):
            op_sql = "LIKE" if op == "like" else "ILIKE"
            return f"{col} {op_sql} {p(field, val)}"

        # Age filter → on first_seen
        if field == "age":
            now = datetime.now(timezone.utc)
            days = val
            ts = now - timedelta(days=days)
            ts_key = p("ts", ts.isoformat())
            if op == "age_lt":     return f"f.first_seen >= {ts_key}"  # younger than N days
            if op == "age_gt":     return f"f.first_seen <= {ts_key}"  # older than N days
            if op == "age_lte":    return f"f.first_seen >= {ts_key}"
            if op == "age_gte":    return f"f.first_seen <= {ts_key}"
            if op == "age_eq":
                ts2 = now - timedelta(days=days - 1)
                return f"f.first_seen BETWEEN {p('ts2', ts.isoformat())} AND {p('ts3', ts2.isoformat())}"

        # Port → defer to caller for asset subquery
        if field == "port" and op == "port_open":
            asset_filters.append(val)
            return ""  # handled in caller

        return ""

    # ── Assets field mapping ───────────────────────────────────────────────────

    def _filter_to_asset_sql(self, f: Filter, p) -> str:
        field, op, val = f.field, f.op, f.value

        if field == "fqdn" and op == "like":
            return f"a.fqdn ILIKE {p('fqdn', val)}"

        if field == "ip":
            if op == "cidr":
                return f"a.ip << {p('cidr', val)}::inet"
            if op == "eq":
                return f"a.ip = {p('ip', val)}::inet"

        if field == "org" and op == "ilike":
            return f"a.org ILIKE {p('org', val)}"

        if field == "port" and op == "port_open":
            return f"{p('port', val)} = ANY(a.ports)"

        if field == "risk_level" and op in ("eq", "in"):
            if op == "in":
                ph = ", ".join(p("risk_v", v) for v in val)
                return f"a.risk_level IN ({ph})"
            return f"a.risk_level = {p('risk', val)}"

        return ""
