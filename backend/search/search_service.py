"""
search_service.py — Orchestriert Parser + Builder, führt DB-Queries aus.

In dieser Version: Demo-Daten (identisch zu easm_fullhunt_ui.jsx),
damit die API sofort ohne echte DB funktioniert.
Beim DB-Rollout: _search_findings_db() / _search_assets_db() aktivieren.
"""

import time
from typing import Any
from .query_parser import QueryParser, ParsedQuery, ParseError
from .query_builder import QueryBuilder


# ── Demo-Datensatz (spiegelt easm_fullhunt_ui.jsx exakt) ──────────────────────

DEMO_FINDINGS = [
    {"id":"F001","severity":"CRITICAL","category":"cve","tool":"nuclei",
     "cve_id":"CVE-2024-3400","cvss_score":10.0,"epss_score":0.974,"cisa_kev":True,
     "title":"CVE-2024-3400 — GlobalProtect RCE","asset":"vpn.mueller-gmbh.de:443",
     "status":"open","ticket_ref":None,"age_days":1,
     "description":"Unauthenticated command injection in PAN-OS GlobalProtect.",
     "remediation":"Upgrade PAN-OS ≥11.1.2-h3."},
    {"id":"F002","severity":"CRITICAL","category":"mcp_exposure","tool":"ramparts",
     "cve_id":None,"cvss_score":9.8,"epss_score":None,"cisa_kev":False,
     "title":"MCP-Server ohne Auth — RCE möglich","asset":"203.0.113.55:8080/mcp",
     "status":"open","ticket_ref":None,"age_days":1,
     "description":"MCP server accepts initialize without Bearer token.",
     "remediation":"Enable Bearer-token auth. Never bind to 0.0.0.0."},
    {"id":"F003","severity":"CRITICAL","category":"exposure","tool":"nuclei",
     "cve_id":None,"cvss_score":9.1,"epss_score":0.812,"cisa_kev":False,
     "title":".env-Datei im Webroot erreichbar","asset":"staging.mueller-gmbh.de/.env",
     "status":"open","ticket_ref":None,"age_days":3,
     "description":"APP_KEY, DB_PASSWORD, AWS_SECRET_ACCESS_KEY exposed.",
     "remediation":"Remove .env from webroot. Rotate all credentials."},
    {"id":"F004","severity":"CRITICAL","category":"cve","tool":"nuclei",
     "cve_id":"CVE-2025-49596","cvss_score":9.4,"epss_score":0.891,"cisa_kev":False,
     "title":"MCP Inspector RCE — DNS Rebinding","asset":"203.0.113.55:6274",
     "status":"open","ticket_ref":None,"age_days":1,
     "description":"MCP Inspector on port 6274/6277 in production.",
     "remediation":"Stop MCP Inspector. Block ports 6274/6277."},
    {"id":"F005","severity":"CRITICAL","category":"exposure","tool":"httpx",
     "cve_id":None,"cvss_score":8.9,"epss_score":0.743,"cisa_kev":False,
     "title":"Spring Boot Actuator /env exponiert","asset":"api.mueller-gmbh.de/actuator/env",
     "status":"open","ticket_ref":None,"age_days":5,
     "description":"Spring Boot Actuator returns DB_PASSWORD, JWT_SECRET.",
     "remediation":"Restrict actuator endpoints to health,info only."},
    {"id":"F006","severity":"HIGH","category":"subdomain_risk","tool":"subfinder",
     "cve_id":None,"cvss_score":8.1,"epss_score":None,"cisa_kev":False,
     "title":"Subdomain Takeover — CNAME verwaist","asset":"dev.mueller-gmbh.de",
     "status":"open","ticket_ref":None,"age_days":1,
     "description":"CNAME points to deleted Heroku app.",
     "remediation":"Remove CNAME record."},
    {"id":"F007","severity":"HIGH","category":"port","tool":"naabu",
     "cve_id":None,"cvss_score":8.1,"epss_score":0.612,"cisa_kev":False,
     "title":"RDP :3389 direkt aus Internet erreichbar","asset":"203.0.113.46:3389",
     "status":"open","ticket_ref":None,"age_days":8,
     "description":"RDP exposed to internet. Primary ransomware entry point.",
     "remediation":"Restrict RDP to VPN-only."},
    {"id":"F008","severity":"HIGH","category":"mcp_exposure","tool":"ramparts",
     "cve_id":None,"cvss_score":8.0,"epss_score":None,"cisa_kev":False,
     "title":"MCP Shell-Tools ohne Auth exponiert","asset":"203.0.113.55:8080",
     "status":"open","ticket_ref":None,"age_days":1,
     "description":"tools/list exposes execute_command, shell, run_script.",
     "remediation":"Restrict tools. Add authentication."},
    {"id":"F009","severity":"HIGH","category":"credential_leak","tool":"theharvester",
     "cve_id":None,"cvss_score":7.5,"epss_score":None,"cisa_kev":False,
     "title":"31 E-Mails in OSINT — 8 in Breach-DBs","asset":"mueller-gmbh.de",
     "status":"open","ticket_ref":None,"age_days":2,
     "description":"31 emails in OSINT, 8 compromised via HIBP.",
     "remediation":"Force password reset. Enable MFA."},
    {"id":"F010","severity":"MEDIUM","category":"http","tool":"httpx",
     "cve_id":None,"cvss_score":6.5,"epss_score":0.234,"cisa_kev":False,
     "title":"CORS Origin-Reflection auf /api/","asset":"api.mueller-gmbh.de/api/",
     "status":"open","ticket_ref":"INC-2040","age_days":3,
     "description":"Server reflects arbitrary Origin header.",
     "remediation":"Whitelist allowed origins explicitly."},
    {"id":"F011","severity":"LOW","category":"ssl_issue","tool":"httpx",
     "cve_id":None,"cvss_score":0.0,"epss_score":None,"cisa_kev":False,
     "title":"SSL-Zertifikat läuft in 8 Tagen ab","asset":"mail.mueller-gmbh.de:443",
     "status":"open","ticket_ref":None,"age_days":1,
     "description":"TLS certificate expires 2026-05-14.",
     "remediation":"Renew certificate. Configure auto-renewal."},
]

DEMO_ASSETS = [
    {"id":"A001","fqdn":"vpn.mueller-gmbh.de","ip":"203.0.113.45","org":"Hetzner Online GmbH","asn":24940,"ports":[443,1194],"risk_level":"CRITICAL","sources":["subfinder","cert"]},
    {"id":"A002","fqdn":"admin.mueller-gmbh.de","ip":"203.0.113.46","org":"Hetzner Online GmbH","asn":24940,"ports":[443,8080],"risk_level":"CRITICAL","sources":["subfinder"]},
    {"id":"A003","fqdn":"staging.mueller-gmbh.de","ip":"203.0.113.48","org":"Hetzner Online GmbH","asn":24940,"ports":[80,443],"risk_level":"CRITICAL","sources":["subfinder","dns"]},
    {"id":"A004","fqdn":"jenkins.mueller-gmbh.de","ip":"203.0.113.55","org":"Hetzner Online GmbH","asn":24940,"ports":[8080,6274,6277],"risk_level":"HIGH","sources":["subfinder"]},
    {"id":"A005","fqdn":"dev.mueller-gmbh.de","ip":None,"org":"Heroku","asn":None,"ports":[],"risk_level":"HIGH","sources":["subfinder"]},
    {"id":"A006","fqdn":"remote.mueller-gmbh.de","ip":"203.0.113.47","org":"Hetzner Online GmbH","asn":24940,"ports":[443,3389],"risk_level":"HIGH","sources":["subfinder","dns"]},
    {"id":"A007","fqdn":"www.mueller-gmbh.de","ip":"203.0.113.5","org":"Hetzner Online GmbH","asn":24940,"ports":[80,443],"risk_level":"LOW","sources":["dns","cert"]},
    {"id":"A008","fqdn":"cdn.mueller-gmbh.de","ip":"104.21.44.8","org":"Cloudflare","asn":13335,"ports":[80,443],"risk_level":"LOW","sources":["dns"]},
    {"id":"A009","fqdn":"api.mueller-gmbh.de","ip":"203.0.113.7","org":"Hetzner Online GmbH","asn":24940,"ports":[443],"risk_level":"MEDIUM","sources":["subfinder","cert"]},
    {"id":"A010","fqdn":"crm.mueller-gmbh.de","ip":"136.147.128.30","org":"Salesforce","asn":14340,"ports":[443],"risk_level":"LOW","sources":["dns"]},
]


class SearchService:

    def __init__(self):
        self.parser  = QueryParser()
        self.builder = QueryBuilder()

    def search(
        self,
        q: str,
        tenant_id: str,
        scope: str = "all",
        limit: int = 50,
        offset: int = 0,
        sort: str = "relevance",
        order: str = "desc",
    ) -> dict[str, Any]:
        t0 = time.time()

        # Parse
        try:
            pq = self.parser.parse(q)
        except ParseError as e:
            return {
                "query": q,
                "error": e.message,
                "suggestion": e.suggestion,
                "results": {"findings": [], "assets": []},
                "total":  {"findings": 0, "assets": 0},
                "took_ms": int((time.time() - t0) * 1000),
            }

        # Determine scope
        requested_scopes = set()
        if scope == "all":
            requested_scopes = {"findings", "assets"}
        else:
            for s in scope.split(","):
                requested_scopes.add(s.strip())

        # Auto-scope: if query only has asset filters, skip findings and vice versa
        auto_scope = pq.has_scope
        active_scopes = requested_scopes & auto_scope if auto_scope else requested_scopes

        results: dict[str, list] = {}
        totals:  dict[str, int]  = {}

        if "findings" in active_scopes:
            all_findings = self._filter_findings_demo(pq)
            all_findings = self._sort_findings(all_findings, sort, order)
            totals["findings"] = len(all_findings)
            results["findings"] = all_findings[offset: offset + limit]
        else:
            totals["findings"] = 0
            results["findings"] = []

        if "assets" in active_scopes:
            all_assets = self._filter_assets_demo(pq)
            totals["assets"] = len(all_assets)
            results["assets"] = all_assets[offset: offset + limit]
        else:
            totals["assets"] = 0
            results["assets"] = []

        took = int((time.time() - t0) * 1000)

        return {
            "query":    q,
            "parsed": {
                "filters":  [{"field": f.field, "op": f.op, "value": f.value, "negate": f.negate}
                              for f in pq.filters],
                "freetext": pq.freetext,
                "logic":    pq.logic,
                "warnings": pq.warnings,
            },
            "results": results,
            "total":   totals,
            "took_ms": took,
        }

    # ── In-memory demo filtering ──────────────────────────────────────────────

    def _filter_findings_demo(self, pq: ParsedQuery) -> list[dict]:
        results = []
        for f in DEMO_FINDINGS:
            if self._matches_finding(f, pq):
                results.append(f)
        return results

    def _matches_finding(self, f: dict, pq: ParsedQuery) -> bool:
        for filt in pq.filters:
            match = self._eval_finding_filter(f, filt)
            if filt.negate:
                match = not match
            if not match:
                return False

        # Freetext
        if pq.freetext:
            ft = pq.freetext.lower()
            haystack = " ".join([
                f.get("title",""), f.get("asset",""), f.get("description",""),
                f.get("cve_id","") or "",
            ]).lower()
            if ft not in haystack:
                return False
        return True

    def _eval_finding_filter(self, f: dict, filt) -> bool:
        field, op, val = filt.field, filt.op, filt.value

        # Map field to finding key
        FMAP = {
            "severity":    "severity",
            "status":      "status",
            "category":    "category",
            "tool":        "tool",
            "cve_id":      "cve_id",
            "cvss_score":  "cvss_score",
            "epss_score":  "epss_score",
            "cisa_kev":    "cisa_kev",
            "ticket_ref":  "ticket_ref",
            "title":       "title",
            "asset":       "asset",
        }

        col_key = FMAP.get(field)

        if col_key:
            fv = f.get(col_key)
            if op == "eq":
                if isinstance(val, str):
                    return str(fv or "").lower() == val.lower()
                return fv == val
            if op == "in":
                return str(fv or "").lower() in [str(v).lower() for v in val]
            if op == "exists":
                return fv is not None and fv != ""
            if op == "not_exists":
                return fv is None or fv == ""
            if op in ("gt","gte","lt","lte") and fv is not None:
                ops = {"gt": lambda a,b: a>b, "gte": lambda a,b: a>=b,
                       "lt": lambda a,b: a<b, "lte": lambda a,b: a<=b}
                return ops[op](float(fv), float(val))
            if op == "between" and fv is not None:
                return float(val[0]) <= float(fv) <= float(val[1])
            if op in ("like","ilike"):
                pattern = val.replace("%","").lower()
                return pattern in str(fv or "").lower()
            return True

        if field == "age":
            age = f.get("age_days", 0)
            if op == "age_lt":  return age < val
            if op == "age_gt":  return age > val
            if op == "age_lte": return age <= val
            if op == "age_gte": return age >= val
            if op == "age_eq":  return age == val
            return True

        if field == "port" and op == "port_open":
            # Check if any asset with matching fqdn has this port
            asset_fqdn = f.get("asset","").split(":")[0].split("/")[0]
            for a in DEMO_ASSETS:
                if a.get("fqdn") == asset_fqdn and val in (a.get("ports") or []):
                    return True
            return False

        return True

    def _filter_assets_demo(self, pq: ParsedQuery) -> list[dict]:
        results = []
        for a in DEMO_ASSETS:
            if self._matches_asset(a, pq):
                results.append(a)
        return results

    def _matches_asset(self, a: dict, pq: ParsedQuery) -> bool:
        for filt in pq.filters:
            match = self._eval_asset_filter(a, filt)
            if filt.negate:
                match = not match
            if not match:
                return False

        if pq.freetext:
            ft = pq.freetext.lower()
            haystack = " ".join([
                a.get("fqdn","") or "", a.get("org","") or "",
                str(a.get("ip","") or ""),
            ]).lower()
            if ft not in haystack:
                return False
        return True

    def _eval_asset_filter(self, a: dict, filt) -> bool:
        field, op, val = filt.field, filt.op, filt.value

        if field == "fqdn" and op == "like":
            pattern = val.replace("%","").lower()
            return pattern in (a.get("fqdn","") or "").lower()

        if field == "ip":
            ip = a.get("ip","") or ""
            if op == "eq":
                return ip == val
            if op == "cidr":
                import ipaddress
                try:
                    return ipaddress.ip_address(ip) in ipaddress.ip_network(val, strict=False)
                except Exception:
                    return False

        if field == "org" and op == "ilike":
            pattern = val.replace("%","").lower()
            return pattern in (a.get("org","") or "").lower()

        if field == "port" and op == "port_open":
            return val in (a.get("ports") or [])

        if field == "risk_level":
            rv = a.get("risk_level","")
            if op == "eq":
                return rv.upper() == str(val).upper()
            if op == "in":
                return rv.upper() in [str(v).upper() for v in val]

        # Severity maps to risk_level for assets
        if field == "severity":
            rv = a.get("risk_level","")
            if op == "eq":
                return rv.upper() == str(val).upper()
            if op == "in":
                return rv.upper() in [str(v).upper() for v in val]

        return True

    def _sort_findings(self, findings: list, sort: str, order: str) -> list:
        SEV_ORD = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
        reverse = order == "desc"

        if sort == "severity":
            return sorted(findings, key=lambda f: SEV_ORD.get(f.get("severity",""),9), reverse=not reverse)
        if sort == "cvss":
            return sorted(findings, key=lambda f: f.get("cvss_score") or 0, reverse=reverse)
        if sort == "epss":
            return sorted(findings, key=lambda f: f.get("epss_score") or 0, reverse=reverse)
        if sort == "age":
            return sorted(findings, key=lambda f: f.get("age_days",0), reverse=reverse)
        # Default: severity DESC (most critical first)
        return sorted(findings, key=lambda f: SEV_ORD.get(f.get("severity",""),9))

    async def search_db(
        self,
        q: str,
        db,
        tenant_id: str,
        scope: str = "all",
        limit: int = 50,
        offset: int = 0,
        sort: str = "relevance",
        order: str = "desc",
    ) -> dict:
        """Production search: queries the database."""
        import time
        t0 = time.time()
        try:
            pq = self.parser.parse(q)
        except Exception as e:
            return {"query": q, "error": str(e), "results": {"findings": [], "assets": []},
                    "total": {"findings": 0, "assets": 0}, "took_ms": 0}

        from db.repo import list_findings, list_assets
        results = {}
        totals = {}

        if scope in ("all", "findings"):
            sev = next((f.value for f in pq.filters if f.field == "severity"), None)
            status = next((f.value for f in pq.filters if f.field == "status"), None)
            cat = next((f.value for f in pq.filters if f.field == "category"), None)
            r = await list_findings(db, tenant_id, sev, status, cat, limit, offset)
            results["findings"] = r["findings"]
            totals["findings"] = r["total"]
        else:
            results["findings"] = []
            totals["findings"] = 0

        if scope in ("all", "assets"):
            r = await list_assets(db, tenant_id, limit, offset)
            results["assets"] = r["assets"]
            totals["assets"] = r["total"]
        else:
            results["assets"] = []
            totals["assets"] = 0

        return {
            "query": q,
            "parsed": {
                "filters": [{"field": f.field, "op": f.op, "value": f.value, "negate": f.negate}
                            for f in pq.filters],
                "freetext": pq.freetext, "logic": pq.logic, "warnings": pq.warnings,
            },
            "results": results,
            "total": totals,
            "took_ms": int((time.time() - t0) * 1000),
        }

