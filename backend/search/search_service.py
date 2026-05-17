"""
search_service.py — Production search service — all queries run against the database.
"""

import time
from typing import Any
from .query_parser import QueryParser, ParsedQuery, ParseError
from .query_builder import QueryBuilder


class SearchService:

    def __init__(self):
        self.parser  = QueryParser()
        self.builder = QueryBuilder()

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
