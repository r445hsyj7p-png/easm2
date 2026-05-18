"""
EASM Toolchain Workers — Celery Task Queue
==========================================
Integriert alle 6 Tools (Subfinder, Naabu, theHarvester, HTTPX, Nuclei, Ramparts)
in die bestehende Celery-Infrastruktur.

Beat-Schedules:
  Alle Mandanten → täglich   (alle Tools, alle Features)
  MCP-Scan       → täglich   (dedizierter MCP-Scan)
  HIBP-Check     → täglich   (Credential Leaks)
  MCP-Scan    → täglich     (separater dedizierter MCP-Scan)
  HIBP-Check  → täglich     (Credential Leaks)
  Nuclei-Update → täglich   (Template-Updates)
  SpyOnWeb     → täglich     (Analytics-ID Reverse-Lookup)
  IP-Reputation → täglich   (GreyNoise + AbuseIPDB)
  Threat-Intel  → täglich   (AlienVault OTX + MISP)
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from celery import Celery
from celery.schedules import crontab
from celery.utils.log import get_task_logger
import json, datetime

# ─── Celery App ───────────────────────────────────────────────────────────────
celery_app = Celery(
    "easm_toolchain",
    broker=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    backend=os.getenv("REDIS_URL", "redis://localhost:6379/1"),
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_soft_time_limit=1800,   # 30 Min
    task_time_limit=2400,        # 40 Min hard limit
    result_expires=86400,

    # Routing: Jedes Tool bekommt eigene Queue für Priorisierung
    task_routes={
        "workers.toolchain_tasks.run_full_pipeline":   {"queue": "scans"},
        "workers.toolchain_tasks.run_discovery":       {"queue": "scans"},
        "workers.toolchain_tasks.run_portscan":        {"queue": "scans"},
        "workers.toolchain_tasks.run_http_probe":      {"queue": "http"},
        "workers.toolchain_tasks.run_vuln_scan":       {"queue": "vuln"},
        "workers.toolchain_tasks.run_mcp_scan":        {"queue": "mcp"},
        "workers.toolchain_tasks.run_hibp_check":      {"queue": "hibp"},
        "workers.toolchain_tasks.schedule_tenants":    {"queue": "scheduler"},
        "workers.toolchain_tasks.update_nuclei_templates": {"queue": "maintenance"},
        "workers.toolchain_tasks.send_critical_alert":    {"queue": "alerts"},
        "workers.toolchain_tasks.run_spyonweb_scan":      {"queue": "intel"},
        "workers.toolchain_tasks.run_ip_reputation_check":{"queue": "intel"},
        "workers.toolchain_tasks.run_threat_intel_check": {"queue": "intel"},
        "workers.toolchain_tasks.run_sslyze":             {"queue": "tls"},
    },

    # Beat-Schedules
    beat_schedule={

        # ── Plan-basierte vollständige Scans ──────────────────────────
        "scan-all-daily": {
            "task": "workers.toolchain_tasks.schedule_tenants",
            "schedule": crontab(hour=3, minute=0),
            "args": ["all"],
            "options": {"queue": "scheduler", "priority": 9},
        },
        "scan-all-daily-2": {
            "task": "workers.toolchain_tasks.schedule_tenants",
            "schedule": crontab(hour=2, minute=0),
            "args": ["all"],
            "options": {"queue": "scheduler", "priority": 6},
        },
        "scan-all-weekly": {
            "task": "workers.toolchain_tasks.schedule_tenants",
            "schedule": crontab(hour=3, minute=0, day_of_week="sunday"),
            "args": ["all"],
            "options": {"queue": "scheduler", "priority": 3},
        },

        # ── Spezialisierte tägliche Checks ────────────────────────────
        "mcp-scan-all-daily": {
            "task": "workers.toolchain_tasks.schedule_tenants",
            "schedule": crontab(hour=4, minute=0),
            "args": ["all", "mcp_only"],
            "options": {"queue": "scheduler"},
        },
        "hibp-check-daily": {
            "task": "workers.toolchain_tasks.schedule_tenants",
            "schedule": crontab(hour=6, minute=0),
            "args": ["all", "hibp_only"],
            "options": {"queue": "hibp"},
        },

        # ── TLS-Scan ──────────────────────────────────────────────────
        "tls-scan-daily": {
            "task": "workers.toolchain_tasks.schedule_tenants",
            "schedule": crontab(hour=3, minute=30),
            "args": ["all", "tls_only"],
            "options": {"queue": "tls"},
        },

        # ── Wartung ───────────────────────────────────────────────────
        "nuclei-template-update": {
            "task": "workers.toolchain_tasks.update_nuclei_templates",
            "schedule": crontab(hour=1, minute=0),
            "options": {"queue": "maintenance"},
        },
        "check-risk-acceptances": {
            "task": "workers.toolchain_tasks.check_risk_acceptances",
            "schedule": crontab(hour=7, minute=30),
            "options": {"queue": "alerts"},
        },
        "check-panos-license-expirations": {
            "task": "workers.toolchain_tasks.check_panos_license_expirations",
            "schedule": crontab(hour=7, minute=0),
            "options": {"queue": "alerts"},
        },
        "generate-monthly-reports": {
            "task": "workers.toolchain_tasks.generate_monthly_reports",
            "schedule": crontab(hour=8, minute=0, day_of_month=1),
            "options": {"queue": "maintenance"},
        },

        # ── Intelligence-Quellen (neu) ─────────────────────────────────────
        "spyonweb-scan-daily": {
            "task": "workers.toolchain_tasks.run_spyonweb_scan",
            "schedule": crontab(hour=5, minute=0),
            "args": ["all"],
            "options": {"queue": "intel"},
        },
        "ip-reputation-check-daily": {
            "task": "workers.toolchain_tasks.run_ip_reputation_check",
            "schedule": crontab(hour=5, minute=30),
            "args": ["all"],
            "options": {"queue": "intel"},
        },
        "threat-intel-ioc-check": {
            "task": "workers.toolchain_tasks.run_threat_intel_check",
            "schedule": crontab(hour=6, minute=30),
            "args": ["all"],
            "options": {"queue": "intel"},
        },
    }
)

logger = get_task_logger(__name__)


# ─── Tenant-Abfrage aus der Datenbank ────────────────────────────────────────

def get_all_tenants() -> list:
    """Lädt alle aktiven Mandanten mit ihren Domains aus der Datenbank."""
    import psycopg2
    import psycopg2.extras

    db_url = os.getenv("DATABASE_URL", "")
    if not db_url:
        logger.error("DATABASE_URL nicht gesetzt — keine Mandanten geladen")
        return []
    try:
        conn = psycopg2.connect(db_url)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    t.id,
                    t.name,
                    COALESCE(MIN(d.domain), t.slug) AS domain,
                    COALESCE(
                        array_agg(DISTINCT r) FILTER (WHERE r IS NOT NULL),
                        '{}'
                    ) AS ip_ranges,
                    COALESCE(MAX(d.panos_version), '') AS panos_version
                FROM tenants t
                LEFT JOIN domains d ON d.tenant_id = t.id AND d.status = 'active'
                LEFT JOIN LATERAL unnest(d.ip_ranges) AS r ON TRUE
                WHERE t.status = 'active'
                GROUP BY t.id, t.name, t.slug
                ORDER BY t.name
            """)
            rows = cur.fetchall()
        conn.close()
        return [
            {
                "id":            row["id"],
                "name":          row["name"],
                "domain":        row["domain"] or "",
                "ip_ranges":     list(row["ip_ranges"] or []),
                "panos_version": row["panos_version"] or "",
                "api_keys":      {},
            }
            for row in rows
        ]
    except Exception as exc:
        logger.error(f"DB-Fehler beim Laden der Mandanten: {exc}")
        return []


def get_tenants_by_plan(plan: str = "all") -> list:
    return get_all_tenants()


# ═══════════════════════════════════════════════════════════════════════════════
# HAUPT-TASK: Vollständige EASM-Pipeline
# ═══════════════════════════════════════════════════════════════════════════════

@celery_app.task(
    bind=True,
    name="workers.toolchain_tasks.run_full_pipeline",
    max_retries=2,
    default_retry_delay=120,
    queue="scans"
)
def run_full_pipeline(self, tenant_id: str, config_dict: dict, request_id: str = ""):
    """
    Vollständige EASM-Pipeline für einen Mandanten.

    Phasen:
      1. Subfinder + theHarvester (parallel) → Subdomain-Pool
      2. Naabu → Port-Scan + MCP-Port-Detection
      3. HTTPX → HTTP-Probing, Screenshots, Tech-Stack
      4. Nuclei → Vulnerability-Scan (API, CVE, MCP)
      5. Ramparts → MCP-Tiefenanalyse (falls MCP-Hosts gefunden)
      6. Aggregation → Deduplizierung, Risk-Score, DB
    """
    from easm.pipeline import EASMPipeline, PipelineConfig

    # Use the DB scan_job id passed via config_dict, falling back to Celery task id
    job_id = config_dict.get("scan_id") or self.request.id
    logger.info(f"[{job_id}] [req={request_id}] Pipeline START: tenant={tenant_id}")

    # Load tenant domain from DB (config_dict from API only has scan_id + scan_type)
    if not config_dict.get("domain"):
        tenant_info = _get_tenant_info(tenant_id)
        config_dict = {**config_dict, **tenant_info}

    def _progress(pct: int, phase: str = ""):
        """Persist progress_pct so the frontend poll can show real progress."""
        _update_scan_progress(job_id, pct, phase)

    try:
        # Status: Running
        _update_scan_status(job_id, "running", tenant_id)
        _progress(0, "starting")

        # Plan-spezifische Konfiguration
        config = _build_config(config_dict)

        # Pipeline ausführen — mit Progress-Updates nach jeder Phase
        pipeline = EASMPipeline(tenant_id=tenant_id, config=config)

        import datetime as _dt
        _start = _dt.datetime.utcnow()

        def _run_with_progress():
            domain    = config_dict.get("domain", "")
            ip_ranges = config_dict.get("ip_ranges", [])
            panos_ver = config_dict.get("panos_version", "")

            from easm.pipeline import PipelineReport
            report = PipelineReport(
                tenant_id=tenant_id,
                domain=domain,
                ip_ranges=ip_ranges,
                scan_start=_dt.datetime.utcnow().isoformat(),
            )

            _progress(5, "discovery")
            subdomains = pipeline._phase_discovery(report, domain)

            _progress(20, "portscan")
            open_ports = pipeline._phase_portscan(report, list(set(
                ip_ranges + [s.affected_asset for s in subdomains if "." in s.affected_asset]
            )))
            mcp_hosts = pipeline._identify_mcp_hosts(report)

            _progress(35, "tls")
            tls_targets = pipeline._build_tls_targets(open_ports, subdomains)
            pipeline._phase_tls(report, tls_targets)

            _progress(50, "http")
            http_targets = pipeline._build_http_targets(open_ports, subdomains)
            pipeline._phase_http(report, http_targets)

            _progress(70, "vuln")
            pipeline._phase_vulnscan(report, list(set(http_targets + mcp_hosts)), mcp_hosts)

            _progress(88, "mcp")
            if mcp_hosts and config.run_ramparts:
                pipeline._phase_mcp(report, mcp_hosts)

            _progress(95, "aggregating")
            pipeline._aggregate(report)

            end_ts = _dt.datetime.utcnow()
            report.scan_end = end_ts.isoformat()
            report.duration_seconds = int((end_ts - _dt.datetime.fromisoformat(report.scan_start)).total_seconds())
            pipeline._print_summary(report)
            return report

        report = _run_with_progress()

        _progress(99, "saving")
        # Ergebnisse in DB speichern
        _save_report(tenant_id, job_id, report)

        # Critical-Alerts senden
        critical_findings = [
            f for f in report.all_findings
            if f.severity == "CRITICAL"
        ]
        if critical_findings:
            send_critical_alert.delay(
                tenant_id=tenant_id,
                findings=[
                    {"title": f.title, "asset": f.affected_asset,
                     "tool": f.tool, "severity": f.severity}
                    for f in critical_findings[:10]
                ]
            )

        # MCP-Spezial-Alert
        mcp_findings = [f for f in report.all_findings
                       if f.category == "mcp_exposure" and f.severity == "CRITICAL"]
        if mcp_findings:
            logger.warning(
                f"[{tenant_id}] ⚡ {len(mcp_findings)} kritische MCP-Findings!"
            )

        result = {
            "job_id": job_id,
            "tenant_id": tenant_id,
            "domain": config_dict.get("domain"),
            "risk_score": report.risk_score,
            "total_findings": report.stats.get("total_findings", 0),
            "by_severity": report.stats.get("by_severity", {}),
            "by_tool": report.stats.get("by_tool", {}),
            "subdomains": report.stats.get("subdomains_found", 0),
            "emails": report.stats.get("emails_found", 0),
            "mcp_servers": report.stats.get("mcp_servers_found", 0),
            "duration_seconds": report.duration_seconds,
        }

        _update_scan_status(job_id, "completed", tenant_id, result)
        logger.info(f"[{job_id}] Pipeline DONE: score={report.risk_score}, "
                   f"findings={report.stats.get('total_findings',0)}")
        return result

    except Exception as exc:
        logger.error(f"[{job_id}] Pipeline FAILED: {exc}")
        _update_scan_status(job_id, "failed", tenant_id, {"error": str(exc)})
        raise self.retry(exc=exc, countdown=120 * (self.request.retries + 1))


# ═══════════════════════════════════════════════════════════════════════════════
# EINZELNE TOOL-TASKS (für gezielte Scans)
# ═══════════════════════════════════════════════════════════════════════════════

@celery_app.task(
    name="workers.toolchain_tasks.run_discovery",
    queue="scans"
)
def run_discovery(tenant_id: str, domain: str, api_keys: dict = None):
    """Nur Discovery: Subfinder + theHarvester"""
    from easm.tool_adapters import SubfinderAdapter, TheHarvesterAdapter

    subfinder = SubfinderAdapter(api_keys=api_keys or {})
    harvester = TheHarvesterAdapter()

    findings_sf = subfinder.run(tenant_id, domain)
    findings_th = harvester.run(tenant_id, domain)

    all_findings = findings_sf + findings_th
    subdomains = [f.affected_asset for f in findings_sf
                  if f.category == "subdomain"]
    emails = []
    for f in findings_th:
        if f.category == "email":
            emails = f.raw_data.get("emails", [])

    logger.info(f"[{tenant_id}] Discovery: {len(subdomains)} subdomains, "
               f"{len(emails)} emails")

    return {
        "tenant_id": tenant_id,
        "subdomains": subdomains,
        "emails": emails,
        "total_findings": len(all_findings),
    }


@celery_app.task(
    name="workers.toolchain_tasks.run_portscan",
    queue="scans"
)
def run_portscan(tenant_id: str, targets: list,
                 ports: str = "top-1000", rate: int = 1000):
    """Nur Port-Scan: Naabu"""
    from easm.tool_adapters import NaabuAdapter

    scanner = NaabuAdapter()
    findings = scanner.run(tenant_id, targets, ports=ports, rate=rate)

    open_ports = {}
    mcp_candidates = []
    for f in findings:
        if ":" in f.affected_asset:
            host, port = f.affected_asset.rsplit(":", 1)
            open_ports.setdefault(host, []).append(int(port))
        if f.category == "mcp_exposure":
            mcp_candidates.append(f.affected_asset)

    logger.info(f"[{tenant_id}] Port-Scan: {len(open_ports)} hosts, "
               f"{len(mcp_candidates)} MCP-Kandidaten")

    return {
        "tenant_id": tenant_id,
        "open_ports": open_ports,
        "mcp_candidates": mcp_candidates,
        "total_findings": len(findings),
    }


@celery_app.task(
    name="workers.toolchain_tasks.run_http_probe",
    queue="http"
)
def run_http_probe(tenant_id: str, urls: list,
                   screenshots: bool = False, threads: int = 50):
    """Nur HTTP-Probing: HTTPX"""
    from easm.tool_adapters import HTTPXAdapter

    prober = HTTPXAdapter()
    findings = prober.run(tenant_id, urls,
                          take_screenshots=screenshots,
                          threads=threads)

    by_severity = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    logger.info(f"[{tenant_id}] HTTP-Probe: {len(findings)} findings "
               f"on {len(urls)} URLs")
    return {
        "tenant_id": tenant_id,
        "findings_count": len(findings),
        "by_severity": by_severity,
    }


@celery_app.task(
    name="workers.toolchain_tasks.run_vuln_scan",
    queue="vuln"
)
def run_vuln_scan(tenant_id: str, targets: list,
                  tags: str = "api,exposure,misconfig,default-login,cve",
                  severity: str = "medium,high,critical"):
    """Nur Vulnerability-Scan: Nuclei"""
    from easm.tool_adapters import NucleiAdapter

    scanner = NucleiAdapter()
    findings = scanner.run(
        tenant_id=tenant_id,
        targets=targets,
        tags=tags,
        severity_filter=severity,
    )

    critical = [f for f in findings if f.severity == "CRITICAL"]
    logger.info(f"[{tenant_id}] Vuln-Scan: {len(findings)} findings, "
               f"{len(critical)} CRITICAL")

    return {
        "tenant_id": tenant_id,
        "findings_count": len(findings),
        "critical_count": len(critical),
        "critical_titles": [f.title for f in critical[:5]],
    }


@celery_app.task(
    name="workers.toolchain_tasks.run_mcp_scan",
    queue="mcp"
)
def run_mcp_scan(tenant_id: str, targets: list, use_ramparts: bool = True):
    """
    Dedizierter MCP-Server-Scan.
    Prüft auf:
    - MCP-Server ohne Auth (Nuclei + eigener Handshake)
    - MCP Inspector (CVE-2025-49596)
    - SSE-Endpunkte ohne Auth
    - Gefährliche Tool-Typen (Ramparts)
    - Prompt-Injection in Tool-Descriptions (Ramparts)
    - mcp.json exponiert
    """
    from easm.tool_adapters import NucleiAdapter, RampartsAdapter

    all_findings = []

    # 1. Nuclei MCP-Scan (Inspector, SSE, mcp.json, CVEs)
    nuclei = NucleiAdapter()
    nuclei_findings = nuclei.run_mcp_scan(tenant_id, targets)
    all_findings.extend(nuclei_findings)

    # 2. Ramparts Tiefenanalyse (Tool-Typen, Prompt-Injection)
    if use_ramparts:
        mcp_urls = []
        for target in targets:
            host = target.replace("http://","").replace("https://","").split("/")[0]
            for port in [3000, 8080, 8000, 9000, 6277]:
                mcp_urls.extend([
                    f"http://{host}:{port}/mcp",
                    f"https://{host}:{port}/mcp",
                ])

        ramparts = RampartsAdapter()
        ramparts_findings = ramparts.run(tenant_id, mcp_urls)
        all_findings.extend(ramparts_findings)

    critical = [f for f in all_findings if f.severity == "CRITICAL"]

    if critical:
        # Sofort-Alert bei kritischen MCP-Findings
        send_critical_alert.delay(
            tenant_id=tenant_id,
            findings=[{"title": f.title, "asset": f.affected_asset,
                       "tool": f.tool} for f in critical[:5]],
            alert_type="mcp_critical"
        )

    logger.warning(f"[{tenant_id}] MCP-Scan: {len(all_findings)} findings, "
                  f"{len(critical)} CRITICAL MCP-Exposures")

    return {
        "tenant_id": tenant_id,
        "mcp_findings": len(all_findings),
        "critical_mcp": len(critical),
        "mcp_servers_without_auth": len([
            f for f in all_findings
            if "ohne Authentifizierung" in f.title or "without auth" in f.title.lower()
        ]),
    }


@celery_app.task(
    name="workers.toolchain_tasks.run_hibp_check",
    queue="hibp",
    rate_limit="10/m"    # HIBP Rate-Limit: 10 Req/Min
)
def run_hibp_check(tenant_id: str, domain: str, api_key: str = ""):
    """HIBP Credential-Leak-Check mit allen Endpunkten"""
    import urllib.request, urllib.error

    BASE = "https://haveibeenpwned.com/api/v3"
    headers = {"User-Agent": "MSSP-EASM/1.0", "hibp-api-key": api_key}

    results = {"domain": domain, "breaches": [], "stealer_on_website": [],
               "stealer_aliases": [], "risk_level": "LOW"}

    # 1. Domain Breaches
    try:
        req = urllib.request.Request(f"{BASE}/breacheddomain/{domain}", headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
            results["breaches"] = list(data.keys())
            if results["breaches"]:
                results["risk_level"] = "HIGH"
    except Exception as e:
        logger.debug(f"HIBP domain breach: {e}")

    # 2. Stealer Log auf Website (Pro-Feature)
    if api_key:
        try:
            req = urllib.request.Request(
                f"{BASE}/stealerlogwebsitedomain/{domain}", headers=headers)
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
                results["stealer_on_website"] = list(data.keys()) if data else []
                if results["stealer_on_website"]:
                    results["risk_level"] = "CRITICAL"
        except Exception:
            pass

        # 3. Stealer E-Mail-Aliase
        try:
            req = urllib.request.Request(
                f"{BASE}/stealerlogemailaliases/{domain}", headers=headers)
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
                results["stealer_aliases"] = data if isinstance(data, list) else []
        except Exception:
            pass

    # 4. Neuester Breach (täglich prüfen ob neue Breaches für Domain relevant)
    try:
        req = urllib.request.Request(f"{BASE}/latestbreach",
                                     headers={"User-Agent": "MSSP-EASM/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            latest = json.loads(r.read())
            results["latest_global_breach"] = {
                "name": latest.get("Name"),
                "date": latest.get("BreachDate"),
                "count": latest.get("PwnCount"),
            }
    except Exception:
        pass

    logger.info(f"[{tenant_id}] HIBP: {len(results['breaches'])} breaches, "
               f"stealer_on_site={len(results['stealer_on_website'])}, "
               f"risk={results['risk_level']}")
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEDULER + MAINTENANCE
# ═══════════════════════════════════════════════════════════════════════════════

@celery_app.task(
    name="workers.toolchain_tasks.schedule_tenants",
    queue="scheduler"
)
def schedule_tenants(plan: str = "all", scan_type: str = "full"):
    """
    Beat-Scheduler-Task: Startet Scans für alle Mandanten.
    scan_type: full | mcp_only | hibp_only
    """
    tenants = get_all_tenants()
    scheduled = 0

    for tenant in tenants:
        if scan_type == "mcp_only":
            # Nur MCP-Scan
            run_mcp_scan.apply_async(
                args=[tenant["id"], tenant["ip_ranges"]],
                priority=5
            )
        elif scan_type == "hibp_only":
            # Nur HIBP
            run_hibp_check.apply_async(
                args=[tenant["id"], tenant["domain"],
                      tenant.get("api_keys", {}).get("hibp", "")],
                priority=5
            )
        else:
            # Vollständige Pipeline
            run_full_pipeline.apply_async(
                args=[tenant["id"], {
                    "domain": tenant["domain"],
                    "ip_ranges": tenant["ip_ranges"],
                    "panos_version": tenant.get("panos_version", ""),
                    "api_keys": tenant.get("api_keys", {}),
                }],
                priority=5
            )
        scheduled += 1

    logger.info(f"Scheduler: {scheduled} {scan_type}-Scans für Plan '{plan}' eingeplant")
    return {"scan_type": scan_type, "scheduled": scheduled}


@celery_app.task(
    name="workers.toolchain_tasks.update_nuclei_templates",
    queue="maintenance"
)
def update_nuclei_templates():
    """Nuclei-Templates täglich aktualisieren"""
    import subprocess
    try:
        result = subprocess.run(
            ["nuclei", "-update-templates", "-silent"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0:
            logger.info("Nuclei Templates updated successfully")
            return {"status": "updated"}
        else:
            # Docker-Fallback
            subprocess.run(
                ["docker", "run", "--rm",
                 "-v", "nuclei_templates:/root/nuclei-templates",
                 "projectdiscovery/nuclei:latest", "-update-templates"],
                timeout=300
            )
            return {"status": "updated_via_docker"}
    except Exception as e:
        logger.error(f"Nuclei template update failed: {e}")
        return {"status": "failed", "error": str(e)}


@celery_app.task(
    name="workers.toolchain_tasks.check_risk_acceptances",
    queue="alerts"
)
def check_risk_acceptances():
    """Prüft ablaufende Risk-Acceptances (14 Tage Vorwarnung)"""
    # In Produktion: DB-Query
    # SELECT * FROM risk_acceptances WHERE expires_at < NOW() + INTERVAL '14 days'
    logger.info("Risk-Acceptance-Check läuft...")
    return {"checked": 0, "expiring_soon": 0}


@celery_app.task(
    name="workers.toolchain_tasks.check_panos_license_expirations",
    queue="alerts"
)
def check_panos_license_expirations():
    """Prüft ablaufende Palo-Alto-Lizenzen"""
    # In Produktion: für jeden Mandanten PAN-OS API aufrufen
    logger.info("Lizenz-Ablauf-Check läuft...")
    return {"checked": 0, "expiring_critical": 0}


@celery_app.task(
    name="workers.toolchain_tasks.generate_monthly_reports",
    queue="maintenance"
)
def generate_monthly_reports():
    """Monatliche Reports für alle Mandanten generieren"""
    tenants = get_all_tenants()
    logger.info(f"Generiere {len(tenants)} monatliche Reports...")
    return {"reports_queued": len(tenants)}


@celery_app.task(
    name="workers.toolchain_tasks.send_critical_alert",
    queue="alerts",
    priority=10
)
def send_critical_alert(tenant_id: str, findings: list,
                         alert_type: str = "general"):
    """Sofort-Alert bei kritischen Findings"""
    import urllib.request

    logger.warning(f"[{tenant_id}] 🚨 CRITICAL ALERT: {len(findings)} findings")

    # In Produktion: E-Mail + Slack-Webhook + Ticket
    # Demo: Log-Ausgabe
    for f in findings:
        logger.critical(
            f"  [{f.get('tool','?')}] {f.get('title','?')} → {f.get('asset','?')}"
        )

    return {
        "tenant_id": tenant_id,
        "alert_type": alert_type,
        "critical_count": len(findings),
        "sent_at": datetime.datetime.utcnow().isoformat()
    }


# ─── Hilfsfunktionen ──────────────────────────────────────────────────────────

def _score_to_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


def _get_tenant_info(tenant_id: str) -> dict:
    """Loads domain, ip_ranges, panos_version from DB for a tenant."""
    import psycopg2, psycopg2.extras
    db_url = os.getenv("DATABASE_URL", "")
    if not db_url:
        logger.error("DATABASE_URL not set — cannot load tenant info")
        return {}
    try:
        conn = psycopg2.connect(db_url)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    COALESCE(MIN(d.domain), t.slug, '') AS domain,
                    COALESCE(
                        array_agg(DISTINCT r) FILTER (WHERE r IS NOT NULL), '{}'
                    ) AS ip_ranges,
                    COALESCE(MAX(d.panos_version), '') AS panos_version
                FROM tenants t
                LEFT JOIN domains d
                    ON d.tenant_id = t.id AND d.status = 'active'
                LEFT JOIN LATERAL unnest(d.ip_ranges) AS r ON TRUE
                WHERE t.id = %s
                GROUP BY t.id, t.slug
            """, (tenant_id,))
            row = cur.fetchone()
        conn.close()
        if row:
            return {
                "domain":        row["domain"] or "",
                "ip_ranges":     list(row["ip_ranges"] or []),
                "panos_version": row["panos_version"] or "",
            }
    except Exception as e:
        logger.error(f"Fehler beim Laden der Tenant-Info: {e}")
    return {}


def _build_config(config_dict: dict):
    """Pipeline-Konfiguration aus config_dict aufbauen."""
    from easm.pipeline import PipelineConfig

    scan_type = config_dict.get("scan_type", "full")
    selected = set(scan_type.split(",")) if scan_type != "full" else None

    def _on(key):
        return selected is None or key in selected

    return PipelineConfig(
        api_keys=config_dict.get("api_keys", {}),
        run_subfinder=_on("discovery"),
        run_theharvester=_on("discovery"),
        run_naabu=_on("portscan"),
        run_sslyze=_on("tls"),
        run_httpx=_on("http"),
        run_nuclei=_on("vuln"),
        run_ramparts=_on("mcp"),
        run_mcp_scan=_on("mcp"),
        subfinder_recursive=True,
        naabu_ports="top-1000", naabu_rate=2000, naabu_nmap=True,
        theharvester_full_sources=True, theharvester_limit=1000,
        httpx_screenshots=True, httpx_threads=100,
        nuclei_tags="api,exposure,misconfig,default-login,mcp,cve",
        nuclei_severity="low,medium,high,critical",
        nuclei_rate=150,
        ramparts_llm=False,
    )


def _update_scan_status(job_id: str, status: str,
                         tenant_id: str, data: dict = None):
    """Aktualisiert scan_jobs in DB via psycopg2 (synchron, Celery-kompatibel)."""
    import psycopg2
    db_url = os.getenv("DATABASE_URL", "")
    if not db_url:
        logger.error("DATABASE_URL nicht gesetzt — Status-Update übersprungen")
        return
    try:
        conn = psycopg2.connect(db_url)
        with conn.cursor() as cur:
            if status == "running":
                cur.execute(
                    "UPDATE scan_jobs SET status='running', started_at=NOW() WHERE id=%s",
                    (job_id,)
                )
            elif status == "completed":
                by_sev = data.get("by_severity", {}) if data else {}
                cur.execute("""
                    UPDATE scan_jobs SET
                        status            = 'completed',
                        completed_at      = NOW(),
                        duration_seconds  = %s,
                        risk_score_after  = %s,
                        findings_count    = %s,
                        raw_results       = %s
                    WHERE id = %s
                """, (
                    data.get("duration_seconds") if data else None,
                    data.get("risk_score")       if data else None,
                    json.dumps(by_sev),
                    json.dumps(data or {}),
                    job_id,
                ))
            elif status in ("failed", "error"):
                cur.execute("""
                    UPDATE scan_jobs SET
                        status        = 'error',
                        completed_at  = NOW(),
                        error_message = %s
                    WHERE id = %s
                """, (
                    (data or {}).get("error", "unknown error"),
                    job_id,
                ))
        conn.commit()
        conn.close()
        logger.info(f"[{job_id[:8]}] Status → {status}")
    except Exception as exc:
        logger.error(f"_update_scan_status DB-Fehler: {exc}")


def _update_scan_progress(job_id: str, pct: int, phase: str = ""):
    """Updates progress_pct in raw_results so the frontend poll sees real progress."""
    import psycopg2
    db_url = os.getenv("DATABASE_URL", "")
    if not db_url:
        return
    try:
        conn = psycopg2.connect(db_url)
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE scan_jobs
                SET raw_results = COALESCE(raw_results, '{}'::jsonb)
                    || jsonb_build_object('progress_pct', %s, 'current_phase', %s)
                WHERE id = %s
            """, (pct, phase, job_id))
        conn.commit()
        conn.close()
    except Exception as exc:
        logger.warning(f"_update_scan_progress failed: {exc}")


def _save_report(tenant_id: str, job_id: str, report):
    """Speichert Findings, Assets, MCP-Server und Score in DB."""
    import psycopg2, psycopg2.extras, hashlib as _hl
    db_url = os.getenv("DATABASE_URL", "")
    if not db_url:
        logger.error("DATABASE_URL nicht gesetzt — Report nicht gespeichert")
        return

    try:
        conn = psycopg2.connect(db_url)
        saved_findings = 0
        saved_assets   = 0
        saved_mcp      = 0

        with conn.cursor() as cur:
            # ── Findings ──────────────────────────────────────────────────
            for f in report.all_findings:
                fp = _hl.sha256(
                    f"{tenant_id}:{f.category}:{f.affected_asset}:{f.cve_id or f.title}".encode()
                ).hexdigest()
                cur.execute("""
                    INSERT INTO findings_v2
                        (id, tenant_id, scan_job_id, sev, cat, tool,
                         title, asset, cve, cvss, kev, "desc", fix,
                         fingerprint, first_seen, last_seen)
                    VALUES
                        (gen_random_uuid()::text, %s, %s, %s, %s, %s,
                         %s, %s, %s, %s, %s, %s, %s,
                         %s, NOW(), NOW())
                    ON CONFLICT (fingerprint) DO UPDATE SET
                        sev       = EXCLUDED.sev,
                        cvss      = EXCLUDED.cvss,
                        kev       = EXCLUDED.kev,
                        scan_job_id = EXCLUDED.scan_job_id,
                        last_seen = NOW()
                """, (
                    tenant_id, job_id,
                    f.severity, f.category, f.tool,
                    f.title, f.affected_asset,
                    getattr(f, "cve_id",    None),
                    getattr(f, "cvss_score", None),
                    bool(getattr(f, "cisa_kev", False)),
                    f.description,
                    getattr(f, "remediation", None),
                    fp,
                ))
                saved_findings += 1

            # ── Assets (Subdomains + IPs) ──────────────────────────────
            seen_assets = set()
            for fqdn in report.subdomains_discovered:
                if fqdn in seen_assets:
                    continue
                seen_assets.add(fqdn)
                cur.execute("""
                    INSERT INTO assets
                        (id, tenant_id, fqdn, ip, org, asn,
                         ports, risk, sources, takeover, technologies,
                         first_seen, last_seen)
                    VALUES
                        (gen_random_uuid()::text, %s, %s,
                         NULL, NULL, NULL,
                         '{}', 'LOW', ARRAY['subfinder'], FALSE, '[]',
                         NOW(), NOW())
                    ON CONFLICT DO NOTHING
                """, (tenant_id, fqdn))
                saved_assets += 1

            for host, ports in report.open_ports.items():
                port_list = [int(p) for p in ports
                             if isinstance(p, int) or (isinstance(p, str) and p.isdigit())]
                cur.execute("""
                    INSERT INTO assets
                        (id, tenant_id, fqdn, ip, org, asn,
                         ports, risk, sources, takeover, technologies,
                         first_seen, last_seen)
                    VALUES
                        (gen_random_uuid()::text, %s, %s,
                         NULL, NULL, NULL,
                         %s::integer[], 'MEDIUM', ARRAY['naabu'], FALSE, '[]',
                         NOW(), NOW())
                    ON CONFLICT DO NOTHING
                """, (tenant_id, host, port_list))
                saved_assets += 1

            # ── MCP Servers ────────────────────────────────────────────
            for url in getattr(report, "mcp_servers_found", []):
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                except Exception:
                    port = 8080
                cur.execute("""
                    INSERT INTO mcp_servers
                        (id, tenant_id, url, port, auth, risk, first_seen)
                    VALUES
                        (gen_random_uuid()::text, %s, %s, %s, FALSE, 'CRITICAL', NOW())
                    ON CONFLICT DO NOTHING
                """, (tenant_id, url, port))
                saved_mcp += 1

            # ── Tenant Risk Score ──────────────────────────────────────
            by_sev = report.stats.get("by_severity", {})
            cur.execute("""
                INSERT INTO tenant_scores
                    (id, tenant_id, score, grade, findings_summary, asset_counts, recorded_at)
                VALUES
                    (gen_random_uuid()::text, %s, %s, %s, %s::jsonb, '{}'::jsonb, NOW())
                ON CONFLICT (tenant_id) DO UPDATE SET
                    score            = EXCLUDED.score,
                    grade            = EXCLUDED.grade,
                    findings_summary = EXCLUDED.findings_summary,
                    recorded_at      = NOW()
            """, (
                tenant_id,
                report.risk_score,
                _score_to_grade(report.risk_score),
                json.dumps(by_sev),
            ))

            # ── Intel Snapshot (Hosting Analysis + FQDN Inventory) ────
            cur.execute("""
                SELECT fqdn, ip::text, org, asn, risk
                FROM assets WHERE tenant_id = %s
                ORDER BY risk, fqdn NULLS LAST
            """, (tenant_id,))
            asset_rows = cur.fetchall()

            # FQDN table
            fqdn_table = [
                {
                    "fqdn":    r[0] or "—",
                    "ip":      r[1] or "—",
                    "org":     r[2] or "—",
                    "asn":     r[3] or 0,
                    "netblock": "—",
                    "country": "—",
                    "risk":    r[4] or "LOW",
                }
                for r in asset_rows if r[0] or r[1]
            ]

            # Hosting orgs aggregation
            from collections import Counter as _Counter
            org_counts = _Counter(
                r[2] for r in asset_rows if r[2]
            )
            total_assets = len(asset_rows) or 1
            _palette = ["#22c55e", "#3b82f6", "#f59e0b", "#ec4899", "#8b5cf6",
                        "#06b6d4", "#f97316", "#a855f7", "#14b8a6", "#ef4444"]
            hosting_orgs = [
                {
                    "name":  org,
                    "count": cnt,
                    "pct":   round(cnt / total_assets * 100, 1),
                    "asn":   0,
                    "color": _palette[i % len(_palette)],
                }
                for i, (org, cnt) in enumerate(org_counts.most_common(10))
            ]

            intel_data = {
                "hosting_orgs": hosting_orgs,
                "fqdn_table":   fqdn_table,
                "geo_assets":   [],
            }
            cur.execute("""
                INSERT INTO intel_snapshots (id, tenant_id, data, created_at)
                VALUES (gen_random_uuid()::text, %s, %s::jsonb, NOW())
            """, (tenant_id, json.dumps(intel_data)))

        conn.commit()
        conn.close()
        logger.info(
            f"[{tenant_id}] Report gespeichert: "
            f"{saved_findings} Findings, {saved_assets} Assets, {saved_mcp} MCP-Server"
        )
    except Exception as exc:
        logger.error(f"_save_report DB-Fehler: {exc}")
        import traceback
        logger.error(traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════════
# NEUE INTELLIGENCE-TASKS: SpyOnWeb, IP-Reputation, Threat-Intel
# ═══════════════════════════════════════════════════════════════════════════════

@celery_app.task(
    name="workers.toolchain_tasks.run_spyonweb_scan",
    queue="intel",
    rate_limit="60/h"   # SpyOnWeb API-Limit respektieren
)
def run_spyonweb_scan(plan_or_tenant: str, domain: str = None,
                       ips: list = None):
    """
    SpyOnWeb Reverse-OSINT Scan.

    Für jede Domain prüft:
    1. Welche anderen Domains teilen dieselbe Google Analytics ID?
    2. Welche Domains teilen denselben AdSense-Code?
    3. Welche Domains sind auf derselben IP gehostet?

    Findet Shadow-Domains, Schwester-Unternehmen und Typosquatting.
    """
    # In Produktion: from easm.tool_adapters import SpyOnWebAdapter

    tenants = get_tenants_by_plan(plan_or_tenant) if not domain else [
        {"id": plan_or_tenant, "domain": domain,
         "ip_ranges": ips or [], "api_keys": {}}
    ]

    results = []
    for tenant in tenants:
        api_key = tenant.get("api_keys", {}).get("spyonweb", "")
        if not api_key:
            logger.debug(f"[{tenant['id']}] SpyOnWeb: kein API-Key konfiguriert")
            continue

        # SpyOnWebAdapter(api_key).run(tenant["id"], tenant["domain"])
        # In Produktion: Ergebnisse in DB speichern
        logger.info(f"[{tenant['id']}] SpyOnWeb: Scanning {tenant['domain']}")
        results.append({
            "tenant_id": tenant["id"],
            "domain": tenant["domain"],
            "status": "queued",
        })

    return {"spyonweb_scans": len(results)}


@celery_app.task(
    name="workers.toolchain_tasks.run_ip_reputation_check",
    queue="intel",
    rate_limit="100/m"
)
def run_ip_reputation_check(plan_or_tenant: str, ip_list: list = None):
    """
    IP-Reputation-Check via GreyNoise + AbuseIPDB.

    Prüft alle bekannten Kunden-IPs (aus Port-Scan-Ergebnissen) gegen:
    - GreyNoise: Mass-Scanner vs. gezielte Angreifer
    - AbuseIPDB: Community-gemeldete Bad-IPs (Confidence-Score)

    WARUM NICHT HONEYDB:
    HoneyDB Community-Tier = nicht-kommerziell only.
    Für MSSP-SaaS-Nutzung: OEM-Lizenz erforderlich (Preis auf Anfrage).
    GreyNoise + AbuseIPDB haben explizite MSSP-kommerzielle Pläne.
    """
    tenants = get_tenants_by_plan(plan_or_tenant) if not ip_list else [
        {"id": plan_or_tenant, "ip_ranges": ip_list, "api_keys": {}}
    ]

    total_checked = 0
    total_findings = 0

    for tenant in tenants:
        api_keys = tenant.get("api_keys", {})
        gn_key = api_keys.get("greynoise", "")
        ab_key = api_keys.get("abuseipdb", "")

        if not gn_key and not ab_key:
            continue

        # IPs aus Port-Scan-Ergebnissen laden (in Produktion: DB-Query)
        ips = tenant.get("ip_ranges", [])
        if not ips:
            continue

        # IPReputationAdapter(gn_key, ab_key).check_ips(tenant["id"], ips)
        logger.info(
            f"[{tenant['id']}] IP-Reputation: {len(ips)} IPs "
            f"via {'GreyNoise' if gn_key else ''}"
            f"{'+' if gn_key and ab_key else ''}"
            f"{'AbuseIPDB' if ab_key else ''}"
        )
        total_checked += len(ips)

    return {
        "tenants_checked": len(tenants),
        "ips_checked": total_checked,
        "findings": total_findings,
    }


@celery_app.task(
    name="workers.toolchain_tasks.run_threat_intel_check",
    queue="intel",
    rate_limit="200/h"
)
def run_threat_intel_check(plan_or_tenant: str,
                            indicators: list = None):
    """
    Threat-Intelligence IOC-Check via AlienVault OTX + MISP.

    Prüft Domains, IPs und Hashes gegen bekannte Threat-Intelligence-Feeds.

    WARUM NICHT CISA AIS DIREKT:
    - PKI-Zertifikat von Federal Bridge CA: $500-2000, US-Registrare only
    - Interconnection Agreement + statische IPs erforderlich
    - TAXII 1.1 Legacy-Protokoll, schlechte Python-Library-Unterstützung
    - Feed sehr US-lastig, für deutsche KMU begrenzt relevant
    - Onboarding: 4-8 Wochen

    STATTDESSEN (AIS-Daten sind trotzdem verfügbar):
    - AlienVault OTX: inkl. vieler US-Gov Threat-Pulses, kostenlos
    - MISP mit OpenCTI-Connector: AIS-Feed fließt hier automatisch ein
    - BSI-MISP-Feed: Deutschland-spezifische IOCs, NIS2-relevant
    - CIRCL MISP: EU/Benelux-fokussiert
    """
    tenants = get_tenants_by_plan(plan_or_tenant)
    total = 0

    for tenant in tenants:
        api_keys = tenant.get("api_keys", {})
        otx_key = api_keys.get("alienvault_otx", "")
        misp_url = api_keys.get("misp_url", "")
        misp_key = api_keys.get("misp_key", "")

        if not otx_key and not (misp_url and misp_key):
            continue

        # In Produktion: Domains + IPs aus DB laden, dann prüfen
        # ThreatIntelAdapter(otx_key, misp_url, misp_key)
        #   .check_domain(tenant["id"], tenant["domain"])
        logger.info(
            f"[{tenant['id']}] Threat-Intel via "
            f"{'OTX ' if otx_key else ''}"
            f"{'MISP' if misp_url else ''}"
        )
        total += 1

    return {"tenants_processed": total}


@celery_app.task(
    name="workers.toolchain_tasks.run_intelligence_full",
    queue="intel"
)
def run_intelligence_full(tenant_id: str, config: dict):
    """
    Vollständiger Intelligence-Scan für einen Mandanten.
    Orchestriert alle drei neuen Intelligence-Adapter:
      1. SpyOnWeb → verbundene Domains via Analytics-IDs
      2. GreyNoise + AbuseIPDB → IP-Reputation aller bekannten Assets
      3. AlienVault OTX + MISP → IOC-Abgleich Domains + IPs
    """
    domain = config.get("domain", "")
    ips = config.get("known_ips", [])
    api_keys = config.get("api_keys", {})

    results = {
        "tenant_id": tenant_id,
        "spyonweb": {"status": "skipped"},
        "ip_reputation": {"status": "skipped"},
        "threat_intel": {"status": "skipped"},
    }

    # 1. SpyOnWeb
    if api_keys.get("spyonweb"):
        run_spyonweb_scan.delay(tenant_id, domain, ips)
        results["spyonweb"]["status"] = "queued"

    # 2. IP-Reputation
    if api_keys.get("greynoise") or api_keys.get("abuseipdb"):
        run_ip_reputation_check.delay(tenant_id, ips)
        results["ip_reputation"]["status"] = "queued"

    # 3. Threat-Intel
    if api_keys.get("alienvault_otx") or api_keys.get("misp_url"):
        run_threat_intel_check.delay(tenant_id)
        results["threat_intel"]["status"] = "queued"

    logger.info(
        f"[{tenant_id}] Intelligence-Full: "
        f"spyonweb={results['spyonweb']['status']}, "
        f"ip_rep={results['ip_reputation']['status']}, "
        f"ti={results['threat_intel']['status']}"
    )
    return results
