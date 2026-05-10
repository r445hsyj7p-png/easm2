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
            "schedule": crontab(minute=0),
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


# ─── Demo-Tenant-Datenbank ────────────────────────────────────────────────────
# In Produktion: echte DB-Abfrage via SQLAlchemy
DEMO_TENANTS = [
    {
        "id": "t-stadtwerke", "name": "Stadtwerke Herford AöR",
        "domain": "stadtwerke-herford.de",
        "ip_ranges": ["192.0.2.0/24"],
        "panos_version": "10.1.11",
        "api_keys": {},
    },
    {
        "id": "t-mueller", "name": "Müller GmbH",
        "domain": "mueller-gmbh.de",
        "ip_ranges": ["203.0.113.0/24"],
        "panos_version": "10.2.7",
        "api_keys": {},
    },
    {
        "id": "t-technova", "name": "TechNova AG",
        "domain": "technova-ag.de",
        "ip_ranges": ["198.51.100.0/24"],
        "panos_version": "11.1.3",
        "api_keys": {},
    },
]


def get_all_tenants() -> list:
    return DEMO_TENANTS


def get_tenants_by_plan(plan: str = "all") -> list:
    """Gibt alle Mandanten zurück — kein Plan-Filter mehr."""
    return DEMO_TENANTS


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
    from pipeline.orchestrator import EASMPipeline, PipelineConfig

    job_id = self.request.id
    logger.info(f"[{job_id}] [req={request_id}] Pipeline START: tenant={tenant_id}")

    try:
        # Status: Running
        _update_scan_status(job_id, "running", tenant_id)

        # Plan-spezifische Konfiguration
        config = _build_config(config_dict)

        # Pipeline ausführen
        pipeline = EASMPipeline(tenant_id=tenant_id, config=config)
        report = pipeline.run(
            domain=config_dict.get("domain", ""),
            ip_ranges=config_dict.get("ip_ranges", []),
            panos_version=config_dict.get("panos_version", "")
        )

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
    from adapters.tool_adapters import SubfinderAdapter, TheHarvesterAdapter

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
    from adapters.tool_adapters import NaabuAdapter

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
    from adapters.tool_adapters import HTTPXAdapter

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
    from adapters.tool_adapters import NucleiAdapter

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
    from adapters.tool_adapters import NucleiAdapter, RampartsAdapter

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
    name="workers.toolchain_tasks.check_license_expirations",
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

def _build_config(plan: str, config_dict: dict):
    """Plan-spezifische Pipeline-Konfiguration"""
    from pipeline.orchestrator import PipelineConfig

    # Alle Features für alle Mandanten — kein Plan-Limit
    return PipelineConfig(
        api_keys=config_dict.get("api_keys", {}),
        run_subfinder=True, run_naabu=True, run_theharvester=True,
        run_httpx=True, run_nuclei=True, run_ramparts=True,
        run_sslyze=True, run_mcp_scan=True,
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
    """Scan-Status in DB aktualisieren"""
    logger.info(f"Scan {job_id[:8]}... [{tenant_id}]: {status}")
    # In Produktion: DB-Update via SQLAlchemy


def _save_report(tenant_id: str, job_id: str, report):
    """Pipeline-Report in DB speichern"""
    logger.info(
        f"Speichere Report: tenant={tenant_id}, "
        f"findings={report.stats.get('total_findings',0)}, "
        f"score={report.risk_score}"
    )
    # In Produktion:
    # with SessionLocal() as db:
    #     for finding in report.all_findings:
    #         db_finding = Finding(tenant_id=tenant_id, ...)
    #         db.merge(db_finding)  # upsert via fingerprint
    #     db.commit()


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
    import sys
    sys.path.insert(0, '/mnt/user-data/outputs')
    # In Produktion: from adapters.tool_adapters import SpyOnWebAdapter
    # Hier Demo-Implementierung

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
