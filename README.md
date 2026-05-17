# EASM MSSP Platform

External Attack Surface Management für MSSP-Betreiber — produktionsreif, mandantenfähig, ein Befehl startet alles.

## Schnellstart

```bash
git clone <repo> easm-platform && cd easm-platform
cp .env.example .env
# SECRET_KEY, POSTGRES_PASSWORD, REDIS_PASSWORD in .env setzen
make dev
```

Browser öffnen: **http://localhost:8080** — beim ersten Aufruf Ersteinrichtung des Admin-Accounts.

| Service   | URL                         | Zugang              |
|-----------|-----------------------------|---------------------|
| Frontend  | http://localhost:8080       | direkt (Nginx :80)  |
| Frontend  | https://easm.cycl.group     | via Traefik TLS     |
| API Docs  | http://localhost:8000/docs  | direkt              |
| Flower    | http://localhost:5555       | direkt              |

---

## Architektur

```
Browser → Nginx (React SPA)
              ↓ /api/*
          FastAPI (4 Worker)
              ↓              ↓              ↓
        PostgreSQL 16     Redis 7      Celery Workers
        (RLS, Multi-      (Broker,     ├── worker-scan   (Scan-Pipeline)
         Tenant)           Cache)      ├── worker-hibp   (Credential-Checks)
                                       ├── worker-alerts (Benachrichtigungen)
                                       └── scheduler     (Celery Beat)
```

**13 Docker-Services** (Traefik, Frontend, API, 3 Worker-Typen, Beat-Scheduler, PostgreSQL, Redis, Flower, Prometheus, Grafana, Docs, Backup)

---

## Features

### UI-Tabs (8)

| Tab | Inhalt |
|-----|--------|
| **Overview** | Executive-Dashboard: Risk-Score, Findings nach Schweregrad, letzte Scans, Asset-Zähler |
| **Findings** | Alle Security-Findings mit Filter, Suche, Severity-Badge, Status-Workflow (open → acknowledged → fixed) |
| **Assets** | Subdomain-Inventar, IP-Adressen, Ports, ASN, Hosting-Organisation, Takeover-Flag |
| **Scans** | Scan-Pipeline starten, Live-Log-Output, Phasen-Fortschritt, Scan-Historie |
| **Reports** | Executive-/Technik-/MCP-/NIS2-Reports, CSV- und JSON-Export |
| **Intel** | Hosting-Überblick, Geo-Map, Asset-Graph, FQDN-Inventar, Threat-Feeds |
| **MCP** | MCP-Server-Erkennung, Tool-Inventar, Auth-Status, CVE-Zuordnung |
| **Admin** | Domains verwalten, Scan-Zeitplan, Benachrichtigungen, Benutzer & RBAC |

### Query-Suche (15 Filter-Felder)

```
severity:critical has:kev          # CISA KEV + kritische Findings
tool:nuclei severity:critical      # Nuclei CRITICAL
cat:mcp has:no-ticket              # MCP-Findings ohne Ticket
port:6274 OR port:6277             # MCP-Inspector-Ports
cvss:>=9 status:open               # CVSS 9+ offen
age:<1 status:open                 # Heute entdeckt
cve:CVE-2024-3400                  # Spezifische CVE
org:hetzner port:3389              # RDP auf Hetzner-Assets
epss:>=0.9                         # Hochwahrscheinliche Exploits
ip:203.0.113.0/24                  # IP-Range (CIDR)
```

Token werden farbig hervorgehoben. Scope-Erkennung: `port:`, `ip:`, `org:` → Assets; `severity:`, `cvss:`, `has:cve` → Findings.

---

## Scan-Pipeline (6 Phasen)

| Phase | Tool | Prüft auf |
|-------|------|-----------|
| **P1 Discovery** | Subfinder + theHarvester | Subdomains (50+ Quellen), E-Mails, LinkedIn-Profile |
| **P2 Port Scan** | Naabu SYN/UDP | Offene Ports, MCP-Port-Erkennung (6274, 6277, 8080) |
| **P3 TLS Scan** | SSLyze | TLS 1.0/1.1, RC4/3DES, Heartbleed, ROBOT, HSTS, Cert-Ablauf |
| **P4 HTTP Probing** | HTTPX + Screenshots | .env-Dateien, Actuator-Endpunkte, Tech-Stack, Favicon-Hash |
| **P5 Vuln Scan** | Nuclei (7000+ Templates) | CVEs, Default-Credentials, Misconfigs, API-Exposures |
| **P6 MCP Analysis** | Ramparts + Handshake | MCP ohne Auth, Tool-Schema (RCE-Tools), Prompt-Injection |

### Integrierte Tools

| Tool | Typ | Kategorie |
|------|-----|-----------|
| **Subfinder** | Binary | Subdomain-Enumeration |
| **theHarvester** | Python | OSINT (E-Mails, Hosts, LinkedIn) |
| **Naabu** | Binary | Port-Scanning |
| **SSLyze** | Python | TLS-Analyse |
| **HTTPX** | Binary | HTTP-Probing + Screenshots |
| **Nuclei** | Binary | Vulnerability-Scanning |
| **Ramparts** | Python | MCP-Security-Analyse |
| **HIBP API** | API | Credential-Breach-Check |
| **GreyNoise** | API | IP-Reputations-Check |
| **AbuseIPDB** | API | IP-Abuse-Score |
| **AlienVault OTX** | API | Threat-Intelligence-Feeds |
| **MISP** | API | IOC-Abgleich (BSI, CIRCL, OpenCTI) |
| **SpyOnWeb** | API | Analytics-Reverse-Lookup (Shadow-Domains) |

### SSLyze-Findings-Mapping

| Befund | Schweregrad | CVSS |
|--------|-------------|------|
| Heartbleed (CVE-2014-0160) | CRITICAL | 7.5 |
| Zertifikat abgelaufen / läuft in ≤7 Tagen ab | CRITICAL | 7.5 |
| ROBOT-Angriff (RSA-Padding-Orakel) | HIGH | 7.4 |
| Zertifikat läuft in ≤30 Tagen ab | HIGH | 5.3 |
| TLS 1.0 / TLS 1.1 / SSL 2 / SSL 3 aktiv | MEDIUM | 5.9 |
| Schwache Cipher Suites (RC4, 3DES, EXPORT) | MEDIUM | 5.3 |
| Self-signed / ungültiges Zertifikat | MEDIUM | 5.3 |
| HSTS nicht konfiguriert | LOW | 3.1 |

---

## Backend-API

**Authentifizierung**
- `POST /api/v1/auth/setup` — Ersteinrichtung Admin
- `POST /api/v1/auth/login` — Login → JWT (12h)
- `GET  /api/v1/auth/status` — Auth-Status

**Mandanten & Assets**
- `GET  /api/v1/tenants/{id}` — Mandanten-Details
- `GET  /api/v1/tenants/{id}/assets` — Asset-Inventar (filter: risk, org, port)
- `GET  /api/v1/tenants/{id}/findings` — Findings (filter: severity, tool, status, cat)
- `PATCH /api/v1/tenants/{id}/findings/{fid}` — Status / Notizen aktualisieren

**Scans**
- `POST /api/v1/tenants/{id}/scans` — Scan auslösen
- `GET  /api/v1/tenants/{id}/scans` — Scan-Historie
- `GET  /api/v1/tenants/{id}/scans/{scan_id}` — Ergebnis-Detail

**Intelligence & MCP**
- `GET  /api/v1/tenants/{id}/intel` — Threat-Intelligence-Aggregation
- `GET  /api/v1/tenants/{id}/mcp` — MCP-Server-Ergebnisse

**MSSP**
- `GET  /api/v1/mssp/dashboard` — Mandanten-übergreifende Metriken

**Suche**
- `GET  /api/v1/search?q=...&scope=findings&limit=50` — Unified Search

Interaktive Dokumentation: `/docs` (Swagger) · `/redoc`

---

## Celery-Tasks

**Scan-Worker** (`toolchain_tasks.py`)

| Task | Queue | Beschreibung |
|------|-------|--------------|
| `run_full_pipeline` | scans | Vollständige 6-Phasen-Pipeline |
| `run_discovery` | scans | Subfinder + theHarvester |
| `run_portscan` | scans | Naabu SYN/UDP |
| `run_sslyze` | tls | TLS-Analyse aller HTTPS-Endpunkte |
| `run_http_probe` | http | HTTPX-Probing + Screenshots |
| `run_vuln_scan` | vuln | Nuclei-Vulnerability-Scan |
| `run_mcp_scan` | mcp | MCP-Tiefenanalyse (Nuclei + Ramparts) |
| `run_hibp_check` | hibp | HIBP-Credential-Breach-Check |
| `run_spyonweb_scan` | intel | Analytics-Reverse-Lookup |
| `run_ip_reputation_check` | intel | GreyNoise + AbuseIPDB |
| `run_threat_intel_check` | intel | OTX + MISP IOC-Abgleich |
| `run_intelligence_full` | intel | Vollständige Intelligence-Pipeline |
| `schedule_tenants` | scheduler | Startet Scans für alle Mandanten |
| `send_critical_alert` | alerts | Sofort-Benachrichtigung bei CRITICAL |
| `update_nuclei_templates` | maintenance | Tägliches Template-Update |
| `generate_monthly_reports` | maintenance | Monatliche Reports |

**Beat-Schedules** (täglich, automatisch)

| Zeit (UTC) | Task |
|------------|------|
| 00:00 | Vollscan alle Mandanten |
| 02:00 | Vollscan (zweiter Lauf) |
| 03:00 | Vollscan (Sonntag, wöchentlich) |
| 03:30 | TLS-Scan alle Mandanten |
| 04:00 | MCP-only-Scan |
| 05:00 | SpyOnWeb-Scan |
| 05:30 | IP-Reputation-Check |
| 06:00 | HIBP-Credential-Check |
| 06:30 | Threat-Intel IOC-Check |
| 07:00 | PAN-OS Lizenz-Ablauf-Check |
| 07:30 | Risk-Acceptance-Ablauf-Check |
| 08:00 | Monatliche Reports (1. des Monats) |
| 01:00 | Nuclei Template-Update |

---

## Infrastruktur

### Docker-Services

| Service | Funktion | Port |
|---------|----------|------|
| **traefik** | Reverse-Proxy + Let's Encrypt TLS | 80, 443 |
| **frontend** | React SPA (Vite + Nginx) | **8080** (direkt) · 443 (via Traefik) |
| **api** | FastAPI (4 Worker, async) | 8000 (intern) |
| **worker-scan** | Scan-Pipeline (4 Concurrency, 2 GB RAM) | — |
| **worker-hibp** | HIBP-Checks (rate-limited 10/Min) | — |
| **worker-alerts** | Reports + Alerts (4 Concurrency) | — |
| **scheduler** | Celery Beat | — |
| **postgres** | PostgreSQL 16 (RLS) | 5432 (intern) |
| **redis** | Redis 7 (Broker + Cache, LRU 512 MB) | 6379 (intern) |
| **flower** | Celery-Monitoring | 5555 |
| **prometheus** | Metriken (30 Tage Retention) | 9090 (intern) |
| **grafana** | Dashboards | 3001 |
| **docs** | Docusaurus Dokumentation | 3002 |
| **backup** | PostgreSQL-Backup tägl. 03:00 UTC (30 Tage) | — |

### Datenbank

- **PostgreSQL 16** mit Row-Level-Security (RLS) — kein Mandant sieht Daten eines anderen
- **Alembic** für Migrations
- Automatische tägliche Backups mit 30-Tage-Retention in `./backups/`

### Monitoring

- **Prometheus** scrapet API, Worker und PostgreSQL
- **Grafana** mit vorbereiteten Dashboards (automatisch provisioniert)
- **Flower** für Celery-Task-Monitoring in Echtzeit

---

## Makefile

```bash
# Setup & Lifecycle
make setup          # Erster Start: build + migrate + seed
make dev            # Lokaler Dev-Start (hot-reload, Port 3000)
make up             # Produktionsstart (Traefik + TLS)
make down           # Alles stoppen
make restart        # Neustart
make update         # git pull + rebuild + restart

# Builds
make build          # Alle Images bauen (parallel)
make build-no-cache # Vollständiger Rebuild ohne Cache

# Logs
make logs           # Alle Services
make logs-api       # Nur API
make logs-worker    # Alle Worker
make logs-scan      # Scan-Worker

# Datenbank
make migrate        # Alembic-Migrationen anwenden
make seed           # Demo-Daten laden
make backup-db      # Manuelles Backup
make restore-db BACKUP=<datei>  # Backup einspielen
make shell-db       # psql-Shell

# Scans
make scan DOMAIN=example.de      # Manueller Vollscan
make scan-mcp DOMAIN=example.de  # Nur MCP-Scan
make update-nuclei               # Nuclei-Templates aktualisieren

# Shell-Zugang
make shell-api      # bash in API-Container
make shell-worker   # bash in Scan-Worker

# Wartung
make clean          # Gestoppte Container + ungenutzte Images entfernen
make clean-all      # ⚠️ Alle Volumes löschen (Datenverlust!)
make ps             # Service-Status
```

---

## Umgebungsvariablen

**Pflicht**

| Variable | Beschreibung |
|----------|--------------|
| `SECRET_KEY` | JWT-Signing-Key (`openssl rand -hex 32`) |
| `POSTGRES_PASSWORD` | Datenbank-Passwort |
| `REDIS_PASSWORD` | Redis-Passwort |

**Produktion**

| Variable | Beschreibung |
|----------|--------------|
| `APP_DOMAIN` | Hauptdomain (z.B. `easm.mssp.de`) |
| `DOCS_DOMAIN` | Docs-Subdomain |
| `GRAFANA_DOMAIN` | Grafana-Subdomain |
| `LETSENCRYPT_EMAIL` | E-Mail für Let's Encrypt |

**Scan-Erweiterungen (optional)**

| Variable | Dienst |
|----------|--------|
| `HIBP_API_KEY` | Have I Been Pwned (Breach-Check) |
| `SHODAN_API_KEY` | Shodan (passive Recon) |
| `SECURITYTRAILS_API_KEY` | SecurityTrails (DNS-History) |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | Censys (Zertifikate) |
| `VIRUSTOTAL_API_KEY` | VirusTotal (URL/File-Scoring) |
| `GITHUB_TOKEN` | GitHub (Secret-Scanning) |
| `ANTHROPIC_API_KEY` | Claude API (LLM-gestützte MCP-Analyse) |
| `GREYNOISE_API_KEY` | GreyNoise (IP-Reputaton) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB (IP-Abuse-Score) |
| `ALIENVAULT_OTX_KEY` | AlienVault OTX (Threat-Intel) |
| `MISP_URL` / `MISP_KEY` | MISP (IOC-Abgleich) |
| `SPYONWEB_API_KEY` | SpyOnWeb (Analytics-Reverse-Lookup) |

**Benachrichtigungen**

| Variable | Beschreibung |
|----------|--------------|
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | E-Mail-Alerts |
| `SLACK_WEBHOOK_URL` | Slack-Alerts (CRITICAL sofort) |

**Scan-Tuning**

| Variable | Standard | Beschreibung |
|----------|----------|--------------|
| `SCAN_CONCURRENCY` | 4 | Parallele Scan-Tasks |
| `NAABU_RATE` | 1000 | Port-Scan-Rate (pps) |
| `HTTPX_SCREENSHOTS` | true | Screenshots aktivieren |

---

## Dokumentation

Die integrierte Docusaurus-Dokumentation (http://localhost:3002) umfasst:

- **Getting Started** — Installation, Konfiguration, Erster Scan
- **Architektur** — Backend, Datenbank, Tools-Übersicht, MCP-Erkennung
- **API-Referenz** — Alle Endpunkte (Findings, Assets, Scans, Reports, Tenants)
- **UI-Guides** — Tab-für-Tab-Erklärung inkl. Query-Syntax-Referenz
- **Operations** — Backups, Monitoring, Skalierung, Troubleshooting, Updates

---

## Architektur-Entscheidungen

- **Kein Demo-Code im API-Pfad** — alle Endpunkte lesen aus PostgreSQL
- **Demo-Daten nur via `make seed`** — einmaliger Import, dann echte DB
- **Async überall** — FastAPI + asyncpg + SQLAlchemy async
- **JWT (12h) + bcrypt** — Passwort-Hashing, Token-Rotation
- **Row-Level Security** — PostgreSQL RLS verhindert Mandanten-Datenlecks auf DB-Ebene
- **Celery-Queue-Routing** — jedes Tool hat eine eigene Queue (tls, vuln, mcp, hibp, intel) für unabhängige Skalierung
- **SSLyze nativ in Python** — kein Binary erforderlich, direkte Integration in Worker
- **Ramparts + Nuclei kombiniert** — MCP-Erkennung auf Netzwerk- und Protokollebene

---

## Lizenz

MIT
