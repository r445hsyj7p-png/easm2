---
sidebar_position: 1
---

# Architektur-Übersicht

## Stack

```
Browser
  └── Traefik (TLS-Terminierung, Routing)
        ├── Frontend  — React SPA (Vite + Nginx)
        ├── API       — FastAPI (Uvicorn, 4 Worker)
        ├── Docs      — Docusaurus (Nginx)
        ├── Flower    — Celery Monitoring
        └── Grafana   — Metriken

API
  ├── PostgreSQL 16  (Row-Level Security, Multi-Tenant)
  └── Redis 7        (Celery Broker + Cache)

Redis
  ├── worker-scan    (Subfinder, Naabu, HTTPX, Nuclei, Ramparts)
  ├── worker-hibp    (HIBP Credential-Checks, rate-limited)
  ├── worker-alerts  (E-Mail, Slack, Reports)
  └── scheduler      (Celery Beat, tägliche Scans)
```

## Service-Kommunikation

Alle Services kommunizieren über ein internes Docker-Netzwerk (`easm`). Nach außen ist nur Traefik auf Port 80/443 exponiert.

```
Internet → Traefik:443 → Services (intern, kein direkter Zugriff)
```

## Datenbankisolation

Jeder Mandant hat eigene Zeilen in allen Tabellen. PostgreSQL Row-Level Security (RLS) stellt sicher, dass kein Mandant Daten anderer Mandanten lesen kann — auch bei SQL-Injection.

Die API setzt vor jedem Query:
```sql
SET app.current_tenant_id = '<uuid>';
```

## Scan-Pipeline (5 Phasen)

| Phase | Tool | Dauer | Output |
|---|---|---|---|
| 1 | Subfinder + theHarvester | ~40s | Subdomains, E-Mails |
| 2 | Naabu | ~28s | Offene Ports, Services |
| 3 | HTTPX | ~34s | HTTP-Infos, Screenshots, Tech-Stack |
| 4 | Nuclei | ~67s | CVEs, Fehlkonfigurationen |
| 5 | Ramparts | ~12s | MCP-Server-Exposition |
