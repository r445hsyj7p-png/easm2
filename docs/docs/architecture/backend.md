---
sidebar_position: 2
title: Backend
---

# Backend-Architektur

## Stack

| Komponente | Technologie | Zweck |
|---|---|---|
| API-Framework | FastAPI 0.115 | REST-Endpunkte, OpenAPI-Schema |
| ASGI-Server | Uvicorn 0.30 | 4 Worker-Prozesse |
| Task Queue | Celery 5.3 | Asynchrone Scan-Jobs |
| Message Broker | Redis 7 | Celery-Queue + Cache |
| Datenbank | PostgreSQL 16 | Persistenz, Multi-Tenant RLS |
| ORM | SQLAlchemy 2.0 | Async DB-Zugriff |
| Migrationen | Alembic | Schema-Versioning |

## API-Service

Der `api`-Container startet mit 4 Uvicorn-Worker-Prozessen. Das Entrypoint-Script führt automatisch `alembic upgrade head` aus — Datenbankmigrationen sind immer aktuell ohne manuellen Eingriff.

```
Request → Traefik (TLS) → Uvicorn → FastAPI Router
                                    ├── /api/v1/auth/
                                    ├── /api/v1/tenants/
                                    ├── /api/v1/findings/
                                    ├── /api/v1/assets/
                                    ├── /api/v1/scans/
                                    ├── /api/v1/reports/
                                    └── /api/v1/health
```

## Celery Worker-Architektur

```
Redis (Broker)
  Queues: scans | http | vuln | mcp | hibp | alerts
       │
  ├── worker-scan   (2 Replicas) — Subfinder/Naabu/HTTPX/Nuclei/Ramparts
  ├── worker-hibp   (rate-limited) — Credential-Checks via HIBP
  ├── worker-alerts — E-Mail/Slack Notifications + Reports
  └── scheduler     — Celery Beat, zeitgesteuerte Scans
```

### Scan-Pipeline: 5 Phasen

| Phase | Tool | Dauer | Output |
|---|---|---|---|
| 1 — Discovery | Subfinder + theHarvester | ~40s | Subdomains, E-Mails |
| 2 — Port-Scan | Naabu SYN | ~28s | Offene Ports |
| 3 — HTTP-Probe | HTTPX | ~34s | Services, Tech-Stack |
| 4 — Vuln-Scan | Nuclei (7000+ Templates) | ~67s | CVEs, Misconfigs |
| 5 — MCP-Scan | Ramparts | ~12s | MCP-Server, Tools |

### Beat-Schedules (Standard)

| Task | Intervall |
|---|---|
| Full Pipeline Scan | täglich 08:00 UTC |
| MCP-Only Scan | täglich 04:00 UTC |
| HIBP Credential Check | täglich 06:00 UTC |
| Nuclei Template Update | täglich 01:00 UTC |
| Deep Scan (UDP + full) | sonntags 02:00 UTC |

## Authentifizierung

JWT Bearer Token (HS256) für UI-Zugriff, API Key für programmatischen Zugriff. PostgreSQL Row-Level Security isoliert Tenant-Daten auf Datenbankebene.
