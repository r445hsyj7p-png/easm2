---
sidebar_position: 1
---

# Monitoring

## Grafana

```
https://grafana.<APP_DOMAIN>
Login: admin / <GRAFANA_ADMIN_PASSWORD>
```

Vorkonfigurierte Dashboards:
- **EASM Overview** — Scan-Status, Findings-Trends, Worker-Auslastung
- **PostgreSQL** — Query-Zeiten, Verbindungen, Locks
- **Redis** — Memory, Throughput, Queue-Längen

## Celery Flower

```
https://flower.<APP_DOMAIN>
Login: admin / <FLOWER_BASIC_AUTH>
```

Zeigt alle laufenden und erledigten Tasks, Worker-Status, Queue-Längen.

## Logs

```bash
make logs            # Alle Services
make logs-api        # Nur API
make logs-worker     # Nur Worker
make logs-scan       # Nur Scan-Worker (verbose)
```

## Health Checks

```bash
# API
curl https://<APP_DOMAIN>/api/v1/health

# Alle Services
make ps
```
