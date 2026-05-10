---
sidebar_position: 3
title: Skalierung
---

# Skalierung

## Horizontale Worker-Skalierung

Die Scan-Worker sind der Engpass bei hohem Durchsatz. Sie können horizontal skaliert werden:

```bash
# 4 Scan-Worker statt 2 (Standard)
docker compose up -d --scale worker-scan=4
```

**Faustregeln:**
- 1 `worker-scan`-Instanz: ~3-5 Domains parallel
- 1 `worker-hibp`-Instanz: ~2 Domains (HIBP Rate-Limit)
- CPU-Limit pro Worker: 2 vCPU, 2GB RAM (in `docker-compose.yml` konfiguriert)

## API-Skalierung

```bash
# Mehr Uvicorn-Worker
# In .env:
UVICORN_WORKERS=8

# Oder mehrere API-Container (benötigt shared Session-Store):
docker compose up -d --scale api=3
```

## Ressource-Empfehlungen

| Mandanten | vCPU | RAM | Worker-Replicas |
|---|---|---|---|
| 1-5 | 4 | 8 GB | 2 |
| 5-20 | 8 | 16 GB | 4 |
| 20-50 | 16 | 32 GB | 8 |
| 50+ | 32+ | 64 GB+ | 12+ |

## PostgreSQL-Tuning

Für grössere Installationen in `docker-compose.yml` anpassen:

```yaml
postgres:
  command: >
    postgres
    -c max_connections=200
    -c shared_buffers=2GB
    -c effective_cache_size=6GB
    -c maintenance_work_mem=512MB
    -c checkpoint_completion_target=0.9
```

## Redis-Tuning

```yaml
redis:
  command: >
    redis-server
    --maxmemory 2gb
    --maxmemory-policy allkeys-lru
    --save 60 1000
```

## Monitoring für Skalierungsentscheidungen

Grafana-Dashboard zeigt:
- Celery Queue-Tiefe (Backpressure-Indikator)
- Worker CPU/Memory-Auslastung
- Scan-Durchlaufzeiten
- API-Latenz (p50/p95/p99)

Wenn Queue-Tiefe konstant > 10: Worker-Replicas erhöhen.
