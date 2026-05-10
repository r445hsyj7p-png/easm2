---
sidebar_position: 4
title: Updates
---

# Updates

## Plattform-Update

```bash
# 1. Repository aktualisieren
git pull origin main

# 2. Images neu bauen
make build

# 3. Services rollierend neu starten (Zero-Downtime)
docker compose up -d --no-deps api
docker compose up -d --no-deps worker-scan worker-hibp worker-alerts
docker compose up -d --no-deps frontend
```

Migrationen laufen automatisch beim API-Container-Start.

## Nuclei-Template-Update

Nuclei-Templates werden täglich automatisch aktualisiert (01:00 UTC via Celery Beat).

```bash
# Manuell:
make update-nuclei
```

## Security-Updates (Betriebssystem)

Da alle Services in Containern laufen, genügt ein Image-Rebuild:

```bash
# Images mit aktuellem Base-Image (python:3.11-slim) neu bauen
docker compose build --no-cache
docker compose up -d
```

Empfohlen: Monatlich oder bei bekannten CVEs in den Base-Images.

## Datenbank-Migrationen

Migrationen laufen automatisch. Für manuelle Ausführung:

```bash
make migrate

# Migrationsstatus prüfen
docker compose exec api alembic current
docker compose exec api alembic history
```

## Changelog prüfen

Vor jedem Update die `CHANGELOG.md` im Repository lesen — Breaking Changes werden dort dokumentiert.
