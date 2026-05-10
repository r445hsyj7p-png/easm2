---
sidebar_position: 5
title: Troubleshooting
---

# Troubleshooting

## Häufige Probleme

### Container startet nicht

```bash
# Logs prüfen
docker compose logs api --tail=50
docker compose logs worker-scan --tail=50

# Status aller Services
docker compose ps
```

### API nicht erreichbar

1. Traefik-Logs prüfen: `docker compose logs traefik`
2. Domain in `.env` korrekt? `APP_DOMAIN=easm-mssp.de`
3. Port 80/443 freigegeben? `ufw allow 80 && ufw allow 443`
4. DNS-Eintrag zeigt auf Server? `dig easm-mssp.de`

### Scans starten nicht

```bash
# Celery-Worker-Status
docker compose exec scheduler celery -A workers.toolchain_tasks inspect active

# Redis erreichbar?
docker compose exec redis redis-cli ping

# Queue-Inhalt
docker compose exec scheduler celery -A workers.toolchain_tasks inspect reserved
```

### PostgreSQL-Verbindungsfehler

```bash
# Datenbankverbindung testen
docker compose exec api python -c "
from sqlalchemy import create_engine, text
import os
e = create_engine(os.environ['DATABASE_URL'])
print(e.connect().execute(text('SELECT 1')).scalar())
"

# Passwort stimmt mit .env überein?
grep POSTGRES_PASSWORD .env
```

### Nuclei-Scan findet nichts

```bash
# Templates vorhanden?
docker compose exec worker-scan nuclei -list-templates | wc -l

# Manuell aktualisieren
make update-nuclei

# Test-Scan direkt
docker compose exec worker-scan \
  nuclei -target example.com -tags cve -severity critical,high
```

### MCP-Scanner funktioniert nicht

```bash
# Ramparts erreichbar?
docker compose run --rm easm-ramparts ramparts --version

# Docker Socket gemountet?
docker compose exec worker-scan ls /var/run/docker.sock
```

### TLS-Zertifikat fehlt

```bash
# Traefik-Logs prüfen
docker compose logs traefik | grep -i acme

# Certresolver-Status
docker compose exec traefik cat /certs/acme.json | python3 -m json.tool | grep '"domain"'

# Let's Encrypt Rate-Limits? → traefik staging nutzen (in docker-compose.yml)
```

## Nützliche Befehle

```bash
# Alle Logs live verfolgen
make logs

# Shell in Container
make shell-api
make shell-db

# Datenbankverbindung
docker compose exec postgres psql -U easm easm

# Celery-Status-Dashboard
# → http://localhost:5555 (Flower)

# Grafana-Dashboards
# → http://localhost:3000 (admin/admin beim ersten Start)

# manuellen Scan triggern
make scan DOMAIN=example.de
```

## Support

Bei anhaltenden Problemen:
1. `make logs > debug.log` — komplette Log-Ausgabe sichern
2. `docker compose ps` — Service-Status dokumentieren
3. `.env` prüfen (ohne Secrets) — Konfiguration verifizieren
