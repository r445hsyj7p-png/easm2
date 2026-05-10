# EASM MSSP Platform

Open-Source External Attack Surface Management für MSSP-Betreiber.  
Ein Befehl startet die gesamte Plattform.

## Schnellstart (lokal)

```bash
git clone <repo> easm-platform && cd easm-platform
cp .env.example .env
# Pflicht: SECRET_KEY, POSTGRES_PASSWORD, REDIS_PASSWORD in .env setzen
make dev
```

Öffne **http://localhost:3000** — beim ersten Aufruf wird der Admin-Account angelegt.

| Service  | URL                        |
|----------|----------------------------|
| Frontend | http://localhost:3000      |
| API Docs | http://localhost:8000/docs |
| Flower   | http://localhost:5555      |
| Grafana  | http://localhost:3001      |
| Docs     | http://localhost:3002      |

## Produktion (mit TLS)

```bash
cp .env.example .env
# APP_DOMAIN, LETSENCRYPT_EMAIL und alle Passwörter setzen
make up
```

Traefik übernimmt automatisch Let's Encrypt TLS.

## Was die Platform kann

| Feature | Status |
|---|---|
| Login / Ersteinrichtung | ✓ voll funktional |
| Overview-Dashboard | ✓ voll funktional |
| Remediation Roadmap | ✓ voll funktional |
| Findings-Tab mit Filter + Suche | ✓ voll funktional |
| Assets-Tab mit Weltkarte | ✓ voll funktional |
| MCP-Exposure-Tab | ✓ voll funktional |
| Intelligence / FQDN-Inventar | ✓ voll funktional |
| Query-Suche (15 Filter-Felder) | ✓ voll funktional |
| Scans starten (Celery-Jobs) | ✓ Jobs laufen — Demo-Daten bis DB-Integration |
| Reports generieren | Demo-Daten |
| Echte Scan-Ergebnisse in UI | Nächster Entwicklungsschritt |

> Die UI läuft vollständig auf konsistenten Demo-Daten.  
> Echte Scans (Subfinder, Naabu, Nuclei) laufen in den Workern —  
> die Ergebnisse werden in PostgreSQL gespeichert und in einer  
> nächsten Iteration in die API-Endpunkte integriert.

## Architektur

```
browser → nginx (frontend) → /api/* → FastAPI (api)
                                    → PostgreSQL
                                    → Redis (Celery Broker)
                                    ← Celery Workers (scan, hibp, alerts)
                                    ← Celery Beat (scheduler)
```

## Makefile

```bash
make dev      # Lokaler Start ohne TLS (localhost:3000)
make up       # Produktionsstart mit Traefik + TLS
make down     # Stoppen
make logs     # Alle Logs
make logs-api # Nur API-Logs
make restart  # Neustart
make seed     # Demo-Daten in DB laden
make backup   # Manuelles DB-Backup
make clean    # Volumes löschen (Achtung: löscht alle Daten)
```

## Umgebungsvariablen

Pflichtfelder in `.env` (von `.env.example` kopieren):

| Variable | Beschreibung |
|---|---|
| `SECRET_KEY` | JWT-Signing-Key (min. 32 Zeichen, `openssl rand -hex 32`) |
| `POSTGRES_PASSWORD` | Datenbank-Passwort |
| `REDIS_PASSWORD` | Redis-Passwort |
| `APP_DOMAIN` | Domain für Produktion (z.B. `easm.mssp.de`) |
| `LETSENCRYPT_EMAIL` | E-Mail für Let's Encrypt |

Alle anderen Variablen sind optional und erweitern die Scan-Abdeckung.

## Lizenz

MIT

## Startsequenz (vollständig)

```bash
# 1. Klonen und konfigurieren
git clone <repo> easm-platform && cd easm-platform
cp .env.example .env
# SECRET_KEY, POSTGRES_PASSWORD, REDIS_PASSWORD in .env setzen

# 2. Starten
make dev

# 3. Demo-Daten laden (optional — für sofortige Nutzung)
make seed

# 4. Browser öffnen
# http://localhost:3000
# → Ersteinrichtung: Admin-Account anlegen
# → Dashboard zeigt echte DB-Daten (nach seed) oder leere Ansicht
```

## Produktionsbetrieb

```bash
# .env: APP_DOMAIN, LETSENCRYPT_EMAIL setzen
make up
make seed   # Demo-Daten oder eigene Domains konfigurieren
```

## Architektur-Entscheidungen

- **Kein Demo-Code im API-Pfad** — alle Endpunkte lesen aus PostgreSQL
- **Demo-Daten nur via seed_demo.py** — einmaliger Import, dann echte DB
- **Async überall** — FastAPI + asyncpg + SQLAlchemy async für maximale Performance  
- **JWT-Auth** — 12h Token, SHA-256 Passwort-Hash (bcrypt-ready)
- **Row-Level Security** — PostgreSQL RLS verhindert Mandanten-Datenlecks
