---
sidebar_position: 1
---

# Installation

## Voraussetzungen

| Anforderung | Minimum | Empfohlen |
|---|---|---|
| Docker | 24.0+ | 27.0+ |
| Docker Compose | 2.20+ | 2.28+ |
| RAM | 4 GB | 8 GB |
| CPU | 2 Cores | 4 Cores |
| Disk | 20 GB | 50 GB |
| OS | Ubuntu 22.04 | Ubuntu 24.04 |

Ein öffentlicher DNS-Eintrag ist für automatisches TLS via Let's Encrypt erforderlich.

## Installation

### 1. Repository klonen

```bash
git clone https://github.com/your-org/easm-platform.git
cd easm-platform
```

### 2. Konfiguration

```bash
cp .env.example .env
nano .env  # Pflichtfelder setzen
```

Pflichtfelder:

```env
POSTGRES_PASSWORD=sicheres_passwort_min_32_zeichen
SECRET_KEY=sicherer_jwt_schluessel_min_64_zeichen
REDIS_PASSWORD=redis_passwort
APP_DOMAIN=easm.ihredomain.de
LETSENCRYPT_EMAIL=admin@ihredomain.de
```

### 3. Bauen und starten

```bash
make build    # ~5-10 Minuten beim ersten Mal
make up
make migrate  # Datenbank-Schema erstellen
```

### 4. Verifizieren

```bash
make ps       # Alle Services sollten "Up" zeigen
make logs-api # API-Logs prüfen
```

Die Plattform ist nach ca. 2 Minuten unter `https://<APP_DOMAIN>` erreichbar.

## Lokale Entwicklung

```bash
make dev      # Hot-Reload für Frontend + Backend
# Frontend: http://localhost:3000
# API:      http://localhost:8000/docs
# DB:       localhost:5432
```
