---
sidebar_position: 2
---

# Konfiguration

Alle Einstellungen werden in der `.env`-Datei gesetzt. Kein manuelles Editieren von Konfigurationsdateien nötig.

## Pflichtfelder

| Variable | Beschreibung |
|---|---|
| `POSTGRES_PASSWORD` | Datenbankpasswort (min. 32 Zeichen) |
| `SECRET_KEY` | JWT-Signing-Key (min. 64 Zeichen) |
| `REDIS_PASSWORD` | Redis-Passwort |
| `APP_DOMAIN` | Hauptdomain der Plattform |
| `LETSENCRYPT_EMAIL` | E-Mail für Let's Encrypt |

## API-Keys (optional)

API-Keys erweitern die Scan-Abdeckung erheblich, sind aber nicht für den Betrieb erforderlich.

| Variable | Tool | Effekt |
|---|---|---|
| `HIBP_API_KEY` | HIBP Pro | Stealer-Log-Daten, exakte Breach-Details |
| `VIRUSTOTAL_API_KEY` | Subfinder | VirusTotal-Subdomain-Quellen |
| `SHODAN_API_KEY` | Subfinder + Naabu | Shodan-Daten als passive Quelle |
| `SECURITYTRAILS_API_KEY` | Subfinder | SecurityTrails DNS-Daten |
| `GITHUB_TOKEN` | theHarvester + Nuclei | GitHub-OSINT + Template-Updates |
| `ANTHROPIC_API_KEY` | Ramparts | LLM-gestützte MCP-Tool-Analyse |

## Scan-Konfiguration

```env
SCAN_CONCURRENCY=4      # Parallele Scans pro Worker
NAABU_RATE=1000         # Pakete/Sek (Cloud-Hoster: ggf. 500)
HTTPX_SCREENSHOTS=true  # Screenshots (erhöht Speicherbedarf)
```

## Notifications

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=alerts@ihredomain.de
SMTP_PASSWORD=...
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```
