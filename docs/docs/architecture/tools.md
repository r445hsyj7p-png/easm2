---
sidebar_position: 4
title: Security Tools
---

# Security-Tool-Integration

## Übersicht

| Tool | Typ | Container | Zweck |
|---|---|---|---|
| Subfinder | Go-Binary | worker-scan | Subdomain Discovery |
| Naabu | Go-Binary | worker-scan | Port-Scanner |
| HTTPX | Go-Binary | worker-scan | HTTP-Probing |
| Nuclei | Go-Binary | worker-scan | Vulnerability-Scanning |
| theHarvester | Python | easm-theharvester | OSINT (E-Mails, VHosts) |
| Ramparts | Python | easm-ramparts | MCP-Security-Scanner |

## Subfinder — Subdomain Discovery

Erkennt Subdomains aus 50+ passiven Quellen ohne aktive Netzwerkanfragen an das Ziel.

**Quellen (Auszug):** VirusTotal, Shodan, Censys, SecurityTrails, DNSdumpster, crt.sh, HackerTarget, Wayback Machine

**Konfiguration mit API-Keys:**
```bash
# .env
VIRUSTOTAL_API_KEY=...   # Erweitert Coverage erheblich
SHODAN_API_KEY=...
SECURITYTRAILS_API_KEY=...
```

**Ohne API-Keys:** ~15 Quellen aktiv. **Mit API-Keys:** 50+ Quellen, deutlich höhere Erkennungsrate.

## Naabu — Port-Scanner

SYN-Scan (NET_RAW capability erforderlich) mit konfigurierbarer Rate.

```
Default: top-1000 Ports, 2000 packets/sec, SYN-Mode
MCP-Ports explizit: 6274, 6277, 3000, 8080, 8000
UDP-Scan: optional für DNS (53), SNMP (161)
```

**Besonderheit:** Naabu scannt explizit nach bekannten MCP-Server-Ports und gibt diese als hochprioritäre Findings weiter.

## HTTPX — HTTP-Probing

Probt alle entdeckten Services auf HTTP/HTTPS-Verfügbarkeit und erkennt:

- Tech-Stack (Wappalyzer-basiert): Framework, CMS, Server, Sprache
- Security-Header: HSTS, CSP, X-Frame-Options, CORS
- Favicon-Hash (für Service-Fingerprinting)
- Screenshots (headless Chromium, wenn aktiviert)
- Spezielle Pfade: `/.env`, `/actuator`, `/graphql`, `/.git`

## Nuclei — Vulnerability-Scanning

7.000+ Community-Templates, täglich automatisch aktualisiert.

**Genutzte Template-Kategorien:**
```
cve          — CVE-Datenbank (CVSS, KEV-Kennzeichnung)
misconfig    — Fehlkonfigurationen (CORS, CSRF, Headers)
exposure     — Datei-Exposition (.env, .git, Backup-Dateien)
default-login — Standard-Credentials auf Management-Interfaces
api          — API-Exposition (Swagger, GraphQL Introspection)
mcp          — MCP-Server-Erkennung und -Analyse
```

**Template-Update:**
```bash
# Automatisch täglich 01:00 UTC via scheduler
# Manuell:
make update-nuclei
```

## theHarvester — OSINT

Erkennt E-Mail-Adressen, Mitarbeiternamen, VHosts und weitere OSINT-Daten.

**Quellen:** Google, Bing, LinkedIn, Hunter.io, Shodan, CertSpotter

Läuft als **separater Docker-Container** (`easm-theharvester`), der vom `worker-scan` via Docker Socket aufgerufen wird. Ermöglicht Updates des Tools ohne Worker-Rebuild.

## Ramparts — MCP-Security-Scanner

Spezialisierter Scanner für Model Context Protocol Exposition.

**Ablauf:**
1. Verbindungsaufbau zum MCP-Endpunkt
2. `initialize`-Request ohne Auth-Token → prüft ob Antwort kommt
3. `tools/list` → inventarisiert alle exponierten Tools
4. Klassifiziert gefährliche Tools: `execute_command`, `shell`, `write_file`
5. Prompt-Injection-Detection in Tool-Beschreibungen

**Erkannte CVEs:** CVE-2025-49596 (MCP Inspector, CVSS 9.4)

Läuft ebenfalls als separater Container, aufrufbar via Docker Socket.
