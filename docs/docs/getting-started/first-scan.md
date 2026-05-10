---
sidebar_position: 3
---

# Erster Scan

## Domain hinzufügen

1. Platform unter `https://<APP_DOMAIN>` öffnen
2. Rechts oben **Settings** (Zahnrad-Icon) klicken
3. **Domains & Targets** → **+ ADD DOMAIN**
4. Domain eingeben: `example.de`
5. Optional: IP-Ranges und PAN-OS-Version eintragen
6. **ADD DOMAIN** klicken

Die Domain erscheint mit Status **pending** in der Liste.

## Scan starten

### Via UI

Im Tab **Scans** → **▶ START SCAN** klicken.

Das Live-Log zeigt den Fortschritt in Echtzeit:

```
[subfinder]   loading passive sources: VirusTotal, Shodan, Censys...
[subfinder]   found 23 subdomains for example.de
[naabu]       scanning 18 IPs | top-1000 ports | SYN mode
[httpx]       probing 31 services | tech-detect | screenshots
[nuclei]      loading 7,234 templates...
[ramparts]    connecting to http://....:8080/mcp
[pipeline]    scan complete | score: 67/100 | 12 findings
```

### Via CLI

```bash
make scan DOMAIN=example.de
```

## Ergebnisse

Nach dem Scan (ca. 3-5 Minuten) sind Ergebnisse in allen Tabs sichtbar:

- **Findings** — priorisierte Schwachstellen nach CVSS/EPSS/KEV
- **Assets** — alle entdeckten Subdomains, IPs, Ports
- **Intelligence** — OSINT, Credentials, Dark-Web-Monitoring
- **MCP Exposure** — exponierte KI-Infrastruktur (falls gefunden)
