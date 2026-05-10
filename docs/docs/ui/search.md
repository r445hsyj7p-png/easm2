---
sidebar_position: 1
title: Suche & Query-Syntax
---

# Globale Suche

Das Suchfeld oben in der Navigation durchsucht **alle Findings und Assets** gleichzeitig. Drücke `Enter` oder klicke `SEARCH` um zu suchen, `Esc` zum Zurücksetzen.

## Erkannte Tokens

Während der Eingabe werden erkannte Filter-Tokens **farbig hervorgehoben**:
- 🔴 Rote Tokens = Severity/CVE-bezogen
- 🟢 Grüne Tokens = Tool/Org-bezogen
- 🟡 Gelbe Tokens = Score-Filter
- 🔵 Blaue Tokens = Asset/IP-bezogen

## Query-Syntax Referenz

### Severity & Status

```
severity:critical
severity:critical,high          # mehrere Werte (OR)
-severity:low                   # Negation
status:open
status:acknowledged
```

### Kategorie & Tool

```
cat:mcp                         # oder: tag:mcp-exposure
cat:cve
cat:credential
tool:nuclei
tool:ramparts
```

### Flags

```
has:cve                         # hat CVE-ID
has:kev                         # CISA Known Exploited
has:ticket                      # Ticket vergeben
has:no-ticket                   # kein Ticket vergeben
has:epss                        # hat EPSS-Score
```

### Score-Filter

```
cvss:>=9                        # CVSS 9.0 und höher
cvss:7..10                      # CVSS zwischen 7 und 10
epss:>=0.9                      # EPSS ≥ 90%
epss:>=0.5                      # EPSS ≥ 50%
```

### Alter

```
age:<7                          # jünger als 7 Tage
age:>30                         # älter als 30 Tage
age:<1                          # heute entdeckt
```

### Assets

```
port:6274                       # Port offen
port:6274 OR port:6277          # Mehrere Ports (ODER)
subdomain:*.mueller-gmbh.de     # FQDN-Wildcard
ip:203.0.113.0/24               # IP-Range (CIDR)
org:hetzner                     # Hosting-Organisation
```

### Spezifische Felder

```
cve:CVE-2024-3400               # Spezifische CVE
asset:vpn.example.de            # Asset-String
title:globalprotect             # Im Titel suchen
"offener rdp port"              # Freitext (Anführungszeichen)
```

### Logische Operatoren

```
severity:critical has:kev                    # AND (Standard)
port:6274 OR port:6277                       # OR
severity:critical -status:acknowledged       # NOT mit -
```

## Praktische Beispiele

| Ziel | Query |
|---|---|
| Alle KEV-Findings sofort | `has:kev severity:critical` |
| MCP-Server ohne Ticket | `cat:mcp has:no-ticket` |
| Neue Findings heute | `age:<1 status:open` |
| Kritische Nuclei-Findings | `tool:nuclei severity:critical` |
| Hetzner Assets mit Port 3389 | `org:hetzner port:3389` |
| Hochwahrscheinliche Exploits | `epss:>=0.9 status:open` |
| Bestimmte CVE | `cve:CVE-2024-3400` |
| MCP-Ports gescannt | `port:6274 OR port:6277` |

## Scope-Erkennung

Die Suche erkennt automatisch welche Datenquellen relevant sind:

- Queries mit `port:`, `subdomain:`, `ip:`, `org:` → durchsucht **Assets**
- Queries mit `severity:`, `cvss:`, `has:cve`, `tool:` → durchsucht **Findings**
- Freitext und gemischte Queries → durchsucht **beides**

## API-Endpunkt

```http
GET /api/v1/search?q=severity:critical has:kev&scope=findings&limit=50
Authorization: Bearer <token>
```

Vollständige API-Dokumentation: [API → Findings](/docs/api/findings)
