---
sidebar_position: 3
title: Assets
---

# Assets-Tab

Der Assets-Tab hat 5 Sub-Tabs für verschiedene Sichtweisen auf das Asset-Inventar.

## Sub-Tabs

### Asset List
Vollständige Tabelle aller entdeckten FQDNs und IPs mit Risk-Level, IP-Adresse, Organisation, ASN, offenen Ports und Discovery-Quelle.

Kritische Ports werden rot hervorgehoben: `3389` (RDP), `6274/6277` (MCP Inspector).

Subdomains mit Takeover-Risiko tragen den roten `TAKEOVER`-Badge.

### Hosting Analysis
Donut-Chart der Hosting-Organisationen + ASN-Mapping-Tabelle mit Prozentverteilung. Zeigt auf einen Blick, wie die Angriffsfläche auf Cloud-Provider und Rechenzentren verteilt ist.

### Geo Distribution
Inline SVG-Weltkarte (Mercator-Projektion) mit animierten Pulse-Ringen für CRITICAL/HIGH-Standorte. Darunter eine Tabelle mit Standort, Land, IP-Anzahl und Risiko.

### Asset Graph
Interaktiver Netzwerk-Graph: Domain → DNS → IP → Netblock → ASN → Organisation. Klick auf einen Node hebt alle verbundenen Kanten hervor. Ermöglicht das schnelle Verstehen der Infrastrukturstruktur.

### FQDN Inventory
Vollständige Tabelle aller FQDNs mit IP, Netblock, ASN (klickbar als Org-Filter) und Organisation. Sortierbar nach Risk, FQDN, ASN, Org. Mit Freitext-Suche und Severity-Filter.
