---
sidebar_position: 5
title: Intelligence
---

# Intelligence-Tab

Der Intelligence-Tab ist ein Hybrid aus dem Assets-Tab (Infrastruktur-Sicht) und Threat-Intelligence (externe Daten).

## Sub-Tabs

### Hosting Analysis
Identische Ansicht wie im Assets-Tab — Donut-Chart und ASN-Tabelle. Optimiert für die Analyse der Infrastruktur-Verteilung aus Intelligence-Perspektive.

### Geo Distribution
Weltkarte mit Asset-Standorten, erweiterbar mit Threat-Intelligence-Daten (bekannte bösartige IPs, Botnet-C2-Infrastruktur in denselben Netzen).

### Asset Graph
Vollständiger interaktiver Graph mit allen 6 Ebenen: Domain → DNS → IP → Netblock → ASN → Organisation. Drag-and-Drop, Pan, Zoom.

### FQDN Inventory
Vollständige FQDN-Tabelle mit Sortierung, Filter und Suche.

### Threat Intelligence

Kombiniert mehrere externe Quellen:

**Credential Intelligence:**
- Anzahl geernteter E-Mails (theHarvester)
- HIBP-Breach-Datenbank-Treffer
- Stealer-Log-Exposition
- LinkedIn-exponierte Mitarbeiter

**Exploit Intelligence:**
- Alle CVEs aus Findings mit CVSS, EPSS und KEV-Status
- Sortiert nach Exploit-Wahrscheinlichkeit (EPSS)

**Dark Web & Typosquatting:**
- Erkannte Lookalike-Domains (Phishing-Risiko)
- Phishing-Kit-Erkennungen
- Brand-Mentions auf bekannten Threat-Plattformen
