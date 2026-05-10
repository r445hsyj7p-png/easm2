---
sidebar_position: 1
title: UI-Übersicht
---

# EASM FullHunt UI

Die Benutzeroberfläche ist inspiriert vom Design von FullHunt.io — tiefes Navy, Cyan-Akzente, monospace Datendarstellung und hohe Informationsdichte.

## Navigation

Die UI hat 7 Haupt-Tabs plus einen Settings-Bereich:

| Tab | Inhalt |
|---|---|
| **Overview** | Dashboard: KPIs, Threat-Level, Domain-Status, Scan-Phasen |
| **Findings** | Vollständige Befundliste mit Filter, Sort, Detail-Panel |
| **Assets** | Asset-Inventar mit 5 Sub-Tabs |
| **MCP Exposure** | Dediziertes Dashboard für MCP-Server-Exposition |
| **Intelligence** | Hosting, Geo, Asset-Graph, FQDN-Inventar, Threat Intel |
| **Scans** | Pipeline-Ausführung mit Live-Log, Scan-History |
| **Reports** | Score-Trend, Report-Generierung (PDF, CSV, JSON) |
| **Settings** ⚙ | Domains verwalten, Schedule, Notifications, RBAC |

## Farbcodierung

| Farbe | Bedeutung |
|---|---|
| 🔴 Rot `#f43f5e` | CRITICAL — sofortiger Handlungsbedarf |
| 🟠 Orange `#f97316` | HIGH — innerhalb 72h |
| 🟡 Gelb `#eab308` | MEDIUM — nächster Sprint |
| 🔵 Blau `#60a5fa` | LOW — planmässig |
| 🟢 Grün `#22c55e` | OK / Primäraktion |

## Design-Token-System

Alle Farben, Abstände und Typografie sind in einem zentralen `T`-Objekt definiert. Kein hardcodierter Hex-Wert ausserhalb davon. Änderungen am Design erfolgen ausschliesslich durch Anpassung der Token.
