---
sidebar_position: 2
title: Findings
---

# Findings-Tab

## Tabellenspalten

| Spalte | Beschreibung | Sortierbar |
|---|---|---|
| Severity | CRITICAL / HIGH / MEDIUM / LOW | ✓ |
| Category | CVE, MCP, Exposure, Credential, Port, ... | — |
| Finding | Titel + CVE-ID falls vorhanden | ✓ |
| Asset | FQDN:Port oder IP | — |
| CVSS | Common Vulnerability Scoring (0-10) | ✓ |
| EPSS | Exploit Prediction Score (0-1) | ✓ |
| KEV | CISA Known Exploited Vulnerabilities | ✓ |
| Tool | Welches Tool das Finding entdeckt hat | — |
| Age | Tage seit Erstentdeckung | ✓ |

## Filter

- **Severity-Filter:** ALL / CRITICAL / HIGH / MEDIUM / LOW
- **Kategorie-Filter:** CVE / MCP / Exposure / Credential (schnelle Toggle-Buttons)
- **KEV-Only:** Checkbox für nur CISA KEV-gelistete Findings
- **Freitext:** Suche in Titel und Asset-Feld

## Detail-Panel

Klick auf eine Zeile öffnet das Detail-Panel rechts:
- CVSS / EPSS / Age als Kacheln
- Vollständige Beschreibung
- Remediation-Box (grün hinterlegt)
- "Ticket erstellen" und "Accept Risk" Buttons

## Findings-Workflow

```
open → acknowledged → in_progress → resolved
         ↓
      accepted_risk (dauerhaft dokumentiert)
```
