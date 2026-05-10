---
sidebar_position: 5
title: Settings
---

# Settings

Der Settings-Bereich ist über das ⚙-Icon rechts in der Navigationsleiste erreichbar.

## Domains & Targets

Verwalte alle überwachten Domains. Für jede Domain:

- **Status:** active / paused / pending
- **IP-Ranges:** optionale CIDR-Notation für direktes IP-Scanning
- **PAN-OS Version:** für Palo Alto spezifische Checks

### Domain hinzufügen

Klicke "+ ADD DOMAIN", fülle das Formular aus und bestätige mit "ADD DOMAIN". Die Domain wird beim nächsten Scan-Zyklus automatisch erfasst.

```
Domain:    example.de
IP-Ranges: 203.0.113.0/24, 198.51.100.0/24  (optional)
PAN-OS:    11.1.3  (optional)
```

Validierung: Format-Check, Duplikat-Prüfung. Nach dem Hinzufügen erscheint die Domain mit Status "pending" in der Liste.

### Aktionen pro Domain

| Aktion | Effekt |
|---|---|
| Edit | Formular zum Bearbeiten von IP-Ranges und PAN-OS-Version |
| Pause | Scan-Jobs werden übersprungen, Domain bleibt im Inventar |
| Resume | Scans werden wieder ausgeführt |
| Remove | Domain und alle zugehörigen Assets/Findings werden entfernt |

## Scan Schedule

Konfiguriere wann welche Scan-Phasen ausgeführt werden. Jeder Task-Typ hat einen eigenen Toggle (aktivieren/deaktivieren), ein Intervall-Dropdown (hourly/daily/weekly/monthly) und eine Uhrzeit-Auswahl.

## Notifications

- **E-Mail Alerts:** Adresse für Sofort-Alerts bei neuen CRITICAL-Findings
- **Slack Webhook:** Optional für Team-Notifications
- **Alert Rules:** "Critical & KEV only" oder "Weekly Summary Report"

## Access & RBAC

Benutzerverwaltung mit drei Rollen:

| Rolle | Rechte |
|---|---|
| Admin | Vollzugriff, User-Management, Domain-Verwaltung |
| Analyst | Findings einsehen, kommentieren, Tickets erstellen |
| Read-Only | Nur Lesen, keine Aktionen |
