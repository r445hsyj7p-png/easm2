---
sidebar_position: 4
title: Scans
---

# Scans-Tab

## Pipeline starten

Der "Start Scan"-Button startet einen vollständigen 5-Phasen-Scan für die aktuell ausgewählte Domain. Der Fortschrittsbalken und das Live-Log-Terminal zeigen den Scan-Verlauf in Echtzeit.

## Live-Log

Das Terminal zeigt die Rohausgabe aller Tools farbcodiert:
- **Cyan** — Subfinder-Ausgabe
- **Grün** — theHarvester-Ausgabe  
- **Gelb** — Naabu-Ausgabe
- **Rot** — Nuclei/Ramparts-Findings (kritische Erkennungen)
- **Violett** — HTTPX-Ausgabe

## Scan-History

Die rechte Spalte zeigt alle vergangenen Scans als Timeline mit Dauer, Findings-Anzahl und Score-Änderung.

## Tool-Breakdown

Statistiken des letzten Scans nach Tool aufgeteilt: Anzahl Findings, Laufzeit in Sekunden, Fortschrittsbalken.
