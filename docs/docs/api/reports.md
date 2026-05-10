---
sidebar_position: 5
title: Reports
---

# Reports API

## Report generieren

```http
POST /api/v1/reports
Authorization: Bearer <token>
Content-Type: application/json

{
  "type": "executive",
  "format": "pdf",
  "domain": "mueller-gmbh.de"
}
```

**Report-Typen:**

| `type` | Inhalt | Formate |
|---|---|---|
| `executive` | Management-Zusammenfassung, Score, Top-Findings | PDF |
| `technical` | Vollständige Findings-Liste mit CVSS/EPSS/KEV | PDF |
| `mcp` | MCP-Exposition, Attack-Chains, Remediation | PDF |
| `nis2` | NIS2-Artikel-Mapping, Gap-Analyse | PDF |
| `findings_export` | Alle Findings | CSV |
| `api_export` | Vollständige Pipeline-Daten | JSON |

**Response:**
```json
{
  "report_id": "r1a2b3c4-...",
  "status": "generating",
  "estimated_seconds": 15
}
```

## Report-Status

```http
GET /api/v1/reports/{report_id}
Authorization: Bearer <token>
```

```json
{
  "report_id": "r1a2b3c4-...",
  "status": "ready",
  "download_url": "/api/v1/reports/r1a2b3c4-.../download",
  "expires_at": "2026-05-12T08:00:00Z"
}
```

## Report herunterladen

```http
GET /api/v1/reports/{report_id}/download
Authorization: Bearer <token>
```

Liefert die Report-Datei als Binary-Stream mit korrektem `Content-Type`.
