---
sidebar_position: 2
title: Findings
---

# Findings API

## Findings auflisten

```http
GET /api/v1/findings
Authorization: Bearer <token>
```

**Query-Parameter:**

| Parameter | Typ | Beschreibung |
|---|---|---|
| `severity` | string | CRITICAL, HIGH, MEDIUM, LOW |
| `status` | string | open, acknowledged, resolved |
| `category` | string | CVE, MCP, Exposure, ... |
| `kev_only` | boolean | Nur CISA KEV-Findings |
| `tool` | string | nuclei, ramparts, subfinder, ... |
| `limit` | integer | Max. Ergebnisse (default: 50) |
| `offset` | integer | Pagination |
| `sort` | string | severity, cvss, epss, age |
| `order` | string | asc, desc |

**Response:**
```json
{
  "total": 35,
  "items": [
    {
      "id": "f1a2b3c4-...",
      "severity": "CRITICAL",
      "category": "CVE",
      "title": "CVE-2024-3400 — GlobalProtect RCE",
      "asset": "vpn.mueller-gmbh.de:443",
      "cve_id": "CVE-2024-3400",
      "cvss_score": 10.0,
      "epss_score": 0.974,
      "cisa_kev": true,
      "tool": "nuclei",
      "status": "open",
      "first_seen": "2026-05-05T08:03:00Z",
      "age_days": 1
    }
  ]
}
```

## Finding-Details

```http
GET /api/v1/findings/{id}
Authorization: Bearer <token>
```

```json
{
  "id": "f1a2b3c4-...",
  "severity": "CRITICAL",
  "category": "CVE",
  "title": "CVE-2024-3400 — GlobalProtect RCE",
  "asset": "vpn.mueller-gmbh.de:443",
  "cve_id": "CVE-2024-3400",
  "cvss_score": 10.0,
  "epss_score": 0.974,
  "cisa_kev": true,
  "tool": "nuclei",
  "description": "Unauthenticated command injection in PAN-OS...",
  "remediation": "Upgrade PAN-OS to >=11.1.2-h3...",
  "status": "open",
  "first_seen": "2026-05-05T08:03:00Z",
  "last_seen": "2026-05-05T08:03:00Z"
}
```

## Finding-Status ändern

```http
PATCH /api/v1/findings/{id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "status": "acknowledged",
  "comment": "Wird mit PAN-OS-Update behoben",
  "ticket_ref": "INC-2039"
}
```

## Findings exportieren

```http
GET /api/v1/findings/export?format=csv
GET /api/v1/findings/export?format=json
Authorization: Bearer <token>
```
