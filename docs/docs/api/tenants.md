---
sidebar_position: 6
title: Tenants & Domains
---

# Tenants & Domains API

## Aktuellen Tenant abrufen

```http
GET /api/v1/tenants/me
Authorization: Bearer <token>
```

```json
{
  "id": "t1a2b3c4-...",
  "name": "Müller GmbH",
  "slug": "mueller-gmbh",
  "active": true,
  "domains": [
    {
      "id": "d1a2b3c4-...",
      "domain": "mueller-gmbh.de",
      "status": "active",
      "ip_ranges": ["203.0.113.0/24"],
      "last_scan": "2026-05-05T08:03:00Z",
      "findings_count": 35,
      "risk_score": 48
    }
  ]
}
```

## Domain hinzufügen

```http
POST /api/v1/tenants/me/domains
Authorization: Bearer <token>
Content-Type: application/json

{
  "domain": "mueller-logistics.de",
  "ip_ranges": ["198.51.100.0/24"],
  "panos_version": "11.1.3"
}
```

## Domain aktualisieren

```http
PATCH /api/v1/tenants/me/domains/{domain_id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "status": "paused",
  "ip_ranges": ["198.51.100.0/24", "198.51.101.0/24"]
}
```

## Domain entfernen

```http
DELETE /api/v1/tenants/me/domains/{domain_id}
Authorization: Bearer <token>
```

Entfernt Domain, alle zugehörigen Assets und Findings (soft-delete, 30 Tage Retention).

## Scan-Schedule konfigurieren

```http
PUT /api/v1/tenants/me/schedule
Authorization: Bearer <token>
Content-Type: application/json

{
  "full_scan":     { "enabled": true, "interval": "daily",  "time": "08:00" },
  "mcp_scan":      { "enabled": true, "interval": "daily",  "time": "04:00" },
  "hibp_check":    { "enabled": true, "interval": "daily",  "time": "06:00" },
  "nuclei_update": { "enabled": true, "interval": "daily",  "time": "01:00" },
  "deep_scan":     { "enabled": false,"interval": "weekly", "time": "02:00" }
}
```
