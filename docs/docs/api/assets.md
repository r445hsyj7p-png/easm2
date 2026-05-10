---
sidebar_position: 3
title: Assets
---

# Assets API

## Assets auflisten

```http
GET /api/v1/assets
Authorization: Bearer <token>
```

**Query-Parameter:** `fqdn`, `ip`, `org`, `risk`, `limit`, `offset`

**Response:**
```json
{
  "total": 26,
  "items": [
    {
      "id": "a1b2c3d4-...",
      "fqdn": "vpn.mueller-gmbh.de",
      "ip": "203.0.113.45",
      "org": "Hetzner Online GmbH",
      "asn": 24940,
      "ports": [443, 1194],
      "risk_level": "CRITICAL",
      "sources": ["subfinder", "cert"],
      "first_seen": "2026-05-05T08:03:00Z"
    }
  ]
}
```

## Asset-Details

```http
GET /api/v1/assets/{id}
Authorization: Bearer <token>
```

Gibt das Asset mit allen verknüpften Findings zurück.

## Hosting-Statistiken

```http
GET /api/v1/assets/stats/hosting
Authorization: Bearer <token>
```

```json
{
  "orgs": [
    { "name": "Hetzner Online GmbH", "asn": 24940, "count": 10, "pct": 38.5 },
    { "name": "Cloudflare, Inc.", "asn": 13335, "count": 4, "pct": 15.4 }
  ]
}
```

## Geo-Verteilung

```http
GET /api/v1/assets/stats/geo
Authorization: Bearer <token>
```
