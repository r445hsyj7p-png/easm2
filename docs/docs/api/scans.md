---
sidebar_position: 4
title: Scans
---

# Scans API

## Scan starten

```http
POST /api/v1/scans
Authorization: Bearer <token>
Content-Type: application/json

{
  "domain": "mueller-gmbh.de",
  "scan_type": "full",
  "phases": ["discovery", "port_scan", "http_probe", "vuln_scan", "mcp_scan"]
}
```

`scan_type`: `full` | `mcp_only` | `discovery_only` | `vuln_only`

**Response:**
```json
{
  "scan_id": "s1a2b3c4-...",
  "status": "queued",
  "domain": "mueller-gmbh.de",
  "started_at": "2026-05-05T08:03:00Z",
  "estimated_duration_seconds": 202
}
```

## Scan-Status abrufen

```http
GET /api/v1/scans/{scan_id}
Authorization: Bearer <token>
```

```json
{
  "scan_id": "s1a2b3c4-...",
  "status": "running",
  "progress_pct": 42,
  "current_phase": "port_scan",
  "phases_completed": ["discovery"],
  "findings_so_far": 6,
  "started_at": "2026-05-05T08:03:00Z"
}
```

## Scan-Log (Server-Sent Events)

```http
GET /api/v1/scans/{scan_id}/log
Authorization: Bearer <token>
Accept: text/event-stream
```

Liefert den Live-Log als SSE-Stream. Das Frontend nutzt diesen Endpoint für das Terminal im Scans-Tab.

```
data: {"tool": "subfinder", "msg": "found 23 subdomains", "level": "info"}
data: {"tool": "naabu", "msg": "203.0.113.55 → 8080 open (MCP port!)", "level": "warn"}
data: {"tool": "nuclei", "msg": "CVE-2024-3400 MATCH on vpn:443", "level": "critical"}
```

## Scan-History

```http
GET /api/v1/scans?domain=mueller-gmbh.de&limit=10
Authorization: Bearer <token>
```

## Scan abbrechen

```http
DELETE /api/v1/scans/{scan_id}
Authorization: Bearer <token>
```
