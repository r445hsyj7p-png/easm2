---
sidebar_position: 5
---

# MCP-Erkennungs-Logik

## Was ist MCP?

Model Context Protocol (Anthropic, 2024) verbindet KI-Agenten mit externen Tools. Exponierte MCP-Server ohne Authentifizierung erlauben vollständige Remote Code Execution.

## Angriffskette

```
POST /mcp → initialize (kein Token nötig)
          → tools/list (Tool-Inventar lesen)
          → tools/call → execute_command → RCE
```

## Erkannte Ports

| Port | Dienst | Risiko |
|---|---|---|
| 6274 | MCP Inspector (Proxy) | CRITICAL — CVE-2025-49596 |
| 6277 | MCP Inspector (SSE) | CRITICAL — CVE-2025-49596 |
| 8080 | FastMCP / Custom | CRITICAL |
| 3000 | MCP Dev-Server | HIGH |

## CVE-2025-49596

CVSS 9.4 — DNS-Rebinding-Angriff auf MCP Inspector. Jede beliebige Website kann Tool-Calls in den lokal laufenden MCP Inspector injizieren.

**Remediation:**
- MCP Inspector nie in Produktion betreiben
- Ports 6274/6277 per Firewall blockieren
- Bearer-Token-Authentifizierung aktivieren
- `DANGEROUSLY_OMIT_AUTH=true` aus Umgebungsvariablen entfernen
