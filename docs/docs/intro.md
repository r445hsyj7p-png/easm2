---
slug: /
sidebar_position: 1
---

# EASM MSSP Platform

**External Attack Surface Management** für Managed Security Service Provider.

Die Plattform scannt kontinuierlich alle exponierten Systeme eurer Mandanten — Subdomains, offene Ports, CVEs, MCP-Server-Exposition, Credential-Leaks — und priorisiert Findings nach CVSS, EPSS und CISA KEV.

## Was die Platform leistet

- **Automatische Angriffsflächen-Erfassung** via Subfinder, Naabu, theHarvester, HTTPX
- **Vulnerability-Scanning** via Nuclei (7.000+ Templates, täglich aktualisiert)
- **MCP-Server-Erkennung** — exponierte KI-Agenten-Infrastruktur (CVE-2025-49596)
- **Credential Intelligence** via HIBP + Stealer-Log-Integration
- **Multi-Tenant-fähig** — Row-Level Security in PostgreSQL
- **Vollständig Docker-basiert** — ein Befehl, keine manuelle Installation

## Quick Start

```bash
git clone https://github.com/your-org/easm-platform.git
cd easm-platform
cp .env.example .env   # Passwörter setzen
make build && make up
make migrate
```

→ [Ausführliche Installationsanleitung](/getting-started/installation)
