---
sidebar_position: 3
title: Datenbank
---

# Datenbank-Architektur

## PostgreSQL 16 mit Row-Level Security

Die Plattform nutzt PostgreSQL 16 mit aktivierter Row-Level Security (RLS) für Multi-Tenant-Datenisolation. Jede Tabelle hat eine RLS-Policy, die sicherstellt, dass Queries nur Daten des aktuellen Mandanten zurückgeben.

## Schema-Übersicht

```sql
tenants          -- Mandanten (Organisationen)
├── users        -- Benutzer je Mandant (RBAC: admin/analyst/readonly)
├── domains      -- Überwachte Domains und IP-Ranges
├── scan_jobs    -- Scan-Ausführungen mit Status und Ergebnissen
├── findings     -- Sicherheitsbefunde (CVSS, EPSS, KEV)
├── assets       -- Entdeckte Assets (FQDNs, IPs, Ports, Services)
├── api_keys     -- API-Tokens für programmatischen Zugriff
└── reports      -- Generierte Reports (PDF, CSV, JSON)
```

## Wichtige Tabellen

### `tenants`
```sql
CREATE TABLE tenants (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL,
    slug        TEXT UNIQUE NOT NULL,
    active      BOOLEAN DEFAULT true,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);
```

### `findings`
```sql
CREATE TABLE findings (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    scan_job_id UUID REFERENCES scan_jobs(id),
    severity    TEXT CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    category    TEXT,       -- CVE, MCP, Exposure, Credential, ...
    title       TEXT NOT NULL,
    asset       TEXT,       -- FQDN:Port oder IP
    cve_id      TEXT,
    cvss_score  NUMERIC(3,1),
    epss_score  NUMERIC(5,4),
    cisa_kev    BOOLEAN DEFAULT false,
    tool        TEXT,       -- nuclei, ramparts, subfinder, ...
    description TEXT,
    remediation TEXT,
    status      TEXT DEFAULT 'open',
    first_seen  TIMESTAMPTZ DEFAULT NOW(),
    last_seen   TIMESTAMPTZ DEFAULT NOW()
);
```

### `assets`
```sql
CREATE TABLE assets (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    fqdn        TEXT,
    ip          INET,
    asn         INTEGER,
    org         TEXT,
    ports       INTEGER[],
    risk_level  TEXT,
    sources     TEXT[],     -- subfinder, dns, cert, mx, ...
    first_seen  TIMESTAMPTZ DEFAULT NOW(),
    last_seen   TIMESTAMPTZ DEFAULT NOW()
);
```

## Row-Level Security

```sql
-- RLS aktivieren
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;

-- Policy: Jeder sieht nur seine eigenen Daten
CREATE POLICY tenant_isolation ON findings
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- App setzt den Kontext pro Request
SET app.tenant_id = '123e4567-e89b-12d3-a456-426614174000';
```

Die API setzt `app.tenant_id` aus dem JWT-Token bei jeder Datenbankverbindung. Selbst bei einem SQL-Injection-Angriff kann ein Mandant keine Daten eines anderen lesen.

## Initialisierung

PostgreSQL führt beim ersten Container-Start automatisch alle `.sql`-Dateien aus `infra/postgres/` aus:

1. `01_init.sql` — Extensions (`uuid-ossp`, `pg_trgm`, `btree_gin`), Rollen, Basis-Konfiguration
2. `02_rls.sql` — Row-Level Security Policies für alle Tabellen

Anschliessend führt der API-Container `alembic upgrade head` aus, das Schema-Migrationen verwaltet.

## Backups

```bash
# Manuelles Backup
make backup-db

# Automatisch via pg_dump im Backup-Container (täglich 03:00 UTC)
# Retention: 30 Tage lokal, optional S3-Upload
```
