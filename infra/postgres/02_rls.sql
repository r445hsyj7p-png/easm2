-- EASM Platform — Row-Level Security
-- Isoliert Mandanten-Daten auf DB-Ebene

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets   ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans    ENABLE ROW LEVEL SECURITY;
ALTER TABLE users    ENABLE ROW LEVEL SECURITY;

-- App-Rolle für API-Zugriff
DO $$ BEGIN
    CREATE ROLE easm_app;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO easm_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO easm_app;

-- RLS Policies: jeder Zugriff muss tenant_id matchen
CREATE POLICY tenant_isolation_findings ON findings
    USING (tenant_id::text = current_setting('app.tenant_id', true));

CREATE POLICY tenant_isolation_assets ON assets
    USING (tenant_id::text = current_setting('app.tenant_id', true));

CREATE POLICY tenant_isolation_scans ON scans
    USING (tenant_id::text = current_setting('app.tenant_id', true));

CREATE POLICY tenant_isolation_users ON users
    USING (tenant_id::text = current_setting('app.tenant_id', true));
