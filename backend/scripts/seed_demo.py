"""
seed_demo.py — Seeds the database with demo data (Müller GmbH scenario).
Run: docker exec easm-api python scripts/seed_demo.py

This is the ONLY place demo data lives in production mode.
The API reads everything from the DB.
"""
import asyncio, sys, os
sys.path.insert(0, '/app')

from db.database import AsyncSessionLocal
from db import repo
from api.demo_data import (
    DEMO_FINDINGS, DEMO_ASSETS, DEMO_MCP_SERVERS, DEMO_INTEL, DEMO_TENANT
)


async def seed():
    async with AsyncSessionLocal() as db:
        # 1. Ensure tenant exists
        from sqlalchemy import text
        r = await db.execute(text("SELECT id FROM tenants WHERE slug = 'mueller-gmbh' LIMIT 1"))
        row = r.first()
        if row:
            tenant_id = str(row[0])
            print(f"Tenant exists: {tenant_id}")
        else:
            await db.execute(text("""
                INSERT INTO tenants (id, name, slug, status, created_at)
                VALUES ('t-mueller', 'Müller GmbH', 'mueller-gmbh', 'active', NOW())
                ON CONFLICT DO NOTHING
            """))
            await db.commit()
            tenant_id = 't-mueller'
            print(f"Tenant created: {tenant_id}")

        # 2. Seed findings
        print("Seeding findings...")
        for f in DEMO_FINDINGS:
            await repo.upsert_finding(db, tenant_id, f)
        print(f"  {len(DEMO_FINDINGS)} findings seeded ✓")

        # 3. Seed assets
        print("Seeding assets...")
        for a in DEMO_ASSETS:
            await repo.upsert_asset(db, tenant_id, a)
        print(f"  {len(DEMO_ASSETS)} assets seeded ✓")

        # 4. Seed MCP servers
        print("Seeding MCP servers...")
        for m in DEMO_MCP_SERVERS:
            await repo.upsert_mcp_server(db, tenant_id, m)
        print(f"  {len(DEMO_MCP_SERVERS)} MCP servers seeded ✓")

        # 5. Seed intel
        print("Seeding intel snapshot...")
        await repo.upsert_intel(db, tenant_id, DEMO_INTEL)
        print("  Intel snapshot seeded ✓")

        # 6. Recalculate score
        score = await repo.upsert_tenant_score(db, tenant_id)
        print(f"  Risk score calculated: {score} ✓")

        print("\nDemo data seeded successfully.")
        print(f"Tenant ID: {tenant_id}")
        print("Run 'make dev' and open http://localhost:3000")
        print("First login will prompt for admin account creation.")

asyncio.run(seed())
