"""
EASM MSSP Platform — FastAPI Backend (Production)
All endpoints backed by PostgreSQL. No demo data in request path.
"""
from fastapi import FastAPI, Depends, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime, timedelta, timezone
import uuid, hashlib, json, os, secrets as _secrets

import jwt as pyjwt
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import get_db
from db import repo

# ─── Config ──────────────────────────────────────────────────────────────────
SECRET_KEY       = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")
JWT_ALGORITHM    = "HS256"
JWT_EXPIRE_HOURS = 12
USERS_FILE       = os.environ.get("USERS_FILE", "/data/users.json")

# ─── JWT helpers ─────────────────────────────────────────────────────────────

def create_jwt(user_id: str, tenant_id: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
    return pyjwt.encode(
        {"sub": user_id, "tid": tenant_id, "role": role, "exp": exp},
        SECRET_KEY, algorithm=JWT_ALGORITHM,
    )

def decode_jwt(token: str) -> dict:
    return pyjwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])

# ─── Password hashing ─────────────────────────────────────────────────────────

def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ─── Auth context ─────────────────────────────────────────────────────────────

class AuthContext:
    def __init__(self, user_id: str, tenant_id: str, role: str):
        self.user_id   = user_id
        self.tenant_id = tenant_id
        self.role      = role

    def assert_own_tenant(self, tenant_id: str):
        if self.role in ("mssp_admin", "mssp_analyst"):
            return  # MSSP staff see all tenants
        if self.tenant_id != tenant_id:
            raise HTTPException(status_code=403, detail="Zugriff verweigert.")

bearer = HTTPBearer(auto_error=False)

async def get_auth(
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
) -> AuthContext:
    if not cred:
        raise HTTPException(status_code=401, detail="Authentifizierung erforderlich.")
    try:
        payload = decode_jwt(cred.credentials)
        return AuthContext(payload["sub"], payload.get("tid", ""), payload["role"])
    except Exception:
        raise HTTPException(status_code=401, detail="Ungültiger oder abgelaufener Token.")

# ─── Pydantic models ──────────────────────────────────────────────────────────

class SetupRequest(BaseModel):
    email: EmailStr
    password: str
    name: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int = JWT_EXPIRE_HOURS * 3600
    tenant_id:    str
    role:         str
    user_name:    str

class FindingUpdateRequest(BaseModel):
    status:     str
    ticket_ref: Optional[str] = None
    note:       Optional[str] = None

class ScanRequest(BaseModel):
    scan_type: str = "full"

# ─── App lifecycle ────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(
    title="EASM MSSP Platform API",
    version="1.0.0",
    description="External Attack Surface Management — Production API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Search router ────────────────────────────────────────────────────────────
try:
    from api.search import search_router
    app.include_router(search_router)
except ImportError:
    pass

# ═══════════════════════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/auth/status", tags=["Auth"])
async def auth_status(db: AsyncSession = Depends(get_db)):
    """Returns whether initial setup is required."""
    count = await repo.user_count(db)
    return {"setup_required": count == 0}


@app.post("/api/v1/auth/setup", response_model=LoginResponse, tags=["Auth"])
async def setup(req: SetupRequest, db: AsyncSession = Depends(get_db)):
    """Creates the first admin account. Only callable once."""
    count = await repo.user_count(db)
    if count > 0:
        raise HTTPException(status_code=403, detail="Einrichtung bereits abgeschlossen.")
    if len(req.password) < 8:
        raise HTTPException(status_code=422, detail="Passwort muss mindestens 8 Zeichen haben.")

    tenant_id = await repo.ensure_default_tenant(db)
    user_id   = await repo.create_user(
        db, req.email, hash_pw(req.password), req.name, "mssp_admin", tenant_id
    )
    token = create_jwt(user_id, tenant_id, "mssp_admin")
    return LoginResponse(
        access_token=token, tenant_id=tenant_id,
        role="mssp_admin", user_name=req.name,
    )


@app.post("/api/v1/auth/login", response_model=LoginResponse, tags=["Auth"])
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate and receive a JWT."""
    count = await repo.user_count(db)
    if count == 0:
        raise HTTPException(status_code=403,
            detail="Ersteinrichtung erforderlich — bitte Admin-Account anlegen.")

    user = await repo.get_user_by_email(db, req.email)
    if not user or user.get("pw_hash") != hash_pw(req.password):
        raise HTTPException(status_code=401, detail="E-Mail oder Passwort falsch.")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account deaktiviert.")

    token = create_jwt(user["id"], user["tenant_id"], user["role"])
    return LoginResponse(
        access_token=token,
        tenant_id=user["tenant_id"],
        role=user["role"],
        user_name=user.get("full_name", req.email),
    )

# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/health", tags=["System"])
async def health(db: AsyncSession = Depends(get_db)):
    try:
        from sqlalchemy import text
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    return {"status": "ok" if db_ok else "degraded", "db": db_ok, "version": "1.0.0"}

# ═══════════════════════════════════════════════════════════════════════════════
# TENANT
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/tenants/{tenant_id}", tags=["Tenants"])
async def get_tenant(
    tenant_id: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    tenant = await repo.get_tenant(db, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Mandant nicht gefunden.")
    return tenant

# ═══════════════════════════════════════════════════════════════════════════════
# FINDINGS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/tenants/{tenant_id}/findings", tags=["Findings"])
async def list_findings(
    tenant_id: str,
    severity:  Optional[str] = None,
    status:    Optional[str] = None,
    category:  Optional[str] = None,
    limit:     int = Query(200, ge=1, le=500),
    offset:    int = Query(0, ge=0),
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    return await repo.list_findings(db, tenant_id, severity, status, category, limit, offset)


@app.patch("/api/v1/tenants/{tenant_id}/findings/{finding_id}", tags=["Findings"])
async def update_finding(
    tenant_id:  str,
    finding_id: str,
    req: FindingUpdateRequest,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    ok = await repo.update_finding_status(db, tenant_id, finding_id, req.status, req.ticket_ref)
    if not ok:
        raise HTTPException(status_code=404, detail="Finding nicht gefunden.")
    # Recalculate score in background
    await repo.upsert_tenant_score(db, tenant_id)
    return {"ok": True}

# ═══════════════════════════════════════════════════════════════════════════════
# ASSETS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/tenants/{tenant_id}/assets", tags=["Assets"])
async def list_assets(
    tenant_id: str,
    limit:  int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    return await repo.list_assets(db, tenant_id, limit, offset)

# ═══════════════════════════════════════════════════════════════════════════════
# MCP
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/tenants/{tenant_id}/mcp", tags=["MCP"])
async def list_mcp_servers(
    tenant_id: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    return await repo.list_mcp_servers(db, tenant_id)

# ═══════════════════════════════════════════════════════════════════════════════
# INTEL
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/tenants/{tenant_id}/intel", tags=["Intelligence"])
async def get_intel(
    tenant_id: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    return await repo.get_intel(db, tenant_id)

# ═══════════════════════════════════════════════════════════════════════════════
# SCANS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/tenants/{tenant_id}/scans", tags=["Scans"])
async def list_scans(
    tenant_id: str,
    limit:  int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    return await repo.list_scans(db, tenant_id, limit, offset)


@app.post("/api/v1/tenants/{tenant_id}/scans", tags=["Scans"])
async def trigger_scan(
    tenant_id: str,
    req: ScanRequest,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    scan_id = await repo.create_scan_job(db, tenant_id, req.scan_type, "manual")
    # Dispatch to Celery
    try:
        from workers.scan_tasks import run_scan
        run_scan.apply_async(args=[scan_id, tenant_id], queue="scans")
    except Exception:
        pass  # Worker not available — job still created in DB
    return {"scan_id": scan_id, "status": "pending"}


@app.get("/api/v1/tenants/{tenant_id}/scans/{scan_id}", tags=["Scans"])
async def get_scan(
    tenant_id: str, scan_id: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    from sqlalchemy import text
    r = await db.execute(text("""
        SELECT id, scan_type, status, findings_count,
               risk_score_after AS risk_score,
               created_at AS started_at, completed_at AS finished_at,
               duration_seconds, error_message,
               COALESCE((raw_results->>'progress_pct')::int, 0) AS progress_pct
        FROM scan_jobs
        WHERE id = :sid AND tenant_id = :tid
    """), {"sid": scan_id, "tid": tenant_id})
    row = r.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden.")
    d = dict(row)
    for f in ("started_at", "finished_at"):
        if d.get(f):
            d[f] = d[f].isoformat()
    return d

# ═══════════════════════════════════════════════════════════════════════════════
# MSSP DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/mssp/dashboard", tags=["MSSP"])
async def mssp_dashboard(
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    """Overview of all tenants for MSSP admins."""
    if ctx.role not in ("mssp_admin", "mssp_analyst"):
        raise HTTPException(status_code=403, detail="Nur für MSSP-Mitarbeiter.")
    from sqlalchemy import text
    r = await db.execute(text("""
        SELECT t.id, t.name, t.slug,
               COALESCE(s.score, 0)  AS score,
               COALESCE(s.grade, '?') AS grade,
               COALESCE(s.findings_summary->>'CRITICAL', '0')::int AS critical_count,
               (SELECT MAX(created_at) FROM scan_jobs
                WHERE tenant_id = t.id AND status='completed') AS last_scan
        FROM tenants t
        LEFT JOIN LATERAL (
            SELECT score, grade, findings_summary
            FROM tenant_scores WHERE tenant_id = t.id
            ORDER BY recorded_at DESC LIMIT 1
        ) s ON TRUE
        ORDER BY score ASC
    """))
    tenants = []
    for row in r.mappings().all():
        d = dict(row)
        if d.get("last_scan"):
            d["last_scan"] = d["last_scan"].isoformat()
        tenants.append(d)
    return {"tenants": tenants, "total": len(tenants)}

# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
