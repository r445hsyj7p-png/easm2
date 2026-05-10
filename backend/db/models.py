"""
EASM as a Service — Datenbankmodelle
Multi-Tenant mit Row-Level Security (tenant_id auf jeder Tabelle)

Schema-Strategie: Shared Database, Shared Schema + RLS
- Einfachste Option für < 500 Mandanten
- Jede Tabelle hat tenant_id als Pflichtfeld
- SQLAlchemy Middleware setzt automatisch WHERE tenant_id = ?
- PostgreSQL Row-Level Security als zweite Sicherheitsschicht
"""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime,
    ForeignKey, Text, JSON, Enum, UniqueConstraint, Index
)
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
import enum


def utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ─── Tenant (Mandant / Kunde) ────────────────────────────────────────

class TenantStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TRIAL = "trial"

# Kein Plan-System — alle Funktionen für alle Mandanten verfügbar

class Tenant(Base):
    """MSSP-Kunde / Mandant"""
    __tablename__ = "tenants"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(200), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)  # URL-safe name
    # plan-Feld entfernt — kein Tier-Modell
    status = Column(Enum(TenantStatus), default=TenantStatus.TRIAL)

    # Kontakt
    primary_email = Column(String(200))
    company_name = Column(String(200))
    industry = Column(String(100))  # z.B. "healthcare", "financial", "kritis"

    # MSSP-interne Felder
    account_manager = Column(String(100))
    sla_level = Column(String(20), default="silver")  # gold/silver/bronze
    notes = Column(Text)

    # API-Zugang für Kunden-Self-Service
    api_key_hash = Column(String(255))
    webhook_url = Column(String(500))  # Alert-Benachrichtigungen

    # Timestamps
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    trial_expires_at = Column(DateTime)

    # Relationships
    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    domains = relationship("Domain", back_populates="tenant", cascade="all, delete-orphan")
    ip_ranges = relationship("IPRange", back_populates="tenant", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="tenant", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="tenant", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="tenant", cascade="all, delete-orphan")

    # Konfiguration
    scan_config = Column(JSON, default=dict)  # kundenspezifische Scan-Settings
    notification_config = Column(JSON, default=dict)  # Alert-Präferenzen

    # Risk-Acceptance: ausgenommene Findings
    accepted_risks = Column(JSON, default=list)


# ─── Users ───────────────────────────────────────────────────────────

class UserRole(str, enum.Enum):
    MSSP_ADMIN = "mssp_admin"        # MSSP-interner Admin: alles
    MSSP_ANALYST = "mssp_analyst"    # MSSP-Analyst: lesen + Scans starten
    CUSTOMER_ADMIN = "customer_admin" # Kunden-Admin: eigener Tenant, read-only
    CUSTOMER_VIEWER = "customer_viewer" # Kunden-Viewer: nur Reports

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=True)  # NULL = MSSP-Admin
    email = Column(String(200), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(200))
    role = Column(Enum(UserRole), nullable=False)
    is_active = Column(Boolean, default=True)
    mfa_secret = Column(String(100))  # TOTP Secret
    mfa_enabled = Column(Boolean, default=False)

    created_at = Column(DateTime, default=utcnow)
    last_login = Column(DateTime)

    # Relationships
    tenant = relationship("Tenant", back_populates="users")


# ─── Assets (Domains + IP-Ranges) ────────────────────────────────────

class DomainStatus(str, enum.Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    VERIFIED = "verified"

class Domain(Base):
    """Zu überwachende Domain eines Mandanten"""
    __tablename__ = "domains"
    __table_args__ = (
        UniqueConstraint("tenant_id", "fqdn", name="uq_tenant_domain"),
        Index("ix_domains_tenant", "tenant_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    fqdn = Column(String(500), nullable=False)  # Fully Qualified Domain Name
    status = Column(Enum(DomainStatus), default=DomainStatus.ACTIVE)

    # DNS-Verifikation (wie HIBP)
    verification_token = Column(String(100))
    verified_at = Column(DateTime)

    # Letzte Scan-Ergebnisse (Cache)
    last_scan_at = Column(DateTime)
    subdomain_count = Column(Integer, default=0)
    risk_score = Column(Integer, default=100)

    created_at = Column(DateTime, default=utcnow)

    # Relationships
    tenant = relationship("Tenant", back_populates="domains")

class IPRange(Base):
    """IP-Range für Port-Scanning"""
    __tablename__ = "ip_ranges"
    __table_args__ = (
        Index("ix_ipranges_tenant", "tenant_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    cidr = Column(String(50), nullable=False)  # z.B. "203.0.113.0/24"
    label = Column(String(200))  # z.B. "Rechenzentrum Frankfurt"
    is_active = Column(Boolean, default=True)
    last_scan_at = Column(DateTime)

    created_at = Column(DateTime, default=utcnow)
    tenant = relationship("Tenant", back_populates="ip_ranges")


# ─── Scan Jobs ────────────────────────────────────────────────────────

class ScanType(str, enum.Enum):
    DOMAIN = "domain"          # DNS, Subdomains, CT, HIBP
    ASSET = "asset"            # Port-Scan, Service-Fingerprinting
    FULL = "full"              # Beides kombiniert
    HIBP = "hibp"              # Nur HIBP-Checks
    PASSWORD = "password"      # Nur Passwort-Checks

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ScanJob(Base):
    """Ein einzelner Scan-Auftrag"""
    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_scanjobs_tenant", "tenant_id"),
        Index("ix_scanjobs_status", "status"),
        Index("ix_scanjobs_created", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)

    scan_type = Column(Enum(ScanType), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)

    # Zielobjekte
    target_domain_id = Column(String(36), ForeignKey("domains.id"), nullable=True)
    target_ip_range_id = Column(String(36), ForeignKey("ip_ranges.id"), nullable=True)

    # Celery Task ID für Status-Tracking
    celery_task_id = Column(String(36))

    # Ergebnisse (Summary)
    findings_count = Column(JSON, default=dict)  # {"CRITICAL": 3, "HIGH": 7, ...}
    risk_score_before = Column(Integer)
    risk_score_after = Column(Integer)
    duration_seconds = Column(Integer)
    error_message = Column(Text)

    # Vollständige Ergebnisse als JSON (für schnelle Abfrage)
    raw_results = Column(JSON)

    # Scheduling
    triggered_by = Column(String(100))  # "schedule", "manual", "api"
    scheduled_for = Column(DateTime)

    created_at = Column(DateTime, default=utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)

    # Relationships
    tenant = relationship("Tenant", back_populates="scan_jobs")
    findings = relationship("Finding", back_populates="scan_job", cascade="all, delete-orphan")


# ─── Findings (Einzelne Schwachstellen) ──────────────────────────────

class FindingSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FindingStatus(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_REMEDIATION = "in_remediation"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"

class FindingCategory(str, enum.Enum):
    CREDENTIAL_LEAK = "credential_leak"
    STEALER_LOG = "stealer_log"
    EXPOSED_SERVICE = "exposed_service"
    SUBDOMAIN_RISK = "subdomain_risk"
    CVE = "cve"
    SSL_ISSUE = "ssl_issue"
    DNS_ISSUE = "dns_issue"
    EMAIL_SECURITY = "email_security"
    TYPOSQUAT = "typosquat"
    PASSWORD_BREACH = "password_breach"
    OT_SCADA = "ot_scada"
    CLOUD_API = "cloud_api"

class Finding(Base):
    """Eine einzelne Schwachstelle / ein Fund"""
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_tenant", "tenant_id"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_status", "status"),
        Index("ix_findings_category", "category"),
        Index("ix_findings_first_seen", "first_seen_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    scan_job_id = Column(String(36), ForeignKey("scan_jobs.id"), nullable=True)

    # Klassifizierung
    category = Column(Enum(FindingCategory), nullable=False)
    severity = Column(Enum(FindingSeverity), nullable=False)
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN)

    # Titel und Beschreibung
    title = Column(String(500), nullable=False)
    description = Column(Text)
    remediation = Column(Text)      # Konkrete Handlungsempfehlung
    technical_details = Column(JSON)  # Rohdaten (Banner, Headers, CVE-Details etc.)

    # Betroffenes Asset
    affected_asset = Column(String(500))  # IP:Port, Domain, E-Mail
    affected_url = Column(String(1000))

    # CVE-spezifisch
    cve_id = Column(String(50))
    cvss_score = Column(Float)
    cisa_kev = Column(Boolean, default=False)
    epss_score = Column(Float)

    # HIBP-spezifisch
    breach_name = Column(String(200))
    breach_date = Column(DateTime)
    pwn_count = Column(Integer)
    data_classes = Column(JSON)      # ["Passwords", "Email addresses", ...]
    is_malware = Column(Boolean, default=False)
    is_stealer_log = Column(Boolean, default=False)

    # Risk Score
    risk_score = Column(Integer, default=0)  # 0-100 pro Finding

    # Lifecycle
    first_seen_at = Column(DateTime, default=utcnow)
    last_seen_at = Column(DateTime, default=utcnow)
    resolved_at = Column(DateTime)
    accepted_at = Column(DateTime)
    accepted_reason = Column(Text)
    accepted_by = Column(String(200))
    accepted_expires_at = Column(DateTime)  # Risk-Acceptance läuft ab

    # Ticket-Integration
    ticket_id = Column(String(200))   # Jira/ServiceNow Ticket-ID
    ticket_url = Column(String(500))

    # Fingerprint für Deduplizierung
    fingerprint = Column(String(64))  # SHA256 von category+asset+details

    # Relationships
    tenant = relationship("Tenant", back_populates="findings")
    scan_job = relationship("ScanJob", back_populates="findings")
    history = relationship("FindingHistory", back_populates="finding",
                          cascade="all, delete-orphan")

class FindingHistory(Base):
    """Audit-Trail: jede Status-Änderung eines Findings"""
    __tablename__ = "finding_history"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False)
    changed_by = Column(String(200))
    old_status = Column(String(50))
    new_status = Column(String(50))
    note = Column(Text)
    timestamp = Column(DateTime, default=utcnow)

    finding = relationship("Finding", back_populates="history")


# ─── Reports ─────────────────────────────────────────────────────────

class ReportType(str, enum.Enum):
    EXECUTIVE_SUMMARY = "executive_summary"  # 1-Seiter für Geschäftsführung
    TECHNICAL_DETAIL = "technical_detail"    # Vollständiger technischer Report
    COMPLIANCE_BSI = "compliance_bsi"        # BSI IT-Grundschutz
    COMPLIANCE_NIS2 = "compliance_nis2"      # NIS2
    COMPLIANCE_ISO = "compliance_iso27001"   # ISO 27001
    MONTHLY = "monthly"                      # Monatlicher MSSP-Report
    DELTA = "delta"                          # Was hat sich geändert?

class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_tenant", "tenant_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)

    report_type = Column(Enum(ReportType), nullable=False)
    title = Column(String(300))
    period_start = Column(DateTime)
    period_end = Column(DateTime)

    # Snapshot der Metriken zum Report-Zeitpunkt
    score_at_generation = Column(Integer)
    findings_snapshot = Column(JSON)

    # Generierter Inhalt
    pdf_path = Column(String(500))  # Pfad zur PDF-Datei
    html_content = Column(Text)

    generated_at = Column(DateTime, default=utcnow)
    generated_by = Column(String(200))  # User-ID oder "scheduler"

    # Auto-Versand
    sent_to = Column(JSON)   # [{"email": "...", "sent_at": "..."}]

    tenant = relationship("Tenant", back_populates="reports")


# ─── Risk Acceptance ─────────────────────────────────────────────────

class RiskAcceptance(Base):
    """Dokumentierte Ausnahmen: Finding wird bewusst akzeptiert"""
    __tablename__ = "risk_acceptances"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    finding_fingerprint = Column(String(64), nullable=False)  # Welches Finding-Muster
    reason = Column(Text, nullable=False)
    accepted_by = Column(String(200), nullable=False)
    approved_by = Column(String(200))   # 4-Augen-Prinzip: MSSP-Analyst muss genehmigen
    expires_at = Column(DateTime)       # Zwingend: Ausnahmen laufen ab
    created_at = Column(DateTime, default=utcnow)
    ticket_reference = Column(String(200))


# ─── Audit Log (unveränderlich) ───────────────────────────────────────

class AuditLog(Base):
    """Manipulationssicherer Audit-Trail aller wichtigen Aktionen"""
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_tenant", "tenant_id"),
        Index("ix_audit_timestamp", "timestamp"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), nullable=True)
    user_id = Column(String(36))
    action = Column(String(200), nullable=False)   # z.B. "scan.started", "finding.accepted"
    resource_type = Column(String(100))
    resource_id = Column(String(36))
    details = Column(JSON)
    ip_address = Column(String(50))
    timestamp = Column(DateTime, default=utcnow)
    # Integrity: SHA256 Hash des Eintrags (Chain-of-Trust)
    prev_hash = Column(String(64))
    entry_hash = Column(String(64))
