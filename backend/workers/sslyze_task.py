"""
SSLyze TLS Scanner — Celery Task
=================================
Scannt TLS-Endpunkte auf:
  - Veraltete Protokolle (TLS 1.0, TLS 1.1, SSL 2/3)
  - Schwache Cipher Suites (RC4, 3DES, EXPORT, NULL)
  - Heartbleed (CVE-2014-0160)
  - ROBOT Attack
  - HSTS-Header fehlt
  - Zertifikat-Ablauf (<30d HIGH, <7d CRITICAL)
  - Self-signed / unvertrauenswürdige Zertifikate
"""

import os, sys, datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from celery import Celery
from celery.utils.log import get_task_logger

celery_app = Celery(
    "easm_sslyze",
    broker=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    backend=os.getenv("REDIS_URL", "redis://localhost:6379/1"),
)

logger = get_task_logger(__name__)

# Weak cipher keywords — presence in suite name triggers MEDIUM finding
_WEAK_CIPHERS = ("RC4", "3DES", "DES", "EXPORT", "NULL", "ANON", "RC2")

# Severity thresholds for cert expiry (days remaining)
_CERT_EXPIRY_CRITICAL = 7
_CERT_EXPIRY_HIGH     = 30


def _make_finding(sev: str, cat: str, title: str, asset: str,
                  desc: str, fix: str, cvss: float,
                  cve: str = None, tool: str = "sslyze") -> dict:
    return {
        "severity":      sev,
        "category":      cat,
        "title":         title,
        "affected_asset": asset,
        "description":   desc,
        "remediation":   fix,
        "cvss":          cvss,
        "cve":           cve,
        "tool":          tool,
        "status":        "open",
        "discovered_at": datetime.datetime.utcnow().isoformat(),
    }


def _scan_target(host: str, port: int) -> list:
    """Run SSLyze against a single (host, port) and return raw findings."""
    try:
        from sslyze import (
            Scanner, ServerScanRequest, ServerNetworkLocation,
            ScanCommand,
        )
        from sslyze.errors import ConnectionToServerFailed
    except ImportError:
        logger.warning("sslyze not installed — skipping TLS scan")
        return []

    findings = []
    asset = f"{host}:{port}"

    try:
        location = ServerNetworkLocation(hostname=host, port=port)
        request = ServerScanRequest(
            server_location=location,
            scan_commands={
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.HTTP_HEADERS,
            },
        )
        scanner = Scanner()
        scanner.queue_scans([request])

        for result in scanner.get_results():
            if result.scan_result is None:
                continue

            sr = result.scan_result

            # ── Deprecated protocol checks ─────────────────────────────────
            deprecated = []
            for cmd, label in [
                (ScanCommand.SSL_2_0_CIPHER_SUITES, "SSL 2.0"),
                (ScanCommand.SSL_3_0_CIPHER_SUITES, "SSL 3.0"),
                (ScanCommand.TLS_1_0_CIPHER_SUITES, "TLS 1.0"),
                (ScanCommand.TLS_1_1_CIPHER_SUITES, "TLS 1.1"),
            ]:
                attr = cmd.value.lower()
                scan_res = getattr(sr, attr, None)
                if scan_res and scan_res.accepted_cipher_suites:
                    deprecated.append(label)

            if deprecated:
                protos = " + ".join(deprecated)
                findings.append(_make_finding(
                    sev="MEDIUM", cat="TLS",
                    title=f"Veraltete TLS-Protokolle aktiv: {protos}",
                    asset=asset,
                    desc=(
                        f"{asset} akzeptiert {protos}-Verbindungen. "
                        "Diese Protokolle sind veraltet (RFC 8996) und anfällig "
                        "für POODLE/BEAST-Angriffe. PCI-DSS 4.0 erfordert TLS ≥ 1.2."
                    ),
                    fix=(
                        "Protokolle deaktivieren. nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                        "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3"
                    ),
                    cvss=5.9,
                ))

            # ── Weak cipher suites ─────────────────────────────────────────
            weak_found = set()
            for cmd in [
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
            ]:
                attr = cmd.value.lower()
                scan_res = getattr(sr, attr, None)
                if not scan_res:
                    continue
                for suite in scan_res.accepted_cipher_suites:
                    name = suite.cipher_suite.name.upper()
                    for weak in _WEAK_CIPHERS:
                        if weak in name:
                            weak_found.add(weak)

            if weak_found:
                weak_list = ", ".join(sorted(weak_found))
                findings.append(_make_finding(
                    sev="MEDIUM", cat="TLS",
                    title=f"Schwache Cipher Suites aktiv: {weak_list}",
                    asset=asset,
                    desc=(
                        f"{asset} akzeptiert unsichere Cipher Suites ({weak_list}). "
                        "RC4 ist kryptographisch gebrochen (RFC 7465). "
                        "3DES ist anfällig für Sweet32 Birthday-Angriffe."
                    ),
                    fix=(
                        "RC4 und 3DES aus Cipher-Suite-Liste entfernen. "
                        "Nur ECDHE+AES-GCM und ChaCha20-Poly1305 verwenden. "
                        "Test: sslyze --regular <host>"
                    ),
                    cvss=5.3,
                ))

            # ── Heartbleed ─────────────────────────────────────────────────
            hb = getattr(sr, "heartbleed", None)
            if hb and hb.result and hb.result.is_vulnerable_to_heartbleed:
                findings.append(_make_finding(
                    sev="CRITICAL", cat="CVE",
                    title="Heartbleed — OpenSSL Speicherleck (CVE-2014-0160)",
                    asset=asset,
                    desc=(
                        f"{asset} ist verwundbar gegen Heartbleed. "
                        "Angreifer können bis zu 64 KB Serverspeicher pro Request lesen, "
                        "einschließlich privater TLS-Schlüssel und Session-Tokens."
                    ),
                    fix="OpenSSL auf ≥1.0.1g / ≥1.0.2 aktualisieren. "
                        "TLS-Zertifikat und alle privaten Schlüssel erneuern.",
                    cvss=7.5,
                    cve="CVE-2014-0160",
                ))

            # ── ROBOT ──────────────────────────────────────────────────────
            robot = getattr(sr, "robot", None)
            if robot and robot.result:
                from sslyze.plugins.robot.implementation import RobotScanResultEnum
                if robot.result.robot_result not in (
                    RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE,
                    RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED,
                ):
                    findings.append(_make_finding(
                        sev="HIGH", cat="TLS",
                        title="ROBOT Attack — RSA-Padding-Orakel",
                        asset=asset,
                        desc=(
                            f"{asset} ist anfällig für den ROBOT-Angriff. "
                            "RSA-Verschlüsselung kann angegriffen werden, "
                            "Session-Keys entschlüsselbar."
                        ),
                        fix="RSA-Schlüsselaustausch deaktivieren. "
                            "Nur ECDHE-Cipher-Suites aktivieren (Forward Secrecy).",
                        cvss=7.4,
                    ))

            # ── HSTS ───────────────────────────────────────────────────────
            http_hdr = getattr(sr, "http_headers", None)
            if http_hdr and http_hdr.result:
                hsts = http_hdr.result.strict_transport_security_header
                if not hsts:
                    findings.append(_make_finding(
                        sev="LOW", cat="TLS",
                        title="HSTS nicht konfiguriert",
                        asset=asset,
                        desc=(
                            f"{asset}: HTTP Strict Transport Security Header fehlt. "
                            "Ermöglicht Protocol-Downgrade-Angriffe. "
                            "Ohne HSTS können Angreifer initiale HTTP-Requests abfangen."
                        ),
                        fix="Header setzen: Strict-Transport-Security: "
                            "max-age=31536000; includeSubDomains; preload",
                        cvss=3.1,
                    ))

            # ── Certificate expiry / validity ──────────────────────────────
            cert_info = getattr(sr, "certificate_info", None)
            if cert_info and cert_info.result:
                for chain in cert_info.result.certificate_deployments:
                    if not chain.received_certificate_chain:
                        continue
                    leaf = chain.received_certificate_chain[0]

                    # Expiry
                    not_after = leaf.not_valid_after_utc.replace(tzinfo=None)
                    days_left = (not_after - datetime.datetime.utcnow()).days

                    if days_left <= 0:
                        findings.append(_make_finding(
                            sev="CRITICAL", cat="TLS",
                            title=f"TLS-Zertifikat abgelaufen ({asset})",
                            asset=asset,
                            desc=f"Das Zertifikat für {asset} ist abgelaufen ({not_after.date()}).",
                            fix="Zertifikat sofort erneuern. Let's Encrypt certbot empfohlen.",
                            cvss=7.5,
                        ))
                    elif days_left <= _CERT_EXPIRY_CRITICAL:
                        findings.append(_make_finding(
                            sev="CRITICAL", cat="TLS",
                            title=f"TLS-Zertifikat läuft in {days_left} Tagen ab",
                            asset=asset,
                            desc=f"Zertifikat für {asset} läuft am {not_after.date()} ab. Browser-Warnungen unmittelbar bevorstehend.",
                            fix="Zertifikat sofort erneuern. Auto-Renewal via ACME/certbot einrichten.",
                            cvss=7.5,
                        ))
                    elif days_left <= _CERT_EXPIRY_HIGH:
                        findings.append(_make_finding(
                            sev="HIGH", cat="TLS",
                            title=f"TLS-Zertifikat läuft in {days_left} Tagen ab",
                            asset=asset,
                            desc=f"Zertifikat für {asset} läuft am {not_after.date()} ab.",
                            fix="Zertifikat erneuern. Auto-Renewal via ACME/certbot einrichten.",
                            cvss=5.3,
                        ))

                    # Self-signed
                    if chain.path_validation_results:
                        all_failed = all(
                            not r.was_validation_successful
                            for r in chain.path_validation_results
                        )
                        if all_failed:
                            findings.append(_make_finding(
                                sev="MEDIUM", cat="TLS",
                                title="Self-signed / ungültiges Zertifikat",
                                asset=asset,
                                desc=f"Das Zertifikat für {asset} ist self-signed oder nicht von einer vertrauenswürdigen CA ausgestellt.",
                                fix="Zertifikat von einer öffentlichen CA (z.B. Let's Encrypt, DigiCert) ausstellen lassen.",
                                cvss=5.3,
                            ))

    except Exception as exc:
        logger.warning(f"SSLyze scan failed for {asset}: {exc}")

    return findings


@celery_app.task(
    bind=True,
    name="workers.toolchain_tasks.run_sslyze",
    max_retries=2,
    default_retry_delay=60,
    queue="tls",
    soft_time_limit=600,
    time_limit=900,
)
def run_sslyze(self, tenant_id: str, targets: list) -> dict:
    """
    TLS-Scan via SSLyze für alle TLS-Endpunkte eines Mandanten.

    Args:
        tenant_id: Mandanten-ID
        targets:   Liste von {"host": str, "port": int} oder [host, port]

    Returns:
        dict mit findings_count, by_severity, duration_seconds
    """
    import time
    t0 = time.time()
    all_findings = []

    normalized = []
    for t in targets:
        if isinstance(t, dict):
            normalized.append((t["host"], int(t.get("port", 443))))
        elif isinstance(t, (list, tuple)) and len(t) >= 2:
            normalized.append((str(t[0]), int(t[1])))
        else:
            normalized.append((str(t), 443))

    logger.info(f"[{tenant_id}] SSLyze: scanning {len(normalized)} TLS endpoints")

    for host, port in normalized:
        findings = _scan_target(host, port)
        all_findings.extend(findings)
        logger.info(f"[{tenant_id}] SSLyze: {host}:{port} → {len(findings)} findings")

    by_severity: dict = {}
    for f in all_findings:
        sev = f["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

    duration = round(time.time() - t0, 1)
    logger.info(
        f"[{tenant_id}] SSLyze: done — {len(all_findings)} findings "
        f"in {duration}s | {by_severity}"
    )

    return {
        "tenant_id":       tenant_id,
        "findings_count":  len(all_findings),
        "findings":        all_findings,
        "by_severity":     by_severity,
        "duration_seconds": duration,
    }
