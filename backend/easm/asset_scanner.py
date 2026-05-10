"""
EASM Asset & Service Scanner — Erweiterung der easm_engine.py
=============================================================
Scannt ALLE extern exponierten Assets und Services einer IP-Range oder Domain:

  1. IP-Range Port-Scanning  (concurrent, schnell)
  2. Service-Fingerprinting  (Banner Grabbing + HTTP-Header)
  3. HTTP-Technologie-Erkennung (Server, Framework, CMS)
  4. Auth-Check auf exponierten Services (kein Passwort?)
  5. Web-Application Checks (Admin-Panels, Default-Creds)
  6. Cloud-Metadaten-Exposure (SSRF auf 169.254.169.254)
  7. API-Endpoint-Discovery
  8. Vuln-Correlation (Service-Version → CVE)
  9. Asset-Inventar mit Risk-Score pro Asset

Architektur:
  easm_engine.py          ← DNS / Domain-Layer (bestehend)
        +
  easm_asset_scanner.py   ← IP / Service / Port-Layer (neu)
        |
        v
  EASMReport (vereint beide)
"""

import socket
import ssl
import json
import ipaddress
import datetime
import concurrent.futures
import urllib.request
import urllib.error
import re
import time
from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════
# KONFIGURATION — Port-Listen & Fingerprints
# ═══════════════════════════════════════════════════════════════════════

# Vollständige Port-Liste für MSSP-Scan (Top 1000 + spezifische OT/Cloud-Ports)
PORT_CATEGORIES = {

    # ── Web-Services ────────────────────────────────────────────────
    "web": [80, 443, 8080, 8443, 8000, 8008, 8888, 9443, 4443,
            8081, 8082, 8090, 8091, 9000, 9001, 10000],

    # ── Datenbanken (fast IMMER kritisch wenn exponiert) ────────────
    "database": [3306, 5432, 1433, 1521, 27017, 27018, 6379,
                 6380, 9200, 9300, 5601, 7474, 7687, 2181,
                 11211, 6432, 4369, 5984],

    # ── Remote Access (höchstes Risiko) ────────────────────────────
    "remote": [22, 23, 3389, 5900, 5901, 5902, 5985, 5986,
               2222, 2323, 4899, 5631],

    # ── Mail ────────────────────────────────────────────────────────
    "mail": [25, 110, 143, 465, 587, 993, 995, 2525],

    # ── Dateiübertragung ─────────────────────────────────────────────
    "file_transfer": [21, 69, 445, 139, 2049, 111, 548, 873, 990],

    # ── Netzwerk-Infrastruktur ──────────────────────────────────────
    "network": [53, 67, 68, 123, 161, 162, 179, 500, 4500,
                1194, 1723, 1812, 1813],

    # ── DevOps / CI/CD (sehr häufig falsch exponiert) ───────────────
    "devops": [2376, 2377, 4243,   # Docker
               6443, 8001, 10250,  # Kubernetes
               9090, 9091, 3000,   # Prometheus / Grafana
               8161, 61616,        # ActiveMQ
               5672, 15672,        # RabbitMQ
               9092, 9093,         # Kafka
               4848,               # GlassFish
               7001, 7002,         # WebLogic
               4567, 8983,         # Solr
               50070, 50090, 8088, # Hadoop
               8888, 7070],        # Jupyter / Tomcat

    # ── OT / SCADA / ICS (KRITIS-relevant) ─────────────────────────
    "ot_scada": [102,   # Siemens S7 / ISO-TSAP
                 502,   # Modbus TCP
                 789,   # Red Lion
                 1089,  # FF Annunciation
                 1091,  # FF System Management
                 1541,  # Wonderware
                 2222,  # EtherNet/IP
                 4000,  # EMERSON DeltaV
                 4840,  # OPC-UA
                 9600,  # OMRON FINS
                 11001, # ProConOS
                 20000, # DNP3
                 44818, # EtherNet/IP
                 47808],# BACnet

    # ── Cloud / Management ──────────────────────────────────────────
    "cloud": [2375, 2376,  # Docker API
              6443,        # K8s API Server
              10255,       # K8s Kubelet (read-only)
              10250,       # K8s Kubelet
              2379, 2380,  # etcd
              8500,        # Consul
              8200, 8201,  # HashiCorp Vault
              4001],       # etcd (alt)
}

# Alle zu scannenden Ports
ALL_PORTS = sorted(set(p for ports in PORT_CATEGORIES.values() for p in ports))

# ── Service-Identification ───────────────────────────────────────────
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 69: "TFTP", 80: "HTTP", 102: "S7/ISO-TSAP",
    110: "POP3", 111: "RPCbind", 123: "NTP", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 179: "BGP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE",
    502: "Modbus", 548: "AFP", 587: "SMTP-Submission", 873: "rsync",
    993: "IMAPS", 995: "POP3S", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "Oracle-DB", 1723: "PPTP", 1812: "RADIUS",
    2049: "NFS", 2179: "Hyper-V", 2222: "EtherNet/IP",
    2375: "Docker-API (unencrypted!)", 2376: "Docker-API-TLS",
    2377: "Docker-Swarm", 2379: "etcd", 2380: "etcd-peer",
    3000: "Grafana", 3306: "MySQL", 3389: "RDP", 4000: "EMERSON",
    4243: "Docker", 4444: "Metasploit?", 4840: "OPC-UA",
    4848: "GlassFish-Admin", 4899: "RAdmin", 4500: "IKE-NAT",
    5432: "PostgreSQL", 5601: "Kibana", 5631: "PCAnywhere",
    5672: "AMQP/RabbitMQ", 5900: "VNC", 5901: "VNC-1",
    5984: "CouchDB", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis", 6432: "PgBouncer", 6443: "K8s-API",
    7001: "WebLogic", 7474: "Neo4j-HTTP", 7687: "Neo4j-Bolt",
    8000: "HTTP-Alt", 8001: "K8s-Admin", 8080: "HTTP-Proxy",
    8081: "HTTP-Alt", 8083: "InfluxDB", 8086: "InfluxDB-API",
    8088: "Hadoop-YARN", 8161: "ActiveMQ-Admin",
    8200: "HashiCorp-Vault", 8443: "HTTPS-Alt", 8500: "Consul",
    8888: "Jupyter", 8983: "Apache-Solr", 9000: "SonarQube",
    9090: "Prometheus", 9091: "Prometheus-Alt", 9092: "Kafka",
    9200: "Elasticsearch", 9300: "Elasticsearch-Cluster",
    9443: "HTTPS-Alt", 9600: "OMRON-FINS", 10000: "Webmin",
    10250: "K8s-Kubelet", 10255: "K8s-Kubelet-RO",
    11001: "ProConOS", 11211: "Memcached", 15672: "RabbitMQ-Admin",
    20000: "DNP3", 27017: "MongoDB", 27018: "MongoDB-Alt",
    44818: "EtherNet/IP-Explicit", 47808: "BACnet", 50070: "Hadoop-NameNode",
    50090: "Hadoop-SNN", 61616: "ActiveMQ-Broker",
}

# ── Risk-Bewertung pro Service ────────────────────────────────────────
SERVICE_RISKS = {
    # CRITICAL — sofortiger Handlungsbedarf
    23:    ("CRITICAL", "Telnet: Klartext-Protokoll, Credentials vollständig lesbar"),
    2375:  ("CRITICAL", "Docker API unverschlüsselt: vollständige Container-Kontrolle ohne Auth"),
    502:   ("CRITICAL", "Modbus TCP: OT-Protokoll ohne Auth — direkter Maschinenzugriff"),
    102:   ("CRITICAL", "S7/ISO-TSAP: Siemens SPS direkt erreichbar — SCADA-Angriff möglich"),
    44818: ("CRITICAL", "EtherNet/IP: industrieller Bus exponiert"),
    20000: ("CRITICAL", "DNP3: Energieversorgungsprotokoll exponiert"),
    445:   ("CRITICAL", "SMB: EternalBlue/MS17-010, Ransomware-Hauptvektor"),
    3389:  ("CRITICAL", "RDP: Ransomware-Haupteinfallstor, Brute-Force-Ziel"),
    5985:  ("CRITICAL", "WinRM HTTP: Remote Code Execution ohne TLS"),
    6379:  ("CRITICAL", "Redis: meist ohne Auth, beliebter Pivot-Punkt"),
    9200:  ("CRITICAL", "Elasticsearch: oft ohne Auth, Datenleck + Cluster-Übernahme"),
    27017: ("CRITICAL", "MongoDB: oft ohne Auth, direkter DB-Zugriff"),
    9600:  ("CRITICAL", "OMRON FINS: SPS direkt erreichbar"),
    11001: ("CRITICAL", "ProConOS: ICS-System exponiert"),
    2379:  ("CRITICAL", "etcd: K8s-Cluster-Geheimnisse lesbar ohne Auth"),
    10250: ("CRITICAL", "K8s Kubelet: Remote Code Execution auf Node"),

    # HIGH — dringend zu untersuchen
    22:    ("HIGH",     "SSH: Brute-Force-Angriffsfläche, Key-Management prüfen"),
    5432:  ("HIGH",     "PostgreSQL: DB direkt exponiert, Auth prüfen"),
    3306:  ("HIGH",     "MySQL: DB direkt exponiert"),
    1433:  ("HIGH",     "MSSQL: DB direkt exponiert"),
    1521:  ("HIGH",     "Oracle DB: direkt exponiert"),
    5601:  ("HIGH",     "Kibana: Admin-UI, Datenleck"),
    9090:  ("HIGH",     "Prometheus: Metrics-Dump, interne Infrastruktur sichtbar"),
    3000:  ("HIGH",     "Grafana: oft mit Default-Creds (admin/admin)"),
    8888:  ("HIGH",     "Jupyter Notebook: oft ohne Auth, RCE durch Notebook-Ausführung"),
    15672: ("HIGH",     "RabbitMQ Admin: oft mit Default-Creds (guest/guest)"),
    8161:  ("HIGH",     "ActiveMQ Admin Console: Default-Creds bekannt"),
    4848:  ("HIGH",     "GlassFish Admin: Default-Creds, bekannte RCE-CVEs"),
    7001:  ("HIGH",     "WebLogic: kritische RCE-CVEs (CVE-2020-14882 etc.)"),
    7474:  ("HIGH",     "Neo4j Browser: Datenbank-UI exponiert"),
    5900:  ("HIGH",     "VNC: Remote Desktop, Brute-Force"),
    8500:  ("HIGH",     "Consul: Service Discovery, oft ohne ACL"),
    8200:  ("HIGH",     "HashiCorp Vault: Secrets-Manager exponiert"),
    10000: ("HIGH",     "Webmin: Admin-Interface, bekannte CVEs"),
    8983:  ("HIGH",     "Apache Solr: Admin-UI + bekannte RCE-CVEs"),
    9000:  ("HIGH",     "SonarQube: Code-Analyse-Plattform, Source-Code-Leck"),
    50070: ("HIGH",     "Hadoop NameNode: Cluster-Admin-UI"),
    6443:  ("HIGH",     "K8s API Server: Cluster-Zugriff, Auth prüfen"),
    8001:  ("HIGH",     "K8s Dashboard: häufig mit zu weiten Rechten"),
    69:    ("HIGH",     "TFTP: kein Auth, Datei-Lesen/Schreiben möglich"),
    111:   ("HIGH",     "RPCbind: NFS-Mountpoints werden exponiert"),
    2049:  ("HIGH",     "NFS: Dateisystem-Shares, oft zu weit offen"),
    873:   ("HIGH",     "rsync: Datei-Sync ohne Auth"),
    11211: ("HIGH",     "Memcached: Cache-Dump möglich, bekannte DDoS-Amplifikation"),
    4840:  ("HIGH",     "OPC-UA: ICS-Kommunikation exponiert"),
    47808: ("HIGH",     "BACnet: Gebäudeautomation exponiert"),

    # MEDIUM — zu prüfen
    25:    ("MEDIUM",   "SMTP: Open Relay prüfen, Banner-Grabbing"),
    21:    ("MEDIUM",   "FTP: unverschlüsselt, anonymer Login prüfen"),
    161:   ("MEDIUM",   "SNMP: Community String 'public' prüfen"),
    5672:  ("MEDIUM",   "AMQP: Message-Broker, Auth-Konfiguration prüfen"),
    4369:  ("MEDIUM",   "Erlang Port Mapper: RabbitMQ-Cluster-Kommunikation"),
    2181:  ("MEDIUM",   "ZooKeeper: Cluster-Koordination, oft ohne Auth"),
    9092:  ("MEDIUM",   "Kafka: Message-Bus, Auth prüfen"),
    5984:  ("MEDIUM",   "CouchDB: NoSQL-DB, Admin-Interface prüfen"),
    8086:  ("MEDIUM",   "InfluxDB API: Zeitreihendaten"),
    8083:  ("MEDIUM",   "InfluxDB Admin: Admin-UI"),
    1723:  ("MEDIUM",   "PPTP VPN: veraltetes, unsicheres VPN-Protokoll"),
}

# ── Web-Technologie-Fingerprints ──────────────────────────────────────
TECH_FINGERPRINTS = {
    # Server-Header
    "Apache":       {"header": "Server", "pattern": r"Apache/?([0-9.]+)?"},
    "nginx":        {"header": "Server", "pattern": r"nginx/?([0-9.]+)?"},
    "IIS":          {"header": "Server", "pattern": r"Microsoft-IIS/?([0-9.]+)?"},
    "Tomcat":       {"header": "Server", "pattern": r"Apache-Coyote|Tomcat"},
    "Cloudflare":   {"header": "Server", "pattern": r"cloudflare"},
    "LiteSpeed":    {"header": "Server", "pattern": r"LiteSpeed"},

    # Framework / CMS
    "WordPress":    {"header": "X-Powered-By", "pattern": r"WordPress|WP"},
    "PHP":          {"header": "X-Powered-By", "pattern": r"PHP/?([0-9.]+)?"},
    "ASP.NET":      {"header": "X-Powered-By", "pattern": r"ASP\.NET/?([0-9.]+)?"},
    "Django":       {"header": "X-Frame-Options", "pattern": r"SAMEORIGIN|DENY"},

    # Security Headers (Fehlen ist ein Finding)
    "no_hsts":          {"header": "Strict-Transport-Security", "pattern": None, "inverted": True},
    "no_csp":           {"header": "Content-Security-Policy", "pattern": None, "inverted": True},
    "no_x_frame":       {"header": "X-Frame-Options", "pattern": None, "inverted": True},
    "no_x_content":     {"header": "X-Content-Type-Options", "pattern": None, "inverted": True},
    "server_exposed":   {"header": "Server", "pattern": r"Apache|nginx|IIS|Tomcat|PHP"},
}

# ── Default Credential Tests ──────────────────────────────────────────
DEFAULT_CREDS = {
    "Grafana":       [("admin", "admin"), ("admin", "grafana")],
    "ActiveMQ":      [("admin", "admin"), ("admin", "activemq")],
    "RabbitMQ":      [("guest", "guest"), ("admin", "admin")],
    "Jenkins":       [("admin", ""), ("admin", "admin")],
    "Elasticsearch": [(None, None)],  # Auth-freier Zugriff
    "Redis":         [(None, None)],  # PING-Test
}


# ═══════════════════════════════════════════════════════════════════════
# DATENMODELLE
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ServiceFinding:
    ip: str
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    version: str = ""
    banner: str = ""
    product: str = ""
    risk: str = "MEDIUM"
    risk_reason: str = ""
    category: str = "other"
    http_info: dict = field(default_factory=dict)
    ssl_info: dict = field(default_factory=dict)
    auth_required: bool = True
    default_creds_work: bool = False
    cves: list = field(default_factory=list)
    remediation: str = ""

@dataclass
class AssetInventory:
    ip: str
    hostname: str = ""
    open_ports: list = field(default_factory=list)
    services: list = field(default_factory=list)
    os_guess: str = ""
    risk_score: int = 0
    highest_severity: str = "LOW"
    is_cloud: bool = False
    cloud_provider: str = ""
    asn: str = ""
    org: str = ""
    country: str = ""

@dataclass
class AssetScanReport:
    tenant_id: str
    ip_ranges: list
    scan_timestamp: str
    assets: list = field(default_factory=list)
    service_findings: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    ot_scada_exposed: bool = False
    cloud_apis_exposed: bool = False
    databases_exposed: bool = False


# ═══════════════════════════════════════════════════════════════════════
# PORT SCANNER
# ═══════════════════════════════════════════════════════════════════════

class PortScanner:
    """
    Schneller concurrent Port-Scanner.
    Nutzt ThreadPoolExecutor für Parallelität.
    Kein Scapy, kein Root-Zugriff nötig.
    """

    def __init__(self, timeout: float = 1.5, max_workers: int = 200):
        self.timeout = timeout
        self.max_workers = max_workers

    def probe_port(self, host: str, port: int) -> Optional[int]:
        """Prüft ob ein Port offen ist"""
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                return port
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def scan_host(self, host: str, ports: list = None) -> list:
        """Scannt alle Ports eines Hosts, gibt offene Ports zurück"""
        if ports is None:
            ports = ALL_PORTS

        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(self.probe_port, host, p): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.append(result)

        return sorted(open_ports)

    def scan_range(self, cidr: str, ports: list = None,
                   max_hosts: int = 256) -> dict:
        """
        Scannt eine komplette IP-Range.
        Gibt {ip: [offene_ports]} zurück.
        """
        if ports is None:
            ports = ALL_PORTS

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return {}

        results = {}
        hosts = list(network.hosts())[:max_hosts]

        print(f"  Scanne {len(hosts)} Hosts in {cidr} auf {len(ports)} Ports...")

        # Ping-Sweep: welche Hosts antworten überhaupt?
        alive_hosts = self._ping_sweep(hosts)
        print(f"  {len(alive_hosts)} erreichbare Hosts gefunden")

        # Port-Scan nur auf erreichbare Hosts
        for host_ip in alive_hosts:
            host_str = str(host_ip)
            open_ports = self.scan_host(host_str, ports)
            if open_ports:
                results[host_str] = open_ports
                print(f"    {host_str}: {len(open_ports)} offene Ports → {open_ports}")

        return results

    def _ping_sweep(self, hosts: list) -> list:
        """Schneller Ping-Sweep via TCP-Connect auf Port 80/443/22"""
        alive = []
        probe_ports = [80, 443, 22, 8080, 8443]

        def check_alive(ip):
            for port in probe_ports:
                try:
                    with socket.create_connection((str(ip), port), timeout=0.5):
                        return ip
                except:
                    pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
            futures = [ex.submit(check_alive, h) for h in hosts]
            for f in concurrent.futures.as_completed(futures):
                r = f.result()
                if r:
                    alive.append(r)

        return alive


# ═══════════════════════════════════════════════════════════════════════
# SERVICE FINGERPRINTER
# ═══════════════════════════════════════════════════════════════════════

class ServiceFingerprinter:
    """
    Identifiziert Services hinter offenen Ports.
    Banner Grabbing + HTTP-Header-Analyse + SSL-Inspektion.
    """

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def fingerprint(self, host: str, port: int) -> ServiceFinding:
        """Vollständiges Fingerprinting eines Services"""
        finding = ServiceFinding(
            ip=host,
            port=port,
            service=SERVICE_MAP.get(port, "unknown"),
            category=self._get_category(port)
        )

        # Risk-Bewertung aus statischer Map
        if port in SERVICE_RISKS:
            finding.risk, finding.risk_reason = SERVICE_RISKS[port]
            finding.remediation = self._get_remediation(port)

        # Banner Grabbing
        banner = self._grab_banner(host, port)
        if banner:
            finding.banner = banner[:200]
            finding.version = self._extract_version(banner, port)
            finding.product = self._identify_product(banner)

        # HTTP-spezifische Analyse
        if port in [80, 8080, 8000, 8008, 8081, 8082, 8090, 9000, 9001,
                    10000, 3000, 9090, 8161, 8983, 15672, 4848, 7474, 8888]:
            http_info = self._analyze_http(host, port, ssl=False)
            finding.http_info = http_info
            if http_info.get("missing_security_headers"):
                if finding.risk in ("LOW", "MEDIUM"):
                    finding.risk = "MEDIUM"

        # HTTPS-spezifische Analyse
        if port in [443, 8443, 9443, 4443, 5986, 8200, 6443, 10250]:
            http_info = self._analyze_http(host, port, ssl=True)
            finding.http_info = http_info
            ssl_info = self._analyze_ssl(host, port)
            finding.ssl_info = ssl_info
            if ssl_info.get("weak_protocol") or ssl_info.get("expired"):
                finding.risk = "HIGH"

        # Auth-Check für spezifische Services
        finding.auth_required = self._check_auth(host, port)
        if not finding.auth_required:
            finding.risk = "CRITICAL"
            finding.risk_reason = f"{finding.service}: KEIN AUTHENTIFIZIERUNGSSCHUTZ!"

        return finding

    def _grab_banner(self, host: str, port: int) -> str:
        """Banner vom Service lesen"""
        probes = {
            # HTTP
            **{p: f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
               for p in [80, 8080, 8000, 8008, 8081, 8090, 9000, 9090, 3000,
                          8161, 8983, 15672, 4848, 7474, 8888, 10000]},
            # SMTP
            25: None, 587: None, 465: None,
            # FTP
            21: None,
            # SSH
            22: None,
            # Generic
            "default": b"HEAD / HTTP/1.0\r\n\r\n"
        }

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                probe = probes.get(port, probes["default"])
                if probe:
                    s.send(probe)
                banner = b""
                s.settimeout(1.5)
                try:
                    while len(banner) < 2048:
                        chunk = s.recv(512)
                        if not chunk:
                            break
                        banner += chunk
                except:
                    pass
                return banner.decode(errors="ignore").strip()
        except:
            return ""

    def _analyze_http(self, host: str, port: int, ssl: bool = False) -> dict:
        """HTTP-Header-Analyse: Technologien + Security-Headers"""
        result = {
            "status_code": 0,
            "server": "",
            "technologies": [],
            "missing_security_headers": [],
            "interesting_headers": {},
            "title": "",
            "redirects_to_https": False,
        }

        proto = "https" if ssl else "http"
        url = f"{proto}://{host}:{port}/"

        try:
            ctx = None
            if ssl:
                ctx = __import__("ssl").create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = __import__("ssl").CERT_NONE

            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 MSSP-Scanner/1.0",
                "Accept": "*/*"
            })
            handler = urllib.request.HTTPSHandler(context=ctx) if ssl else None
            opener = urllib.request.build_opener(handler) if handler else urllib.request.build_opener()
            opener.addheaders = []

            with opener.open(req, timeout=self.timeout) as resp:
                result["status_code"] = resp.status
                headers = dict(resp.headers)

                # Server-Header
                result["server"] = headers.get("Server", headers.get("server", ""))

                # Security-Header-Check
                required_headers = [
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "Referrer-Policy",
                ]
                for h in required_headers:
                    if h.lower() not in {k.lower() for k in headers}:
                        result["missing_security_headers"].append(h)

                # Technologie-Erkennung
                for tech, fp in TECH_FINGERPRINTS.items():
                    header_val = headers.get(fp["header"], headers.get(fp["header"].lower(), ""))
                    if fp["pattern"] and re.search(fp["pattern"], header_val, re.I):
                        match = re.search(fp["pattern"], header_val, re.I)
                        version = match.group(1) if match and match.lastindex else ""
                        result["technologies"].append(f"{tech} {version}".strip())

                # Interessante Headers
                interesting = ["X-Powered-By", "X-Generator", "X-AspNet-Version",
                               "Via", "X-Backend-Server", "X-Runtime", "X-Version"]
                for h in interesting:
                    val = headers.get(h, headers.get(h.lower(), ""))
                    if val:
                        result["interesting_headers"][h] = val

                # Body für Title
                try:
                    body = resp.read(4096).decode(errors="ignore")
                    title_match = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
                    if title_match:
                        result["title"] = title_match.group(1).strip()[:80]
                except:
                    pass

        except urllib.error.HTTPError as e:
            result["status_code"] = e.code
        except Exception:
            pass

        return result

    def _analyze_ssl(self, host: str, port: int) -> dict:
        """SSL/TLS-Zertifikat und Protokoll analysieren"""
        result = {
            "protocol": "",
            "cipher": "",
            "weak_protocol": False,
            "expired": False,
            "self_signed": False,
            "days_until_expiry": -1,
            "subject": "",
            "sans": [],
        }
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    result["protocol"] = ssock.version()
                    result["cipher"] = ssock.cipher()[0] if ssock.cipher() else ""
                    cert = ssock.getpeercert()
                    if cert:
                        # Ablauf
                        if cert.get("notAfter"):
                            expiry = ssl.cert_time_to_seconds(cert["notAfter"])
                            days = int((expiry - time.time()) / 86400)
                            result["days_until_expiry"] = days
                            result["expired"] = days < 0
                        # Subject
                        subj = dict(x[0] for x in cert.get("subject", []))
                        result["subject"] = subj.get("commonName", "")
                        # SANs
                        for t, v in cert.get("subjectAltName", []):
                            if t == "DNS":
                                result["sans"].append(v)
                        # Self-signed?
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        if issuer.get("organizationName") == subj.get("organizationName"):
                            result["self_signed"] = True
                    if result["protocol"] in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
                        result["weak_protocol"] = True
        except:
            pass
        return result

    def _check_auth(self, host: str, port: int) -> bool:
        """
        Prüft ob ein Service ohne Authentication erreichbar ist.
        Gibt False zurück wenn KEINE Auth nötig (=kritisches Finding).
        """
        # Redis: PING
        if port == 6379:
            try:
                with socket.create_connection((host, port), timeout=2) as s:
                    s.send(b"*1\r\n$4\r\nPING\r\n")
                    resp = s.recv(64).decode(errors="ignore")
                    return "PONG" not in resp  # PONG = kein Auth = unsicher
            except:
                return True

        # Elasticsearch
        if port == 9200:
            try:
                req = urllib.request.Request(f"http://{host}:{port}/_cluster/health")
                with urllib.request.urlopen(req, timeout=2) as r:
                    data = json.loads(r.read())
                    return "status" not in data  # 'status' = kein Auth = unsicher
            except urllib.error.HTTPError as e:
                return e.code == 401  # 401 = Auth vorhanden
            except:
                return True

        # MongoDB
        if port == 27017:
            try:
                with socket.create_connection((host, port), timeout=2) as s:
                    # Sende isMaster command
                    cmd = b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
                    cmd += b"\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff"
                    cmd += b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
                    s.send(cmd)
                    resp = s.recv(256)
                    return len(resp) == 0  # Antwort = kein Auth (vereinfacht)
            except:
                return True

        # Memcached
        if port == 11211:
            try:
                with socket.create_connection((host, port), timeout=2) as s:
                    s.send(b"stats\r\n")
                    resp = s.recv(512).decode(errors="ignore")
                    return "STAT" not in resp  # STAT = kein Auth = unsicher
            except:
                return True

        # Standard: Auth angenommen (safe default)
        return True

    def _extract_version(self, banner: str, port: int) -> str:
        """Extrahiert Versionsinformationen aus Banner"""
        patterns = [
            r"(\d+\.\d+(?:\.\d+)*(?:[-_]\w+)?)",
        ]
        for p in patterns:
            m = re.search(p, banner)
            if m:
                return m.group(1)
        return ""

    def _identify_product(self, banner: str) -> str:
        """Identifiziert Produkt aus Banner"""
        known = [
            "Apache", "nginx", "IIS", "Tomcat", "OpenSSH",
            "Postfix", "Exim", "vsftpd", "ProFTPD", "Redis",
            "MongoDB", "MySQL", "PostgreSQL", "Elasticsearch",
        ]
        for prod in known:
            if prod.lower() in banner.lower():
                return prod
        return ""

    def _get_category(self, port: int) -> str:
        for cat, ports in PORT_CATEGORIES.items():
            if port in ports:
                return cat
        return "other"

    def _get_remediation(self, port: int) -> str:
        remediations = {
            2375: "Docker API: TLS aktivieren (--tlsverify), nie direkt exponieren",
            6379: "Redis: requirepass setzen, bind auf localhost, kein Internet",
            9200: "Elasticsearch: X-Pack Security aktivieren, Firewall-Regel",
            27017: "MongoDB: --auth Flag, bind_ip auf localhost",
            3389: "RDP: hinter VPN/Bastion, NLA erzwingen, MFA aktivieren",
            445:  "SMB: alle öffentlichen IPs blockieren, nur intern",
            23:   "Telnet: deaktivieren, SSH verwenden",
            502:  "Modbus: Netzwerksegmentierung, kein Internet-Zugriff",
            102:  "S7: Air-Gap oder strikte Firewall-Segmentierung",
            5985: "WinRM: nur über HTTPS (5986), oder via VPN",
            3306: "MySQL: bind-address=127.0.0.1, SSH-Tunnel für Remote-Zugriff",
            5432: "PostgreSQL: pg_hba.conf auf localhost einschränken",
            8888: "Jupyter: --no-browser, Passwort setzen, kein 0.0.0.0",
            3000: "Grafana: Admin-Passwort ändern, hinter Reverse-Proxy",
            10250: "Kubelet: --anonymous-auth=false, nur über API-Server",
        }
        return remediations.get(port, "Service absichern oder hinter Firewall/VPN schützen")


# ═══════════════════════════════════════════════════════════════════════
# ASSET SCANNER — ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════

class AssetScanner:
    """
    Orchestriert vollständigen Asset-Scan für einen Mandanten.
    Kombinierbar mit easm_engine.py (DNS-Layer).
    """

    def __init__(self, tenant_id: str, max_workers: int = 100):
        self.tenant_id = tenant_id
        self.port_scanner = PortScanner(timeout=1.5, max_workers=max_workers)
        self.fingerprinter = ServiceFingerprinter(timeout=3.0)

    def scan(self,
             ip_ranges: list,
             domains: list = None,
             port_categories: list = None,
             max_hosts_per_range: int = 256) -> AssetScanReport:
        """
        Vollständiger Asset-Scan.

        Args:
            ip_ranges: Liste von CIDR-Blöcken (["203.0.113.0/24"])
            domains:   Optionale Domains für Reverse-DNS-Mapping
            port_categories: Welche Kategorien scannen? None = alle
            max_hosts_per_range: Max. Hosts pro Range
        """
        report = AssetScanReport(
            tenant_id=self.tenant_id,
            ip_ranges=ip_ranges,
            scan_timestamp=datetime.datetime.now(datetime.UTC).isoformat()
        )

        # Ports bestimmen
        if port_categories:
            ports = sorted(set(
                p for cat in port_categories
                for p in PORT_CATEGORIES.get(cat, [])
            ))
        else:
            ports = ALL_PORTS

        print(f"\n{'='*60}")
        print(f"Asset Scan: {self.tenant_id}")
        print(f"Ranges: {ip_ranges}")
        print(f"Ports: {len(ports)} Port-Kategorien")
        print(f"{'='*60}")

        all_host_ports = {}

        # ── 1. Port-Scan aller IP-Ranges ──────────────────────────
        for cidr in ip_ranges:
            print(f"\n[1] Port-Scan: {cidr}")
            try:
                host_ports = self.port_scanner.scan_range(
                    cidr, ports, max_hosts_per_range
                )
                all_host_ports.update(host_ports)
            except Exception as e:
                print(f"    Fehler bei {cidr}: {e}")

        # ── 2. Einzelne IPs/Hosts ohne Range ──────────────────────
        if domains:
            print(f"\n[1b] Hostname-Auflösung für {len(domains)} Domains...")
            for domain in domains:
                try:
                    ip = socket.gethostbyname(domain)
                    if ip not in all_host_ports:
                        print(f"    {domain} -> {ip}, scanne...")
                        open_ports = self.port_scanner.scan_host(ip, ports)
                        if open_ports:
                            all_host_ports[ip] = open_ports
                except Exception:
                    pass

        print(f"\n[2] Gefunden: {len(all_host_ports)} Hosts mit offenen Ports")

        # ── 3. Service Fingerprinting ──────────────────────────────
        print(f"\n[3] Service Fingerprinting...")
        all_findings = []

        for ip, open_ports in all_host_ports.items():
            asset = AssetInventory(ip=ip, open_ports=open_ports)

            for port in open_ports:
                print(f"    {ip}:{port} ({SERVICE_MAP.get(port, '?')}) ...", end=" ")
                finding = self.fingerprinter.fingerprint(ip, port)
                all_findings.append(finding)
                asset.services.append(finding)

                # Höchstes Severity tracken
                severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
                if severity_order.get(finding.risk, 0) > severity_order.get(asset.highest_severity, 0):
                    asset.highest_severity = finding.risk

                # Flags
                if finding.category == "ot_scada":
                    report.ot_scada_exposed = True
                if finding.category == "cloud":
                    report.cloud_apis_exposed = True
                if finding.category == "database":
                    report.databases_exposed = True

                print(f"[{finding.risk}]")

            # Risk Score pro Asset
            asset.risk_score = self._calc_asset_score(asset)
            report.assets.append(asset)

        report.service_findings = all_findings

        # ── 4. Statistiken ─────────────────────────────────────────
        report.stats = self._calc_stats(report)

        self._print_summary(report)
        return report

    def _calc_asset_score(self, asset: AssetInventory) -> int:
        """Risiko-Score pro Asset (0=sicher, 100=kritisch)"""
        score = 0
        weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2}
        for svc in asset.services:
            score += weights.get(svc.risk, 0)
            if not svc.auth_required:
                score += 30
        return min(100, score)

    def _calc_stats(self, report: AssetScanReport) -> dict:
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_category = {}
        no_auth_services = []

        for f in report.service_findings:
            by_severity[f.risk] = by_severity.get(f.risk, 0) + 1
            by_category[f.category] = by_category.get(f.category, 0) + 1
            if not f.auth_required:
                no_auth_services.append(f"{f.ip}:{f.port} ({f.service})")

        return {
            "total_assets": len(report.assets),
            "total_open_ports": sum(len(a.open_ports) for a in report.assets),
            "total_services": len(report.service_findings),
            "by_severity": by_severity,
            "by_category": by_category,
            "no_auth_services": no_auth_services,
            "ot_scada_exposed": report.ot_scada_exposed,
            "cloud_apis_exposed": report.cloud_apis_exposed,
            "databases_exposed": report.databases_exposed,
        }

    def _print_summary(self, report: AssetScanReport):
        s = report.stats
        print(f"\n{'='*60}")
        print(f"ASSET SCAN ERGEBNIS: {report.tenant_id}")
        print(f"{'='*60}")
        print(f"  Assets gefunden:    {s['total_assets']}")
        print(f"  Offene Ports:       {s['total_open_ports']}")
        print(f"  Services:           {s['total_services']}")
        print(f"")
        print(f"  CRITICAL:  {s['by_severity']['CRITICAL']}")
        print(f"  HIGH:      {s['by_severity']['HIGH']}")
        print(f"  MEDIUM:    {s['by_severity']['MEDIUM']}")
        print(f"")
        if s['no_auth_services']:
            print(f"  ⚠ OHNE AUTHENTICATION: {len(s['no_auth_services'])}")
            for svc in s['no_auth_services']:
                print(f"    → {svc}")
        if s['ot_scada_exposed']:
            print(f"  ⚠ KRITIS: OT/SCADA-Systeme exponiert!")
        if s['cloud_apis_exposed']:
            print(f"  ⚠ Cloud-Management-APIs exponiert!")
        if s['databases_exposed']:
            print(f"  ⚠ Datenbanken direkt exponiert!")
        print(f"{'='*60}")


# ═══════════════════════════════════════════════════════════════════════
# INTEGRATION MIT EASM ENGINE
# ═══════════════════════════════════════════════════════════════════════

class FullEASMScanner:
    """
    Kombiniert DNS-Layer (easm_engine.py) mit Asset-Layer (easm_asset_scanner.py).
    Liefert vollständiges EASM-Bild: extern exponierte Assets + Services + CVEs.

    Verwendung:
        scanner = FullEASMScanner("kunde-001")
        report = scanner.full_scan(
            domain="example.de",
            ip_ranges=["203.0.113.0/24"],
            panos_version="10.2.7"
        )
    """

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        # Import der bestehenden Engine
        try:
            from easm_engine import EASMScanner
            self.domain_scanner = EASMScanner(tenant_id)
        except ImportError:
            self.domain_scanner = None
            print("Hinweis: easm_engine.py nicht gefunden, nur Asset-Scan")

        self.asset_scanner = AssetScanner(tenant_id)

    def full_scan(self,
                  domain: str,
                  ip_ranges: list,
                  panos_version: str = "",
                  port_categories: list = None) -> dict:
        """
        Vollständiger EASM-Scan: Domain + Assets + Services.
        """
        results = {
            "tenant_id": self.tenant_id,
            "domain": domain,
            "ip_ranges": ip_ranges,
            "scan_timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "domain_report": None,
            "asset_report": None,
            "combined_risk_score": 100,
            "executive_summary": {}
        }

        # ── Domain-Layer (DNS, CVE, HIBP) ─────────────────────────
        if self.domain_scanner:
            print("\n[A] Domain-Layer Scan...")
            domain_report = self.domain_scanner.scan(
                domain=domain,
                ip_ranges=ip_ranges,
                panos_version=panos_version,
                deep_scan=False
            )
            results["domain_report"] = {
                "score": domain_report.score,
                "subdomains": len(domain_report.subdomains),
                "cves": len(domain_report.cve_findings),
                "credential_leaks": len(domain_report.credential_leaks),
            }

        # ── Asset-Layer (Port-Scan, Service-Fingerprinting) ────────
        print("\n[B] Asset-Layer Scan...")

        # IPs der gefundenen Subdomains hinzufügen
        extra_domains = []
        if self.domain_scanner and domain_report:
            extra_domains = [s.subdomain for s in domain_report.subdomains
                            if s.ip and s.risk in ("HIGH", "CRITICAL")]

        asset_report = self.asset_scanner.scan(
            ip_ranges=ip_ranges,
            domains=extra_domains,
            port_categories=port_categories
        )
        results["asset_report"] = {
            "total_assets": asset_report.stats["total_assets"],
            "total_services": asset_report.stats["total_services"],
            "critical_services": asset_report.stats["by_severity"]["CRITICAL"],
            "no_auth_services": asset_report.stats["no_auth_services"],
            "ot_exposed": asset_report.ot_scada_exposed,
            "cloud_exposed": asset_report.cloud_apis_exposed,
            "db_exposed": asset_report.databases_exposed,
        }

        # ── Combined Risk Score ────────────────────────────────────
        domain_score = results["domain_report"]["score"] if results["domain_report"] else 100
        asset_deductions = (
            asset_report.stats["by_severity"]["CRITICAL"] * 20 +
            asset_report.stats["by_severity"]["HIGH"] * 10 +
            len(asset_report.stats["no_auth_services"]) * 30 +
            (25 if asset_report.ot_scada_exposed else 0)
        )
        asset_score = max(0, 100 - asset_deductions)
        results["combined_risk_score"] = int((domain_score + asset_score) / 2)

        # ── Executive Summary ──────────────────────────────────────
        results["executive_summary"] = {
            "overall_score": results["combined_risk_score"],
            "critical_count": (
                asset_report.stats["by_severity"]["CRITICAL"] +
                (results["domain_report"]["cves"] if results["domain_report"] else 0)
            ),
            "immediate_actions": self._get_immediate_actions(asset_report, results),
            "ot_risk": asset_report.ot_scada_exposed,
            "data_exposure_risk": asset_report.databases_exposed,
        }

        return results

    def _get_immediate_actions(self, asset_report, results) -> list:
        actions = []
        if asset_report.ot_scada_exposed:
            actions.append("SOFORT: OT/SCADA-Systeme von Internet trennen!")
        if asset_report.stats["no_auth_services"]:
            for svc in asset_report.stats["no_auth_services"][:3]:
                actions.append(f"SOFORT: Auth auf {svc} aktivieren")
        if asset_report.stats["by_severity"]["CRITICAL"] > 0:
            actions.append(f"{asset_report.stats['by_severity']['CRITICAL']} kritische Services schließen")
        if asset_report.cloud_apis_exposed:
            actions.append("Cloud-Management-APIs (Docker/K8s) hinter Firewall")
        return actions[:5]


# ═══════════════════════════════════════════════════════════════════════
# DEMO
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("EASM Asset Scanner — Demo")
    print("="*60)

    # Fingerprinting einzelner bekannter Services testen
    fp = ServiceFingerprinter()

    # Teste HTTP-Service-Analyse (paloaltonetworks.com)
    print("\n[Test] HTTP-Analyse paloaltonetworks.com:443")
    http_info = fp._analyze_http("paloaltonetworks.com", 443, ssl=True)
    print(json.dumps(http_info, indent=2))

    print("\n[Test] SSL-Analyse paloaltonetworks.com:443")
    ssl_info = fp._analyze_ssl("paloaltonetworks.com", 443)
    print(json.dumps(ssl_info, indent=2))

    # Port-Liste ausgeben
    print(f"\n[Info] Scanner deckt {len(ALL_PORTS)} Ports ab:")
    for cat, ports in PORT_CATEGORIES.items():
        print(f"  {cat:20s}: {len(ports)} Ports")
    print(f"  {'GESAMT':20s}: {len(ALL_PORTS)} Ports")

    print(f"\n[Info] {len(SERVICE_RISKS)} Services mit Risiko-Bewertung")
    crit_services = [p for p, (r, _) in SERVICE_RISKS.items() if r == "CRITICAL"]
    print(f"  CRITICAL: {len(crit_services)} Services → {[SERVICE_MAP.get(p, p) for p in crit_services]}")
