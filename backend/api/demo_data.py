"""
demo_data.py
Full demo dataset — identical to easm_fullhunt_ui.jsx constants.
All field names match the canonical API schema.
"""
from datetime import datetime, timezone, timedelta

NOW = datetime.now(timezone.utc)

def days_ago(n): return (NOW - timedelta(days=n)).isoformat()

DEMO_TENANT = {
    "id": "t-mueller",
    "name": "Müller GmbH",
    "slug": "mueller-gmbh",
    "active": True,
    "score": 48,
    "grade": "D",
    "assets": {"subdomains": 26, "ips": 18, "ports": 47, "services": 31},
    "findings_summary": {"CRITICAL": 5, "HIGH": 10, "MEDIUM": 14, "LOW": 4, "INFO": 2},
    "last_scan": days_ago(3),
    "next_scan": (NOW + timedelta(days=1)).isoformat(),
    "tool_stats": {
        "subfinder":    {"subdomains": 23, "findings": 4,  "duration": 18},
        "naabu":        {"ports": 47,      "findings": 6,  "duration": 28},
        "theharvester": {"emails": 31,     "findings": 2,  "duration": 22},
        "httpx":        {"urls": 19,       "findings": 8,  "duration": 34},
        "nuclei":       {"templates": 7,   "findings": 11, "duration": 67},
        "ramparts":     {"mcp": 1,         "findings": 3,  "duration": 12},
    },
    "pipeline_stats": {
        "subdomains_found": 23,
        "emails_harvested": 31,
        "open_ports": 47,
        "mcp_servers": 1,
        "duration_seconds": 202,
    },
}

DEMO_FINDINGS = [
    {"id":"F001","sev":"CRITICAL","cat":"CVE","tool":"nuclei",
     "cve":"CVE-2024-3400","cvss":10.0,"epss":"0.974","kev":True,
     "title":"CVE-2024-3400 — GlobalProtect RCE","asset":"vpn.mueller-gmbh.de:443",
     "status":"open","ticket_ref":None,"age":1,
     "desc":"Unauthenticated command injection in PAN-OS GlobalProtect. Full RCE without credentials. Actively exploited in the wild.",
     "fix":"Upgrade PAN-OS to >=11.1.2-h3. Disable GlobalProtect telemetry as interim mitigation.",
     "first_seen":days_ago(1)},
    {"id":"F002","sev":"CRITICAL","cat":"MCP","tool":"ramparts",
     "cve":None,"cvss":9.8,"epss":None,"kev":False,
     "title":"MCP-Server ohne Auth — RCE möglich","asset":"203.0.113.55:8080/mcp",
     "status":"open","ticket_ref":None,"age":1,
     "desc":"MCP server accepts initialize without Bearer token. tools/list exposes: execute_command, read_file, write_file, shell.",
     "fix":"Enable Bearer-token authentication. Never bind MCP to 0.0.0.0. Remove DANGEROUSLY_OMIT_AUTH=true.",
     "first_seen":days_ago(1)},
    {"id":"F003","sev":"CRITICAL","cat":"Exposure","tool":"nuclei",
     "cve":None,"cvss":9.1,"epss":"0.812","kev":False,
     "title":".env-Datei im Webroot erreichbar","asset":"staging.mueller-gmbh.de/.env",
     "status":"open","ticket_ref":None,"age":3,
     "desc":"APP_KEY, DB_PASSWORD, REDIS_PASSWORD and AWS_SECRET_ACCESS_KEY exposed in plaintext .env file.",
     "fix":"Remove .env from webroot. Deny access in nginx/Apache. Rotate all exposed credentials immediately.",
     "first_seen":days_ago(3)},
    {"id":"F004","sev":"CRITICAL","cat":"CVE","tool":"nuclei",
     "cve":"CVE-2025-49596","cvss":9.4,"epss":"0.891","kev":False,
     "title":"CVE-2025-49596 — MCP Inspector RCE","asset":"203.0.113.55:6274",
     "status":"open","ticket_ref":None,"age":1,
     "desc":"MCP Inspector running in production on port 6274/6277. DNS rebinding attack allows any website to inject tool calls into connected AI agents.",
     "fix":"Stop MCP Inspector immediately. Block ports 6274/6277 via firewall. Inspector is dev-only.",
     "first_seen":days_ago(1)},
    {"id":"F005","sev":"CRITICAL","cat":"Exposure","tool":"httpx",
     "cve":None,"cvss":8.9,"epss":"0.743","kev":False,
     "title":"Spring Boot Actuator /env exponiert","asset":"api.mueller-gmbh.de/actuator/env",
     "status":"open","ticket_ref":None,"age":5,
     "desc":"Spring Boot Actuator /actuator/env responds with all environment variables including DB_PASSWORD, JWT_SECRET, STRIPE_API_KEY.",
     "fix":"Set management.endpoints.web.exposure.include=health,info. Add Spring Security to /actuator/*.",
     "first_seen":days_ago(5)},
    {"id":"F006","sev":"HIGH","cat":"Subdomain","tool":"subfinder",
     "cve":None,"cvss":8.1,"epss":None,"kev":False,
     "title":"Subdomain Takeover — CNAME verwaist","asset":"dev.mueller-gmbh.de",
     "status":"open","ticket_ref":None,"age":1,
     "desc":"CNAME points to herokudns.com (Heroku app no longer exists). Subdomain takeover possible.",
     "fix":"Remove CNAME record or re-create Heroku app. Run DNS cleanup quarterly.",
     "first_seen":days_ago(1)},
    {"id":"F007","sev":"HIGH","cat":"Port","tool":"naabu",
     "cve":None,"cvss":8.1,"epss":"0.612","kev":False,
     "title":"RDP Port 3389 direkt erreichbar","asset":"203.0.113.46:3389",
     "status":"open","ticket_ref":None,"age":8,
     "desc":"RDP exposed directly to internet. Primary entry point for ransomware.",
     "fix":"Restrict RDP to VPN-only. Enable NLA. Use GlobalProtect as RDP gateway.",
     "first_seen":days_ago(8)},
    {"id":"F008","sev":"HIGH","cat":"MCP","tool":"ramparts",
     "cve":None,"cvss":8.0,"epss":None,"kev":False,
     "title":"MCP Shell-Tools ohne Auth exponiert","asset":"203.0.113.55:8080",
     "status":"open","ticket_ref":None,"age":1,
     "desc":"MCP server exposes execute_command, shell, run_script tools without authentication.",
     "fix":"Restrict dangerous tools. Add authentication. Run MCP server with minimal OS privileges.",
     "first_seen":days_ago(1)},
    {"id":"F009","sev":"HIGH","cat":"Credential","tool":"theharvester",
     "cve":None,"cvss":7.5,"epss":None,"kev":False,
     "title":"31 E-Mails in OSINT — 8 in Breach-DBs","asset":"mueller-gmbh.de",
     "status":"open","ticket_ref":None,"age":2,
     "desc":"31 @mueller-gmbh.de email addresses found in public OSINT. HIBP: 8 accounts compromised.",
     "fix":"Force password reset for affected accounts. Enable MFA. Deploy phishing simulation.",
     "first_seen":days_ago(2)},
    {"id":"F010","sev":"MEDIUM","cat":"HTTP","tool":"httpx",
     "cve":None,"cvss":6.5,"epss":"0.234","kev":False,
     "title":"CORS Origin-Reflection auf /api/","asset":"api.mueller-gmbh.de/api/",
     "status":"open","ticket_ref":"INC-2040","age":3,
     "desc":"Server reflects arbitrary Origin header in Access-Control-Allow-Origin.",
     "fix":"Whitelist allowed origins explicitly. Never reflect arbitrary Origin headers.",
     "first_seen":days_ago(3)},
    {"id":"F011","sev":"LOW","cat":"TLS","tool":"httpx",
     "cve":None,"cvss":0.0,"epss":None,"kev":False,
     "title":"SSL-Zertifikat läuft in 8 Tagen ab","asset":"mail.mueller-gmbh.de:443",
     "status":"open","ticket_ref":None,"age":1,
     "desc":"TLS certificate expires 2026-05-14. Browser warnings imminent.",
     "fix":"Renew certificate. Configure auto-renewal via Let's Encrypt certbot.",
     "first_seen":days_ago(1)},
]

DEMO_ASSETS = [
    {"id":"A001","fqdn":"vpn.mueller-gmbh.de","ip":"203.0.113.45","org":"Hetzner Online GmbH","asn":24940,"ports":[443,1194],"risk":"CRITICAL","sources":["subfinder","cert"],"first_seen":days_ago(1)},
    {"id":"A002","fqdn":"admin.mueller-gmbh.de","ip":"203.0.113.46","org":"Hetzner Online GmbH","asn":24940,"ports":[443,8080],"risk":"CRITICAL","sources":["subfinder"],"first_seen":days_ago(1)},
    {"id":"A003","fqdn":"staging.mueller-gmbh.de","ip":"203.0.113.48","org":"Hetzner Online GmbH","asn":24940,"ports":[80,443],"risk":"CRITICAL","sources":["subfinder","dns"],"first_seen":days_ago(1)},
    {"id":"A004","fqdn":"jenkins.mueller-gmbh.de","ip":"203.0.113.55","org":"Hetzner Online GmbH","asn":24940,"ports":[8080,6274,6277],"risk":"HIGH","sources":["subfinder"],"first_seen":days_ago(1)},
    {"id":"A005","fqdn":"dev.mueller-gmbh.de","ip":None,"org":"Heroku","asn":None,"ports":[],"risk":"HIGH","sources":["subfinder"],"takeover":True,"first_seen":days_ago(1)},
    {"id":"A006","fqdn":"remote.mueller-gmbh.de","ip":"203.0.113.47","org":"Hetzner Online GmbH","asn":24940,"ports":[443,3389],"risk":"HIGH","sources":["subfinder","dns"],"first_seen":days_ago(1)},
    {"id":"A007","fqdn":"www.mueller-gmbh.de","ip":"203.0.113.5","org":"Hetzner Online GmbH","asn":24940,"ports":[80,443],"risk":"LOW","sources":["dns","cert"],"first_seen":days_ago(10)},
    {"id":"A008","fqdn":"mail.mueller-gmbh.de","ip":"203.0.113.10","org":"Hetzner Online GmbH","asn":24940,"ports":[25,443,587],"risk":"LOW","sources":["dns","mx"],"first_seen":days_ago(10)},
    {"id":"A009","fqdn":"api.mueller-gmbh.de","ip":"203.0.113.7","org":"Hetzner Online GmbH","asn":24940,"ports":[443],"risk":"MEDIUM","sources":["subfinder","cert"],"first_seen":days_ago(5)},
    {"id":"A010","fqdn":"cdn.mueller-gmbh.de","ip":"104.21.44.8","org":"Cloudflare","asn":13335,"ports":[80,443],"risk":"LOW","sources":["dns"],"first_seen":days_ago(10)},
]

DEMO_MCP_SERVERS = [
    {"id":"MCP001","url":"http://203.0.113.55:8080/mcp","port":8080,"auth":False,
     "tools":["execute_command","read_file","write_file","list_directory","shell"],
     "server":"FastMCP v1.2.0","cve":"CVE-2025-49596","risk":"CRITICAL",
     "injection":True,"inspection_active":True},
    {"id":"MCP002","url":"http://203.0.113.55:6274","port":6274,"auth":False,
     "tools":["inspector_proxy"],
     "server":"@modelcontextprotocol/inspector@0.6.0","cve":"CVE-2025-49596","risk":"CRITICAL",
     "injection":False,"inspection_active":True},
]

DEMO_INTEL = {
    "hosting_orgs": [
        {"name":"Hetzner Online GmbH","asn":24940,"count":10,"pct":38.5,"color":"#3b82f6"},
        {"name":"Cloudflare, Inc.",   "asn":13335,"count":4, "pct":15.4,"color":"#f97316"},
        {"name":"Amazon AWS",         "asn":16509,"count":4, "pct":15.4,"color":"#f59e0b"},
        {"name":"Salesforce.com",     "asn":14340,"count":3, "pct":11.5,"color":"#8b5cf6"},
        {"name":"Google LLC",         "asn":15169,"count":2, "pct":7.7, "color":"#10b981"},
        {"name":"STRATO AG",          "asn":6724, "count":1, "pct":3.8, "color":"#ec4899"},
        {"name":"Deutsche Telekom",   "asn":3320, "count":2, "pct":7.7, "color":"#6366f1"},
    ],
    "geo_assets": [
        {"city":"Frankfurt","country":"DE","ip_count":10,"risk":"CRITICAL","lat":50.11,"lng":8.68},
        {"city":"Berlin",   "country":"DE","ip_count":4, "risk":"HIGH",    "lat":52.52,"lng":13.40},
        {"city":"Düsseldorf","country":"DE","ip_count":3,"risk":"HIGH",    "lat":51.23,"lng":6.78},
        {"city":"Ashburn",  "country":"US","ip_count":4, "risk":"LOW",     "lat":39.02,"lng":-77.54},
        {"city":"San Jose", "country":"US","ip_count":2, "risk":"LOW",     "lat":37.34,"lng":-121.9},
        {"city":"Amsterdam","country":"NL","ip_count":3, "risk":"MEDIUM",  "lat":52.37,"lng":4.89},
    ],
    "fqdn_table": [
        {"fqdn":"vpn.mueller-gmbh.de",     "ip":"203.0.113.45","netblock":"203.0.113.0/24","asn":"AS24940","org":"Hetzner Online GmbH","risk":"CRITICAL"},
        {"fqdn":"admin.mueller-gmbh.de",   "ip":"203.0.113.46","netblock":"203.0.113.0/24","asn":"AS24940","org":"Hetzner Online GmbH","risk":"CRITICAL"},
        {"fqdn":"staging.mueller-gmbh.de", "ip":"203.0.113.48","netblock":"203.0.113.0/24","asn":"AS24940","org":"Hetzner Online GmbH","risk":"CRITICAL"},
        {"fqdn":"jenkins.mueller-gmbh.de", "ip":"203.0.113.55","netblock":"203.0.113.0/24","asn":"AS24940","org":"Hetzner Online GmbH","risk":"HIGH"},
        {"fqdn":"dev.mueller-gmbh.de",     "ip":"—",           "netblock":"—",             "asn":"—",     "org":"Heroku","risk":"HIGH"},
        {"fqdn":"remote.mueller-gmbh.de",  "ip":"203.0.113.47","netblock":"203.0.113.0/24","asn":"AS24940","org":"Hetzner Online GmbH","risk":"HIGH"},
        {"fqdn":"www.mueller-gmbh.de",     "ip":"203.0.113.5", "netblock":"203.0.113.0/24","asn":"AS24940","org":"Hetzner Online GmbH","risk":"LOW"},
        {"fqdn":"mail.mueller-gmbh.de",    "ip":"203.0.113.10","netblock":"203.0.113.0/24","asn":"AS24940","org":"Hetzner Online GmbH","risk":"LOW"},
        {"fqdn":"api.mueller-gmbh.de",     "ip":"203.0.113.7", "netblock":"203.0.113.0/24","asn":"AS24940","org":"Hetzner Online GmbH","risk":"MEDIUM"},
        {"fqdn":"cdn.mueller-gmbh.de",     "ip":"104.21.44.8", "netblock":"104.21.0.0/16", "asn":"AS13335","org":"Cloudflare","risk":"LOW"},
    ],
}

DEMO_SCAN_JOBS = [
    {"id":"S001","domain":"mueller-gmbh.de","scan_type":"full","status":"completed",
     "progress_pct":100,"findings_count":35,"risk_score":48,
     "started_at":days_ago(3),"finished_at":days_ago(3),
     "duration_seconds":202,"phases_completed":["discovery","port_scan","http_probe","vuln_scan","mcp_scan"]},
    {"id":"S002","domain":"mueller-gmbh.de","scan_type":"full","status":"completed",
     "progress_pct":100,"findings_count":31,"risk_score":52,
     "started_at":days_ago(4),"finished_at":days_ago(4),
     "duration_seconds":198,"phases_completed":["discovery","port_scan","http_probe","vuln_scan","mcp_scan"]},
    {"id":"S003","domain":"mueller-gmbh.de","scan_type":"mcp_only","status":"completed",
     "progress_pct":100,"findings_count":3,"risk_score":None,
     "started_at":days_ago(5),"finished_at":days_ago(5),
     "duration_seconds":34,"phases_completed":["mcp_scan"]},
]

DEMO_USERS = {
    "admin": {
        "id": "u-admin",
        "email": "admin@mueller-gmbh.de",
        "role": "admin",
        "tenant_id": "t-mueller",
        "password": "admin123",  # demo only
    }
}
