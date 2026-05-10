import { useState, useEffect, useRef, useCallback, createContext, useContext } from "react";

// ─── API CONFIGURATION ────────────────────────────────────────────────────────
const API_BASE = "/api/v1";
const TENANT_ID = "t-mueller";
const getToken   = ()  => localStorage.getItem("easm_token") || "";
const saveToken  = tok => localStorage.setItem("easm_token", tok);
const clearToken = ()  => localStorage.removeItem("easm_token");

async function apiFetch(path, opts = {}) {
  const token = getToken();
  const res = await fetch(API_BASE + path, {
    ...opts,
    headers: { "Content-Type":"application/json", ...(token?{Authorization:`Bearer ${token}`}:{}), ...(opts.headers||{}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401) { clearToken(); window.location.reload(); return; }
  if (!res.ok) { const e = await res.json().catch(()=>({detail:res.statusText})); throw new Error(e.detail||`HTTP ${res.status}`); }
  return res.json();
}

const AppCtx = createContext(null);
function useApp() { return useContext(AppCtx); }


const T = {
  // Backgrounds — dark navy scale
  bg0:    "#050810",   // void / page base
  bg1:    "#080c18",   // app shell
  bg2:    "#0d1221",   // card surface
  bg3:    "#121929",   // elevated / panel header
  bg4:    "#172131",   // hover state
  bg5:    "#1d2a3d",   // selected / active state

  // Borders
  border:      "#1e2d45",
  border2:     "#253554",
  borderFocus: "#22c55e",

  // Primary accent — green (theHarvester green)
  accent:   "#22c55e",
  accent2:  "#16a34a",
  accent3:  "#0f3d20",
  accentFg: "#dcfce7",

  // Severity — each has 3 tokens: color / bg / border
  critical:       "#f43f5e",
  criticalBg:     "#1c0810",
  criticalBorder: "#7f1d1d",
  high:           "#f97316",
  highBg:         "#1c0e00",
  highBorder:     "#7c2d12",
  medium:         "#eab308",
  mediumBg:       "#1a1400",
  mediumBorder:   "#713f12",
  low:            "#60a5fa",
  lowBg:          "#00111e",
  lowBorder:      "#1e3a5f",
  info:           "#94a3b8",
  infoBg:         "#0d1221",
  infoBorder:     "#1e2d45",

  // Tool palette (used only in charts & badges)
  toolSubfinder:    "#22c55e",
  toolNaabu:        "#eab308",
  toolTheharvester: "#60a5fa",
  toolHttpx:        "#a78bfa",
  toolNuclei:       "#f43f5e",
  toolRamparts:     "#f97316",

  // Text hierarchy
  text0:  "#f1f5f9",   // headings / values
  text1:  "#94a3b8",   // body / labels
  text2:  "#475569",   // muted / secondary
  text3:  "#273548",   // disabled / decorative

  // Typography
  font:     "'JetBrains Mono', 'Fira Code', monospace",
  fontSans: "'IBM Plex Sans', system-ui, sans-serif",
  // Aliases matching old token names (inline hex — no self-reference)
  cyan:   "#22c55e",
  green:  "#22c55e",
  red:    "#f43f5e",
  orange: "#f97316",
  yellow: "#eab308",
  blue:   "#60a5fa",

};


const SEV = {
  CRITICAL: { color: T.critical, bg: T.criticalBg, border: T.criticalBorder },
  HIGH:     { color: T.high,     bg: T.highBg,     border: T.highBorder     },
  MEDIUM:   { color: T.medium,   bg: T.mediumBg,   border: T.mediumBorder   },
  LOW:      { color: T.low,      bg: T.lowBg,      border: T.lowBorder      },
  INFO:     { color: T.info,     bg: T.infoBg,     border: T.infoBorder     },
};

// Tool color map
const TOOL_COLOR = {
  subfinder:    T.toolSubfinder,
  naabu:        T.toolNaabu,
  theharvester: T.toolTheharvester,
  httpx:        T.toolHttpx,
  nuclei:       T.toolNuclei,
  ramparts:     T.toolRamparts,
};


// ─── DEMO DATA ────────────────────────────────────────────────────────────────
const TENANT = {
  domain: "mueller-gmbh.de",
  score: 48,
  grade: "D",
  active: true,
  last_scan: "2026-05-05T08:03:22Z",
  next_scan: "2026-05-06T08:00:00Z",
  assets: { subdomains: 26, ips: 18, ports: 47, services: 31 },
  findings: { CRITICAL: 5, HIGH: 10, MEDIUM: 14, LOW: 4, INFO: 2 },
  tool_stats: {
    subfinder:    { subdomains: 23, findings: 4,  duration: 18 },
    naabu:        { ports: 47,      findings: 6,  duration: 28 },
    theharvester: { emails: 31,     findings: 2,  duration: 22 },
    httpx:        { urls: 19,       findings: 8,  duration: 34 },
    nuclei:       { templates: 7,   findings: 11, duration: 67 },
    ramparts:     { mcp: 1,         findings: 3,  duration: 12 },
  },
};

const FINDINGS = [
  { id:"f01", sev:"CRITICAL", cat:"CVE",         tool:"nuclei",
    title:"CVE-2024-3400 — GlobalProtect RCE", asset:"vpn.mueller-gmbh.de:443",
    cvss:10.0, kev:true,  epss:"0.974", age:1,  status:"open",
    desc:"Unauthenticated command injection in PAN-OS GlobalProtect. Full RCE without credentials. Actively exploited in the wild.",
    fix:"Upgrade PAN-OS to ≥11.1.2-h3 / ≥10.2.9-h1 immediately. Disable GlobalProtect telemetry as interim mitigation.",
    cve:"CVE-2024-3400" },
  { id:"f02", sev:"CRITICAL", cat:"MCP",         tool:"ramparts",
    title:"MCP-Server ohne Auth — RCE möglich", asset:"203.0.113.55:8080/mcp",
    cvss:9.8,  kev:false, epss:"—",     age:1,  status:"open",
    desc:"MCP server responds to initialize requests without Bearer token. tools/list exposes: execute_command, read_file, write_file. Full RCE via tools/call.",
    fix:"Enable Bearer-token authentication. Never bind MCP to 0.0.0.0. Remove DANGEROUSLY_OMIT_AUTH=true." },
  { id:"f03", sev:"CRITICAL", cat:"Exposure",    tool:"nuclei",
    title:".env-Datei im Webroot erreichbar",   asset:"staging.mueller-gmbh.de/.env",
    cvss:9.1,  kev:false, epss:"0.812", age:3,  status:"open",
    desc:"APP_KEY, DB_PASSWORD, REDIS_PASSWORD and AWS_SECRET_ACCESS_KEY exposed in plaintext .env file.",
    fix:"Remove .env from webroot. Deny access in nginx/Apache. Rotate all exposed credentials immediately." },
  { id:"f04", sev:"CRITICAL", cat:"CVE",         tool:"nuclei",
    title:"CVE-2025-49596 — MCP Inspector RCE", asset:"203.0.113.55:6274",
    cvss:9.4,  kev:false, epss:"0.891", age:1,  status:"open",
    cve:"CVE-2025-49596",
    desc:"MCP Inspector running in production on port 6274/6277. DNS rebinding attack allows any website to inject tool calls into connected AI agents.",
    fix:"Stop MCP Inspector immediately. Block ports 6274/6277 via firewall. Inspector is dev-only." },
  { id:"f05", sev:"CRITICAL", cat:"Auth",        tool:"nuclei",
    title:"Spring Boot Actuator /env exponiert", asset:"api.mueller-gmbh.de/actuator/env",
    cvss:8.9,  kev:false, epss:"0.743", age:5,  status:"open",
    desc:"Spring Boot Actuator /actuator/env responds with all environment variables including DB_PASSWORD, JWT_SECRET, STRIPE_API_KEY.",
    fix:"Set management.endpoints.web.exposure.include=health,info. Add Spring Security to /actuator/*." },
  { id:"f06", sev:"HIGH",     cat:"Subdomain",   tool:"subfinder",
    title:"Subdomain Takeover: dev.mueller-gmbh.de", asset:"dev.mueller-gmbh.de",
    cvss:8.1,  kev:false, epss:"—",     age:1,  status:"open",
    desc:"CNAME points to herokudns.com (Heroku app no longer exists). Subdomain takeover possible — attacker can host content under your domain.",
    fix:"Remove CNAME record or re-create Heroku app. Run DNS cleanup quarterly." },
  { id:"f07", sev:"HIGH",     cat:"Port",        tool:"naabu",
    title:"RDP Port 3389 direkt erreichbar",    asset:"203.0.113.46:3389",
    cvss:8.1,  kev:false, epss:"0.612", age:8,  status:"open",
    desc:"RDP exposed directly to internet. Primary entry point for ransomware. Brute-force and credential-stuffing attacks detected in scan window.",
    fix:"Restrict RDP to VPN-only. Enable NLA. Use Palo Alto GlobalProtect as RDP gateway." },
  { id:"f08", sev:"HIGH",     cat:"MCP",         tool:"ramparts",
    title:"MCP Shell-Tools ohne Auth exponiert", asset:"203.0.113.55:8080",
    cvss:8.0,  kev:false, epss:"—",     age:1,  status:"open",
    desc:"MCP server exposes execute_command, shell, run_script tools without authentication. Direct RCE via POST /mcp → tools/call.",
    fix:"Restrict dangerous tools. Add authentication. Run MCP server with minimal OS privileges." },
  { id:"f09", sev:"HIGH",     cat:"Credential",  tool:"theharvester",
    title:"31 E-Mails in Stealer-Log-Daten",    asset:"mueller-gmbh.de",
    cvss:7.5,  kev:false, epss:"—",     age:2,  status:"open",
    desc:"31 @mueller-gmbh.de email addresses found in public OSINT sources. Cross-referenced with HIBP: 8 accounts have compromised credentials.",
    fix:"Force password reset for affected accounts. Enable MFA. Deploy phishing simulation." },
  { id:"f10", sev:"HIGH",     cat:"CVE",         tool:"nuclei",
    title:"CVE-2024-21887 — Ivanti Connect RCE", asset:"remote.mueller-gmbh.de:443",
    cvss:9.1,  kev:true,  epss:"0.966", age:12, status:"acknowledged",
    cve:"CVE-2024-21887",
    desc:"Command injection in Ivanti Connect Secure. KEV-listed — active exploitation confirmed. Combine with CVE-2023-46805 for pre-auth RCE.",
    fix:"Apply Ivanti patch. If unpatched: factory reset and reimage. Check for web shells in /data/runtime/." },
  { id:"f11", sev:"MEDIUM",   cat:"HTTP",        tool:"httpx",
    title:"CORS Origin-Reflection auf /api/",   asset:"api.mueller-gmbh.de/api/",
    cvss:6.5,  kev:false, epss:"0.234", age:3,  status:"open",
    desc:"Server reflects arbitrary Origin header in Access-Control-Allow-Origin. Combined with credentials: cross-site API calls possible from any domain.",
    fix:"Whitelist allowed origins explicitly. Never reflect arbitrary Origin headers. Remove CORS wildcard." },
  { id:"f12", sev:"MEDIUM",   cat:"HTTP",        tool:"httpx",
    title:"GraphQL Introspection aktiv",        asset:"api.mueller-gmbh.de/graphql",
    cvss:5.3,  kev:false, epss:"—",     age:3,  status:"open",
    desc:"GraphQL endpoint active with introspection enabled. Full schema readable by any unauthenticated client including all types, queries, mutations.",
    fix:"Disable introspection in production: graphql-disable-introspection middleware or schema directives." },
  { id:"f13", sev:"LOW",      cat:"TLS",         tool:"httpx",
    title:"SSL-Zertifikat läuft in 8 Tagen ab", asset:"mail.mueller-gmbh.de:443",
    cvss:0.0,  kev:false, epss:"—",     age:1,  status:"open",
    desc:"TLS certificate expires 2026-05-14. Browser warnings imminent. HSTS preload will cause extended outage if not renewed.",
    fix:"Renew certificate. Configure auto-renewal via Let's Encrypt certbot or ACME protocol." },
];

const SUBDOMAINS = [
  { fqdn:"vpn.mueller-gmbh.de",      ip:"203.0.113.45",  org:"Hetzner Online",    asn:24940, ports:[443,1194],   risk:"CRITICAL", sources:["subfinder","cert"] },
  { fqdn:"admin.mueller-gmbh.de",    ip:"203.0.113.46",  org:"Hetzner Online",    asn:24940, ports:[443,8080],   risk:"CRITICAL", sources:["subfinder"] },
  { fqdn:"staging.mueller-gmbh.de",  ip:"203.0.113.48",  org:"Hetzner Online",    asn:24940, ports:[80,443],     risk:"CRITICAL", sources:["subfinder","dns"] },
  { fqdn:"jenkins.mueller-gmbh.de",  ip:"203.0.113.55",  org:"Hetzner Online",    asn:24940, ports:[8080,6274],  risk:"HIGH",     sources:["subfinder"] },
  { fqdn:"dev.mueller-gmbh.de",       ip:"—",             org:"Heroku",            asn: 0,    ports:[],           risk:"HIGH",     sources:["subfinder"], takeover:true },
  { fqdn:"remote.mueller-gmbh.de",   ip:"203.0.113.47",  org:"Hetzner Online",    asn:24940, ports:[443,3389],   risk:"HIGH",     sources:["subfinder","dns"] },
  { fqdn:"www.mueller-gmbh.de",       ip:"203.0.113.5",   org:"Hetzner Online",    asn:24940, ports:[80,443],     risk:"LOW",      sources:["dns","cert"] },
  { fqdn:"mail.mueller-gmbh.de",      ip:"203.0.113.10",  org:"Hetzner Online",    asn:24940, ports:[25,443,587], risk:"LOW",      sources:["dns","mx"] },
  { fqdn:"api.mueller-gmbh.de",       ip:"203.0.113.7",   org:"Hetzner Online",    asn:24940, ports:[443],        risk:"MEDIUM",   sources:["subfinder","cert"] },
  { fqdn:"cdn.mueller-gmbh.de",       ip:"104.21.44.8",   org:"Cloudflare",        asn:13335, ports:[80,443],     risk:"LOW",      sources:["dns"] },
  { fqdn:"shop.mueller-gmbh.de",      ip:"203.0.113.6",   org:"Hetzner Online",    asn:24940, ports:[80,443],     risk:"MEDIUM",   sources:["subfinder","cert"] },
  { fqdn:"crm.mueller-gmbh.de",       ip:"136.147.128.30",org:"Salesforce",        asn:14340, ports:[443],        risk:"LOW",      sources:["dns"] },
  { fqdn:"analytics.mueller-gmbh.de", ip:"172.217.22.4",  org:"Google",            asn:15169, ports:[443],        risk:"LOW",      sources:["dns"] },
  { fqdn:"intranet.mueller-gmbh.de",  ip:"81.169.145.20", org:"STRATO AG",         asn:6724,  ports:[80,443],     risk:"HIGH",     sources:["subfinder"] },
];

const MCP_SERVERS = [
  { url:"http://203.0.113.55:8080/mcp", port:8080, auth:false,  tools:["execute_command","read_file","write_file","list_directory","shell"],
    server:"FastMCP v1.2.0", cve:"CVE-2025-49596", risk:"CRITICAL",
    injection:true, inspection_active:true },
  { url:"http://203.0.113.55:6274",     port:6274, auth:false,  tools:["inspector_proxy"],
    server:"@modelcontextprotocol/inspector@0.6.0", cve:"CVE-2025-49596", risk:"CRITICAL",
    injection:false, inspection_active:true },
];

// ─── MINI COMPONENTS ──────────────────────────────────────────────────────────


// ─── APP PROVIDER ─────────────────────────────────────────────────────────────
const EMPTY_TENANT = { domain:"—", score:0, grade:"?", active:false, last_scan:null, next_scan:null,
  assets:{subdomains:0,ips:0,ports:0,services:0}, findings_summary:{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0}, tool_stats:{} };

function AppProvider({ tenantId, children }) {
  const [tenant,  setTenant]   = useState(EMPTY_TENANT);
  const [findings,setFindings] = useState([]);
  const [assets,  setAssets]   = useState([]);
  const [mcp,     setMcp]      = useState([]);
  const [intel,   setIntel]    = useState(null);
  const [scans,   setScans]    = useState([]);
  const [loading, setLoading]  = useState(true);
  const [error,   setError]    = useState(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [t,f,a,m,i,s] = await Promise.all([
        apiFetch(`/tenants/${tenantId}`),
        apiFetch(`/tenants/${tenantId}/findings?limit=200`),
        apiFetch(`/tenants/${tenantId}/assets`),
        apiFetch(`/tenants/${tenantId}/mcp`),
        apiFetch(`/tenants/${tenantId}/intel`),
        apiFetch(`/tenants/${tenantId}/scans?limit=20`),
      ]);
      setTenant(t); setFindings(f.findings??f); setAssets(a.assets??a);
      setMcp(m.servers??m); setIntel(i); setScans(s.scans??s);
    } catch(e) { setError(e.message); }
    finally    { setLoading(false); }
  }, [tenantId]);

  useEffect(() => { load(); }, [load]);

  const updateFinding = useCallback(async (id, patch) => {
    setFindings(prev => prev.map(f => f.id===id ? {...f,...patch} : f));
    try { await apiFetch(`/tenants/${tenantId}/findings/${id}`, {method:"PATCH",body:patch}); }
    catch { load(); }
  }, [tenantId, load]);

  const triggerScan = useCallback(async (type="full") => {
    const job = await apiFetch(`/tenants/${tenantId}/scans`, {method:"POST",body:{scan_type:type}});
    setScans(prev => [job,...prev]); return job;
  }, [tenantId]);

  return (
    <AppCtx.Provider value={{tenant,findings,assets,mcp,intel,scans,loading,error,reload:load,updateFinding,triggerScan,tenantId}}>
      {children}
    </AppCtx.Provider>
  );
}


const Sev = ({ s, small }) => {
  const c = SEV[s] || SEV.INFO;
  return (
    <span style={{
      fontFamily: T.font, fontSize: small ? 9 : 10, fontWeight: 700,
      color: c.color, background: c.bg, border: `1px solid ${c.border}`,
      padding: small ? "1px 5px" : "2px 7px", borderRadius: 3,
      letterSpacing: "0.04em", whiteSpace: "nowrap",
    }}>{s}</span>
  );
};

const Tag = ({ label, color = T.text2, bg = T.bg3, border = T.border, onClick }) => (
  <span onClick={onClick} style={{
    fontFamily: T.font,
    fontSize: 9,
    fontWeight: 600,
    letterSpacing: "0.05em",
    color,
    background: bg,
    border: `1px solid ${border}`,
    padding: "1px 7px",
    borderRadius: 3,
    whiteSpace: "nowrap",
    cursor: onClick ? "pointer" : "default",
  }}>{label}</span>
);

// ─── BUTTON ───────────────────────────────────────────────────────────────────
const Btn = ({ children, onClick, variant = "primary", size = "md", disabled = false, style = {} }) => {
  const [hov, setHov] = useState(false);
  const base = {
    fontFamily: T.font, fontWeight: 700, letterSpacing: "0.06em",
    border: "none", borderRadius: 4, cursor: disabled ? "not-allowed" : "pointer",
    transition: "all 0.15s", outline: "none", display: "inline-flex",
    alignItems: "center", gap: 6, opacity: disabled ? 0.5 : 1,
    fontSize: size === "sm" ? 9 : size === "lg" ? 12 : 10,
    padding: size === "sm" ? "4px 10px" : size === "lg" ? "10px 24px" : "7px 16px",
  };
  const variants = {
    primary:   { background: hov ? T.accent2   : T.accent,   color: "#052e16", border: "none" },
    secondary: { background: hov ? T.bg4       : T.bg3,      color: T.text1,   border: `1px solid ${hov ? T.border2 : T.border}` },
    danger:    { background: hov ? T.criticalBorder : T.criticalBg, color: T.critical, border: `1px solid ${T.criticalBorder}` },
    ghost:     { background: "transparent",                   color: hov ? T.text0 : T.text1, border: `1px solid ${hov ? T.border2 : T.border}` },
  };
  return (
    <button onClick={!disabled ? onClick : undefined}
      onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}
      style={{ ...base, ...variants[variant], ...style }}>
      {children}
    </button>
  );
};

// ─── INPUT ────────────────────────────────────────────────────────────────────
const Input = ({ value, onChange, placeholder = "", style = {}, onKeyDown }) => {
  const [focused, setFocused] = useState(false);
  return (
    <input value={value} onChange={onChange} placeholder={placeholder} onKeyDown={onKeyDown}
      onFocus={() => setFocused(true)} onBlur={() => setFocused(false)}
      style={{
        background: T.bg2, color: T.text0,
        border: `1px solid ${focused ? T.borderFocus : T.border}`,
        borderRadius: 4, outline: "none",
        fontFamily: T.font, fontSize: 11,
        padding: "7px 11px", transition: "border-color 0.15s",
        boxShadow: focused ? `0 0 0 3px ${T.accent}18` : "none",
        ...style,
      }} />
  );
};

// ─── SELECT ───────────────────────────────────────────────────────────────────
const Select = ({ value, onChange, children, style = {} }) => (
  <select value={value} onChange={onChange} style={{
    background: T.bg2, color: T.text1,
    border: `1px solid ${T.border}`, borderRadius: 4,
    outline: "none", fontFamily: T.font, fontSize: 10,
    padding: "6px 8px", cursor: "pointer", ...style,
  }}>{children}</select>
);

// ─── CARD ─────────────────────────────────────────────────────────────────────
const Card = ({ children, style = {}, noPad = false }) => (
  <div style={{
    background: T.bg2, border: `1px solid ${T.border}`,
    borderRadius: 6, padding: noPad ? 0 : 20,
    overflow: noPad ? "hidden" : "visible", ...style,
  }}>{children}</div>
);

// ─── SECTION HEADER ───────────────────────────────────────────────────────────
const CardHeader = ({ children, sub, action }) => (
  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
    <div>
      <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0 }}>{children}</div>
      {sub && <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, marginTop: 3, letterSpacing: "0.04em" }}>{sub}</div>}
    </div>
    {action}
  </div>
);

const Pill = ({ label, color = T.text1 }) => (
  <span style={{
    fontFamily: T.font, fontSize: 9, fontWeight: 600, letterSpacing: "0.04em",
    color, background: `${color}15`, border: `1px solid ${color}35`,
    padding: "1px 8px", borderRadius: 999,
  }}>{label}</span>
);

const ScoreBar = ({ score }) => {
  const color = score >= 75 ? T.accent : score >= 50 ? T.medium : score >= 25 ? T.high : T.critical;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ flex: 1, height: 4, background: T.bg4, borderRadius: 2, overflow: "hidden" }}>
        <div style={{ width: `${score}%`, height: "100%", background: color,
          borderRadius: 2, transition: "width 1s ease" }} />
      </div>
      <span style={{ fontFamily: T.font, fontSize: 11, color, fontWeight: 700, minWidth: 28 }}>{score}</span>
    </div>
  );
};

const TH = ({ children, onClick, sorted, dir, right }) => (
  <th onClick={onClick} style={{
    padding: "8px 12px", fontSize: 9, fontFamily: T.font, fontWeight: 700,
    color: sorted ? T.accent : T.text2, letterSpacing: "0.08em", textTransform: "uppercase",
    borderBottom: `1px solid ${T.border}`, background: T.bg2,
    textAlign: right ? "right" : "left", cursor: onClick ? "pointer" : "default",
    whiteSpace: "nowrap", userSelect: "none",
  }}>
    {children}{sorted ? (dir === "asc" ? " ↑" : " ↓") : ""}
  </th>
);

const TD = ({ children, mono, right, muted }) => (
  <td style={{
    padding: "9px 12px", fontSize: 11,
    fontFamily: mono ? T.font : T.fontSans,
    color: muted ? T.text2 : T.text1,
    borderBottom: `1px solid ${T.border}`,
    textAlign: right ? "right" : "left",
    whiteSpace: "nowrap",
  }}>{children}</td>
);

const KPI = ({ label, value, sub, color = T.accent, onClick }) => (
  <div onClick={onClick} style={{
    background: T.bg2, border: `1px solid ${T.border}`,
    borderRadius: 6, padding: "16px 20px", cursor: onClick ? "pointer" : "default",
    transition: "border-color 0.15s",
    ...(onClick ? { ":hover": { borderColor: color } } : {}),
  }}
  onMouseEnter={e => onClick && (e.currentTarget.style.borderColor = color)}
  onMouseLeave={e => onClick && (e.currentTarget.style.borderColor = T.border)}>
    <div style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text2, marginBottom: 6, letterSpacing: "0.05em", textTransform: "uppercase" }}>{label}</div>
    <div style={{ fontFamily: T.font, fontSize: 26, fontWeight: 700, color, lineHeight: 1 }}>{value}</div>
    {sub && <div style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text3, marginTop: 4 }}>{sub}</div>}
  </div>
);

const SectionHeader = CardHeader; // unified alias

// ─── SEARCH BAR ───────────────────────────────────────────────────────────────
const SearchBar = ({ onSearch, liveQuery = "", onInputChange }) => {
  const [q, setQ] = useState(liveQuery);
  const [focused, setFocused] = useState(false);
  const examples = [
    "tag:mcp-exposure severity:critical",
    "subdomain:*.mueller-gmbh.de",
    "tool:nuclei has:cve",
    "port:6274 OR port:6277",
    "age:<7 has:no-ticket",
    "cvss:>=9 status:open",
  ];
  const [ex, setEx] = useState(0);

  useEffect(() => {
    const t = setInterval(() => setEx(i => (i+1)%examples.length), 3000);
    return () => clearInterval(t);
  }, []);

  // Sync when parent clears
  useEffect(() => { if (liveQuery === "") setQ(""); }, [liveQuery]);

  const handleChange = (val) => {
    setQ(val);
    if (onInputChange) onInputChange(val);
  };

  const handleSearch = () => { if (q.trim()) onSearch(q.trim()); };

  return (
    <div>
      <div style={{
        display: "flex", alignItems: "center", gap: 0,
        background: T.bg2, border: `1px solid ${focused ? T.borderFocus : T.border2}`,
        borderRadius: 6, overflow: "hidden",
        boxShadow: focused ? `0 0 0 3px ${T.accent}18` : "none",
        transition: "border-color 0.15s, box-shadow 0.15s",
      }}>
        <div style={{ padding: "0 12px", color: T.text3, fontSize: 13 }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <circle cx="11" cy="11" r="7"/><path d="M16.5 16.5L21 21"/>
          </svg>
        </div>
        <input
          value={q}
          onChange={e => handleChange(e.target.value)}
          onKeyDown={e => {
            if (e.key === "Enter") handleSearch();
            if (e.key === "Escape") { handleChange(""); onSearch(""); }
          }}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          placeholder={q ? "" : examples[ex]}
          style={{
            flex: 1, background: "transparent", border: "none", outline: "none",
            fontFamily: T.font, fontSize: 12, color: T.text0,
            padding: "11px 0", letterSpacing: "0.02em",
          }} />
        {q && (
          <button onClick={() => { handleChange(""); onSearch(""); }} style={{
            background: "transparent", border: "none", padding: "0 10px",
            color: T.text3, cursor: "pointer", fontSize: 18, lineHeight: "1",
          }}>×</button>
        )}
        <button onClick={handleSearch} style={{
          background: q.trim() ? T.accent : T.bg4,
          border: "none", padding: "11px 20px",
          fontFamily: T.font, fontSize: 11, fontWeight: 700,
          color: q.trim() ? "#052e16" : T.text3,
          cursor: q.trim() ? "pointer" : "default",
          letterSpacing: "0.06em", transition: "all 0.15s",
        }}>SEARCH</button>
      </div>
      <QueryTokenBar query={q} />
    </div>
  );
};

// ─── OVERVIEW TAB ─────────────────────────────────────────────────────────────

// ─── REMEDIATION ENGINE ───────────────────────────────────────────────────────
const EFFORT_COLOR = {"Sofort":"#f43f5e","Kurzfristig":"#f97316","Mittelfristig":"#eab308","Langfristig":"#60a5fa"};

function buildRemediations(findings) {
  const groups = {};
  const add = (key, f, rem) => {
    if (!groups[key]) groups[key] = {remediation:rem,findings:[],assets:new Set()};
    groups[key].findings.push(f);
    groups[key].assets.add((f.asset||"").split(":")[0].split("/")[0]||"?");
  };
  (findings||[]).forEach(f => {
    const cat=(f.cat||"").toLowerCase(), title=(f.title||"").toLowerCase();
    if (cat==="mcp"||cat==="mcp_exposure") {
      if (title.includes("inspector")||f.cve==="CVE-2025-49596")
        add("mcp_inspector",f,{id:"R-MCP-01",title:"MCP Inspector stoppen (Port 6274/6277)",effortLabel:"Sofort",effortHours:0.5,effortDesc:"Service stoppen + Firewall-Regel",steps:["docker stop mcp-inspector","Ports 6274/6277 in Firewall blockieren","Inspector nie in Produktion betreiben"],impact_note:"Verhindert CVE-2025-49596 sofort."});
      else
        add("mcp_auth",f,{id:"R-MCP-02",title:"MCP-Server authentifizieren",effortLabel:"Sofort",effortHours:1,effortDesc:"Auth-Konfiguration setzen",steps:["DANGEROUSLY_OMIT_AUTH=true entfernen","Bearer-Token setzen","Nie auf 0.0.0.0 binden"],impact_note:"Schließt RCE-Vektor via tools/call."});
    } else if (f.cve&&(cat==="cve")) {
      add(`cve_${f.cve}`,f,{id:`R-CVE-${(f.cve||"").replace("CVE-","").replace("-","")}`,title:`${f.cve} patchen`,effortLabel:"Kurzfristig",effortHours:4,effortDesc:"Patch einspielen",steps:[`Patch für ${f.cve} einspielen`,"System neu starten","Verifikations-Scan"],impact_note:f.kev?`CISA KEV — aktiv ausgenutzt. CVSS ${f.cvss}`:`CVSS ${f.cvss}`});
    } else if (title.includes(".env")) {
      add("env_file",f,{id:"R-EXP-01",title:".env entfernen & Credentials rotieren",effortLabel:"Kurzfristig",effortHours:2,effortDesc:"Config + Rotation",steps:['nginx: location /.env { deny all; }',".env aus Webroot entfernen","ALLE Credentials rotieren",".env in .gitignore"],impact_note:""});
    } else if (title.includes("actuator")) {
      add("actuator",f,{id:"R-EXP-02",title:"Spring Boot Actuator absichern",effortLabel:"Kurzfristig",effortHours:1,effortDesc:"Config anpassen",steps:["management.endpoints.web.exposure.include=health,info","Spring Security für /actuator/**"],impact_note:""});
    } else if (cat==="subdomain"||title.includes("takeover")) {
      add("dns_takeover",f,{id:"R-DNS-01",title:"Verwaiste DNS-Einträge bereinigen",effortLabel:"Sofort",effortHours:0.5,effortDesc:"DNS-Eintrag löschen",steps:["CNAME-Ziel prüfen","Eintrag löschen","Quartalsweise DNS-Audit"],impact_note:"Verhindert Subdomain Takeover."});
    } else if (cat==="port"||title.includes("rdp")) {
      add("rdp_firewall",f,{id:"R-PORT-01",title:"RDP hinter VPN",effortLabel:"Mittelfristig",effortHours:16,effortDesc:"Infra-Konfiguration",steps:["Port 3389 auf VPN-Subnet","NLA aktivieren","MFA für VPN"],impact_note:"Entfernt Ransomware-Eintrittspunkt."});
    } else if (cat==="credential"||cat==="credential_leak") {
      add("credential_reset",f,{id:"R-CRED-01",title:"MFA & Passwort-Reset",effortLabel:"Langfristig",effortHours:40,effortDesc:"Koordinierter Rollout",steps:["MFA erzwingen","Passwort-Reset","HIBP-Monitoring"],impact_note:""});
    } else if (cat==="http") {
      add("http_hardening",f,{id:"R-HTTP-01",title:"HTTP-Security härten",effortLabel:"Kurzfristig",effortHours:2,effortDesc:"Config-Änderung",steps:["CORS-Whitelist","Security-Header (HSTS,CSP)","GraphQL Introspection deaktivieren"],impact_note:""});
    } else if (cat==="tls"||cat==="ssl_issue"||title.includes("ssl")||title.includes("zertifikat")) {
      add("cert_renewal",f,{id:"R-TLS-01",title:"SSL-Zertifikate erneuern",effortLabel:"Kurzfristig",effortHours:1,effortDesc:"Zertifikat erneuern",steps:["Sofort erneuern","Auto-Renewal certbot","Alert < 14 Tage"],impact_note:""});
    } else {
      add(`ind_${f.id}`,f,{id:`R-${f.id}`,title:f.title||"Finding beheben",effortLabel:"Kurzfristig",effortHours:2,effortDesc:"Maßnahme erforderlich",steps:[f.fix||"Siehe Finding-Details."],impact_note:""});
    }
  });
  const SS={CRITICAL:10,HIGH:7,MEDIUM:4,LOW:1,INFO:0};
  const EO={"Sofort":0,"Kurzfristig":1,"Mittelfristig":2,"Langfristig":3};
  return Object.values(groups).map(g=>{
    const maxSev=g.findings.reduce((b,f)=>(SS[f.sev]||0)>(SS[b]||0)?f.sev:b,"LOW");
    const hasKev=g.findings.some(f=>f.kev);
    const maxEpss=Math.max(...g.findings.map(f=>parseFloat(f.epss)||0));
    const sevSum=g.findings.reduce((s,f)=>s+(SS[f.sev]||0),0);
    const impact=Math.round(sevSum*g.assets.size*(hasKev?1.5:1)*(1+maxEpss));
    return{...g.remediation,findings:g.findings,assetCount:g.assets.size,maxSev,hasKev,maxEpss,impactScore:impact,quickWin:Math.round(impact/(g.remediation.effortHours||1))};
  }).sort((a,b)=>{const e=(EO[a.effortLabel]||9)-(EO[b.effortLabel]||9);return e!==0?e:b.quickWin-a.quickWin;});
}

const RemediationDashboard = ({ setTab }) => {
  const { findings } = useApp();
  const [selected, setSelected] = useState(null);
  const remediations = buildRemediations(findings);
  const openF = (findings||[]).filter(f=>f.status==="open");
  const SS={CRITICAL:10,HIGH:7,MEDIUM:4,LOW:1,INFO:0};
  const loss=openF.reduce((s,f)=>s+(SS[f.sev]||0),0);
  const score=Math.max(0,100-loss);
  const quickWins=remediations.filter(r=>r.effortLabel==="Sofort");
  const qwF=quickWins.flatMap(r=>r.findings).length;
  const qwH=quickWins.reduce((s,r)=>s+r.effortHours,0);
  const scoreAfter=Math.min(100,score+quickWins.flatMap(r=>r.findings).reduce((s,f)=>s+(SS[f.sev]||0),0));
  const buckets=["Sofort","Kurzfristig","Mittelfristig","Langfristig"];
  return (
    <div style={{display:"flex",flexDirection:"column",gap:16}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
        {[{label:"Maßnahmen gesamt",value:remediations.length,color:T.text0,sub:`schließen ${openF.length} Findings`},{label:"Sofort umsetzbar",value:quickWins.length,color:T.critical,sub:`~${qwH}h Aufwand`},{label:"Findings geschlossen",value:qwF,color:T.accent,sub:"durch Sofort-Maßnahmen"},{label:"Score nach Sofort",value:scoreAfter,color:T.accent,sub:`aktuell: ${score}`}].map(k=>(
          <div key={k.label} style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:4,padding:"14px 16px"}}>
            <div style={{fontFamily:T.fontSans,fontSize:9,color:T.text2,marginBottom:6,textTransform:"uppercase",letterSpacing:"0.06em"}}>{k.label}</div>
            <div style={{fontFamily:T.font,fontSize:26,fontWeight:700,color:k.color,lineHeight:1,marginBottom:4}}>{k.value}</div>
            <div style={{fontFamily:T.font,fontSize:9,color:T.text3}}>{k.sub}</div>
          </div>
        ))}
      </div>
      <div style={{display:"grid",gridTemplateColumns:selected?"1fr 380px":"1fr",gap:16,alignItems:"flex-start"}}>
        <div style={{display:"flex",flexDirection:"column",gap:8}}>
          {buckets.map(bucket=>{
            const items=remediations.filter(r=>r.effortLabel===bucket);
            if(!items.length) return null;
            const bc=EFFORT_COLOR[bucket];
            return (<div key={bucket}>
              <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:8,marginTop:bucket!=="Sofort"?8:0}}>
                <div style={{height:1,flex:1,background:`${bc}30`}}/>
                <span style={{fontFamily:T.font,fontSize:9,fontWeight:700,color:bc,letterSpacing:"0.1em",background:`${bc}12`,border:`1px solid ${bc}40`,padding:"2px 10px",borderRadius:999}}>{bucket.toUpperCase()} — {items.length} MASSNAHME{items.length!==1?"N":""}</span>
                <div style={{height:1,flex:1,background:`${bc}30`}}/>
              </div>
              {items.map(r=>{
                const isSel=selected?.id===r.id; const sc=SEV[r.maxSev]||SEV.INFO;
                return (<div key={r.id} onClick={()=>setSelected(isSel?null:r)}
                  style={{background:isSel?T.bg3:T.bg2,border:`1px solid ${isSel?bc:T.border}`,borderLeft:`3px solid ${bc}`,borderRadius:4,padding:"12px 16px",cursor:"pointer",marginBottom:6,transition:"all 0.12s"}}
                  onMouseEnter={e=>{if(!isSel)e.currentTarget.style.background=T.bg3}}
                  onMouseLeave={e=>{if(!isSel)e.currentTarget.style.background=T.bg2}}>
                  <div style={{display:"flex",alignItems:"flex-start",gap:12}}>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:5}}>
                        <span style={{fontFamily:T.font,fontSize:9,color:bc,fontWeight:700,letterSpacing:"0.06em",flexShrink:0}}>{r.id}</span>
                        {r.hasKev&&<span style={{fontFamily:T.font,fontSize:8,fontWeight:700,color:T.critical,background:T.criticalBg,border:`1px solid ${T.criticalBorder}`,padding:"0 5px",borderRadius:2}}>KEV</span>}
                        <span style={{fontFamily:T.font,fontSize:9,color:T.text3}}>~{r.effortHours<1?`${r.effortHours*60}min`:`${r.effortHours}h`} · {r.effortDesc}</span>
                      </div>
                      <div style={{fontFamily:T.fontSans,fontSize:13,fontWeight:600,color:T.text0,marginBottom:6}}>{r.title}</div>
                      <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                        <span style={{fontFamily:T.font,fontSize:9,color:sc.color,background:`${sc.color}12`,border:`1px solid ${sc.color}35`,padding:"1px 7px",borderRadius:3}}>{r.maxSev}</span>
                        <span style={{fontFamily:T.font,fontSize:9,color:T.text2,background:T.bg4,border:`1px solid ${T.border}`,padding:"1px 7px",borderRadius:3}}>{r.findings.length} Finding{r.findings.length!==1?"s":""}</span>
                        <span style={{fontFamily:T.font,fontSize:9,color:T.text2,background:T.bg4,border:`1px solid ${T.border}`,padding:"1px 7px",borderRadius:3}}>{r.assetCount} Asset{r.assetCount!==1?"s":""}</span>
                        {r.maxEpss>0&&<span style={{fontFamily:T.font,fontSize:9,color:r.maxEpss>=0.9?T.critical:T.high,background:`${r.maxEpss>=0.9?T.critical:T.high}12`,border:`1px solid ${r.maxEpss>=0.9?T.critical:T.high}35`,padding:"1px 7px",borderRadius:3}}>EPSS {r.maxEpss.toFixed(2)}</span>}
                      </div>
                    </div>
                    <div style={{flexShrink:0,textAlign:"right",minWidth:80}}>
                      <div style={{fontFamily:T.font,fontSize:9,color:T.text3,marginBottom:4,letterSpacing:"0.06em"}}>IMPACT</div>
                      <div style={{height:4,width:80,background:T.bg4,borderRadius:2,overflow:"hidden"}}><div style={{height:"100%",borderRadius:2,width:`${Math.min(100,(r.impactScore/200)*100)}%`,background:bc}}/></div>
                      <div style={{fontFamily:T.font,fontSize:10,color:bc,marginTop:3,fontWeight:700}}>{r.impactScore}</div>
                    </div>
                  </div>
                </div>);
              })}
            </div>);
          })}
        </div>
        {selected&&(
          <div style={{background:T.bg2,border:`1px solid ${T.border}`,borderTop:`2px solid ${EFFORT_COLOR[selected.effortLabel]}`,borderRadius:4,overflow:"hidden",position:"sticky",top:0}}>
            <div style={{padding:"14px 16px",borderBottom:`1px solid ${T.border}`,background:T.bg3}}>
              <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
                <span style={{fontFamily:T.font,fontSize:9,fontWeight:700,color:EFFORT_COLOR[selected.effortLabel],background:`${EFFORT_COLOR[selected.effortLabel]}15`,border:`1px solid ${EFFORT_COLOR[selected.effortLabel]}40`,padding:"1px 8px",borderRadius:3}}>{selected.effortLabel}</span>
                {selected.hasKev&&<span style={{fontFamily:T.font,fontSize:9,fontWeight:700,color:T.critical,background:T.criticalBg,border:`1px solid ${T.criticalBorder}`,padding:"1px 6px",borderRadius:2}}>⚠ KEV</span>}
                <button onClick={()=>setSelected(null)} style={{marginLeft:"auto",background:"transparent",border:"none",color:T.text3,cursor:"pointer",fontSize:18,lineHeight:1}}>×</button>
              </div>
              <div style={{fontFamily:T.fontSans,fontSize:14,fontWeight:700,color:T.text0,lineHeight:1.3}}>{selected.title}</div>
              {selected.impact_note&&<div style={{fontFamily:T.fontSans,fontSize:11,color:T.text2,marginTop:6}}>{selected.impact_note}</div>}
            </div>
            <div style={{padding:"14px 16px"}}>
              <div style={{fontFamily:T.font,fontSize:9,color:T.text3,letterSpacing:"0.08em",marginBottom:10}}>UMSETZUNGSSCHRITTE</div>
              {selected.steps.map((step,i)=>(<div key={i} style={{display:"flex",gap:10,marginBottom:8,padding:"8px 10px",background:T.bg3,borderRadius:3}}><span style={{fontFamily:T.font,fontSize:10,color:T.accent,fontWeight:700,flexShrink:0,marginTop:1}}>{i+1}.</span><span style={{fontFamily:T.fontSans,fontSize:11,color:T.text1,lineHeight:1.5}}>{step}</span></div>))}
              <div style={{fontFamily:T.font,fontSize:9,color:T.text3,letterSpacing:"0.08em",marginTop:14,marginBottom:8}}>BETROFFEN — {selected.findings.length} FINDING{selected.findings.length!==1?"S":""}</div>
              {selected.findings.map(f=>{const sc=SEV[f.sev]||SEV.INFO;return(<div key={f.id} onClick={()=>setTab("findings")} style={{display:"flex",alignItems:"center",gap:8,padding:"6px 8px",borderRadius:3,marginBottom:4,background:T.bg2,border:`1px solid ${T.border}`,cursor:"pointer"}} onMouseEnter={e=>e.currentTarget.style.opacity="0.75"} onMouseLeave={e=>e.currentTarget.style.opacity="1"}><span style={{fontFamily:T.font,fontSize:8,fontWeight:700,color:sc.color,background:sc.bg,border:`1px solid ${sc.border}`,padding:"0 5px",borderRadius:2,flexShrink:0}}>{f.sev}</span><span style={{fontFamily:T.fontSans,fontSize:11,color:T.text1,flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{f.title}</span><span style={{fontFamily:T.font,fontSize:9,color:T.text3,flexShrink:0}}>→</span></div>);})}
              <button onClick={()=>setTab("findings")} style={{width:"100%",marginTop:12,background:T.accent,border:"none",borderRadius:4,padding:"9px",fontFamily:T.font,fontSize:10,fontWeight:700,color:"#052e16",cursor:"pointer",letterSpacing:"0.06em"}}>Findings ansehen →</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// ─── OVERVIEW (Dashboard + Remediation sub-tabs) ──────────────────────────────
const OverviewDashboard = ({ setTab, tenant, findings, intel, total, setSub }) => {
  const { triggerScan } = useApp();
 setTab }

const OverviewTab = ({ setTab }) => {
  const { tenant, findings, intel } = useApp();
  const [sub, setSub] = useState("dashboard");
  const total = Object.values(tenant.findings_summary||{}).reduce((a,b)=>a+b,0);
  const sofortCount = buildRemediations(findings).filter(r=>r.effortLabel==="Sofort").length;
  const subTabStyle = id => ({padding:"8px 16px",background:"transparent",border:"none",borderBottom:`2px solid ${sub===id?T.accent:"transparent"}`,fontFamily:T.fontSans,fontSize:12,fontWeight:sub===id?600:400,color:sub===id?T.accent:T.text1,cursor:"pointer",transition:"all 0.15s",marginBottom:-1});
  return (
    <div style={{display:"flex",flexDirection:"column",gap:0}}>
      <div style={{display:"flex",gap:0,borderBottom:`1px solid ${T.border}`,marginBottom:20}}>
        <button onClick={()=>setSub("dashboard")} style={subTabStyle("dashboard")}>Dashboard</button>
        <button onClick={()=>setSub("remediation")} style={{...subTabStyle("remediation"),display:"flex",alignItems:"center",gap:7}}>
          Remediation Roadmap
          {sub!=="remediation"&&sofortCount>0&&<span style={{fontFamily:T.font,fontSize:9,fontWeight:700,color:T.critical,background:T.criticalBg,border:`1px solid ${T.criticalBorder}`,padding:"1px 6px",borderRadius:999}}>{sofortCount} Sofort</span>}
        </button>
      </div>
      {sub==="dashboard"&&<OverviewDashboard setTab={setTab} tenant={tenant} findings={findings} intel={intel} total={total} setSub={setSub}/>}
      {sub==="remediation"&&<RemediationDashboard setTab={setTab}/>}
    </div>
  );
};

const FindingsTab = () => {
  const { findings, updateFinding } = useApp();

  const [sort, setSort] = useState({ col: "sev", dir: "asc" });
  const [filters, setFilters] = useState({ sev: "ALL", cat: "ALL", tool: "ALL", kev: false });
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState(null);

  const SEV_ORDER = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4 };

  const filtered = (findings||[]).filter(f =>
      (filters.sev === "ALL" || f.sev === filters.sev) &&
      (filters.cat === "ALL" || f.cat === filters.cat) &&
      (filters.tool === "ALL" || f.tool === filters.tool) &&
      (!filters.kev || f.kev) &&
      (!search || f.title.toLowerCase().includes(search.toLowerCase()) ||
        f.asset.toLowerCase().includes(search.toLowerCase()))
    )
    .sort((a, b) => {
      let cmp = 0;
      if (sort.col === "sev")   cmp = SEV_ORDER[a.sev] - SEV_ORDER[b.sev];
      if (sort.col === "cvss")  cmp = (b.cvss||0) - (a.cvss||0);
      if (sort.col === "epss")  cmp = (parseFloat(b.epss)||0) - (parseFloat(a.epss)||0);
      if (sort.col === "kev")   cmp = (b.kev?1:0) - (a.kev?1:0);
      if (sort.col === "age")   cmp = b.age - a.age;
      if (sort.col === "title") cmp = a.title.localeCompare(b.title);
      return sort.dir === "asc" ? cmp : -cmp;
    });

  const toggleSort = (col) => setSort(s => s.col === col ? { col, dir: s.dir === "asc" ? "desc" : "asc" } : { col, dir: "asc" });
  const cats = [...new Set((findings||[]).map(f=>f.cat))];
  const tools = [...new Set((findings||[]).map(f=>f.tool))];

  return (
    <div style={{ display: "flex", gap: 16, alignItems: "flex-start" }}>
      {/* Table */}
      <div style={{ flex: 1, minWidth: 0 }}>
        {/* Filter row */}
        <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap", alignItems: "center" }}>
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Filter findings..."
            style={{
              background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 4,
              padding: "6px 10px", fontFamily: T.font, fontSize: 11, color: T.text0,
              outline: "none", width: 200,
            }} />
          <div style={{ width: 1, height: 20, background: T.border }} />
          {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(s => (
            <button key={s} onClick={() => setFilters(f => ({...f, sev: s}))} style={{
              padding: "4px 10px", background: filters.sev === s ? (SEV[s]?.bg || T.bg3) : "transparent",
              border: `1px solid ${filters.sev === s ? (SEV[s]?.color || T.accent) : T.border}`,
              borderRadius: 3, fontFamily: T.font, fontSize: 10, fontWeight: 700,
              color: filters.sev === s ? (SEV[s]?.color || T.accent) : T.text2, cursor: "pointer",
            }}>{s === "ALL" ? "All" : s}</button>
          ))}
          <div style={{ width: 1, height: 20, background: T.border }} />
          {cats.map(c => (
            <button key={c} onClick={() => setFilters(f => ({...f, cat: f.cat === c ? "ALL" : c}))} style={{
              padding: "4px 9px", background: filters.cat === c ? T.bg4 : "transparent",
              border: `1px solid ${filters.cat === c ? T.accent : T.border}`,
              borderRadius: 3, fontFamily: T.font, fontSize: 9, color: filters.cat === c ? T.accent : T.text2, cursor: "pointer",
            }}>{c}</button>
          ))}
          <label style={{ display: "flex", alignItems: "center", gap: 5, cursor: "pointer", marginLeft: "auto" }}>
            <input type="checkbox" checked={filters.kev} onChange={e => setFilters(f => ({...f, kev: e.target.checked}))} />
            <span style={{ fontFamily: T.font, fontSize: 10, color: filters.kev ? T.red : T.text2 }}>KEV Only</span>
          </label>
          <span style={{ fontFamily: T.font, fontSize: 10, color: T.text3 }}>{filtered.length} findings</span>
        </div>

        <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <TH onClick={() => toggleSort("sev")}  sorted={sort.col==="sev"}  dir={sort.dir}>Severity</TH>
                <TH>Category</TH>
                <TH onClick={() => toggleSort("title")} sorted={sort.col==="title"} dir={sort.dir}>Finding</TH>
                <TH>Asset</TH>
                <TH onClick={() => toggleSort("cvss")} sorted={sort.col==="cvss"} dir={sort.dir} right>CVSS</TH>
                <TH onClick={() => toggleSort("epss")} sorted={sort.col==="epss"} dir={sort.dir} right>EPSS</TH>
                <TH onClick={() => toggleSort("kev")} sorted={sort.col==="kev"} dir={sort.dir}>KEV</TH>
                <TH>Tool</TH>
                <TH onClick={() => toggleSort("age")} sorted={sort.col==="age"} dir={sort.dir}>Age</TH>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f, i) => (
                <tr key={f.id} onClick={() => setSelected(selected?.id === f.id ? null : f)}
                  style={{
                    cursor: "pointer", background: selected?.id === f.id ? T.bg3 : "transparent",
                    borderLeft: selected?.id === f.id ? `2px solid ${SEV[f.sev]?.color}` : "2px solid transparent",
                    transition: "background 0.1s",
                  }}
                  onMouseEnter={e => { if (selected?.id !== f.id) e.currentTarget.style.background = T.bg3; }}
                  onMouseLeave={e => { if (selected?.id !== f.id) e.currentTarget.style.background = "transparent"; }}>
                  <TD><Sev s={f.sev} /></TD>
                  <TD><Tag label={f.cat} /></TD>
                  <TD>
                    <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text0, maxWidth: 280 }}>
                      {f.title}
                    </div>
                    {f.cve && <div style={{ fontFamily: T.font, fontSize: 9, color: T.critical, marginTop: 2 }}>{f.cve}</div>}
                  </TD>
                  <TD mono muted>{f.asset}</TD>
                  <TD right>
                    {f.cvss > 0 ? (
                      <span style={{ fontFamily: T.font, fontSize: 11, fontWeight: 700,
                        color: f.cvss >= 9 ? T.red : f.cvss >= 7 ? T.high : T.medium }}>
                        {f.cvss.toFixed(1)}
                      </span>
                    ) : <span style={{ color: T.text3 }}>—</span>}
                  </TD>
                  <TD right>
                    {f.epss && f.epss !== "—" ? (
                      <span style={{ fontFamily: T.font, fontSize: 11, fontWeight: 700,
                        color: parseFloat(f.epss) >= 0.9 ? T.red : parseFloat(f.epss) >= 0.5 ? T.high : T.text2 }}>
                        {f.epss}
                      </span>
                    ) : <span style={{ color: T.text3, fontFamily: T.font, fontSize: 11 }}>—</span>}
                  </TD>
                  <TD>
                    {f.kev ? (
                      <span onClick={e => { e.stopPropagation(); setFilters(fl => ({...fl, kev: true})); }}
                        title="Click to filter KEV only"
                        style={{ fontFamily: T.font, fontSize: 9, fontWeight: 700,
                        color: T.critical, background: `${T.critical}15`, border: `1px solid ${T.critical}40`,
                        padding: "1px 6px", borderRadius: 2, cursor: "pointer" }}>KEV</span>
                    ) : <span style={{ color: T.text3, fontFamily: T.font, fontSize: 11 }}>—</span>}
                  </TD>
                  <TD>
                    <span style={{ fontFamily: T.font, fontSize: 9, color: TOOL_COLOR[f.tool] || T.text2, fontWeight: 700 }}>
                      {f.tool}
                    </span>
                  </TD>
                  <TD mono muted>{f.age}d</TD>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail panel */}
      {selected && (
        <div style={{
          width: 340, flexShrink: 0, background: T.bg2, border: `1px solid ${T.border}`,
          borderRadius: 6, overflow: "hidden", position: "sticky", top: 0,
        }}>
          <div style={{ padding: "14px 16px", borderBottom: `1px solid ${T.border}`, background: T.bg3 }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
              <Sev s={selected.sev} />
              <Tag label={selected.cat} />
              {selected.kev && <Tag label="KEV" color={T.red} border={`${T.critical}40`} bg={`${T.critical}12`} />}
              <button onClick={() => setSelected(null)} style={{
                marginLeft: "auto", background: "transparent", border: "none",
                color: T.text3, cursor: "pointer", fontSize: 16, lineHeight: 1,
              }}>×</button>
            </div>
            <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0, lineHeight: 1.4 }}>
              {selected.title}
            </div>
            {selected.cve && (
              <div style={{ fontFamily: T.font, fontSize: 10, color: T.critical, marginTop: 6 }}>{selected.cve}</div>
            )}
          </div>

          <div style={{ padding: "14px 16px" }}>
            {/* Scores */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 14 }}>
              {[
                { l:"CVSS", v: selected.cvss > 0 ? selected.cvss.toFixed(1) : "—", c: selected.cvss >= 9 ? T.red : T.high },
                { l:"EPSS", v: selected.epss || "—", c: T.medium },
                { l:"Age",  v: `${selected.age}d`, c: T.text1 },
              ].map(x => (
                <div key={x.l} style={{ background: T.bg3, borderRadius: 4, padding: "8px 10px", textAlign: "center" }}>
                  <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, marginBottom: 3 }}>{x.l}</div>
                  <div style={{ fontFamily: T.font, fontSize: 14, fontWeight: 700, color: x.c }}>{x.v}</div>
                </div>
              ))}
            </div>

            <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, marginBottom: 4, letterSpacing: "0.06em" }}>ASSET</div>
            <div style={{ fontFamily: T.font, fontSize: 11, color: T.accent, marginBottom: 14, wordBreak: "break-all" }}>{selected.asset}</div>

            <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, marginBottom: 6, letterSpacing: "0.06em" }}>DESCRIPTION</div>
            <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text1, lineHeight: 1.6, marginBottom: 14 }}>{selected.desc}</div>

            <div style={{ background: `${T.accent}10`, border: `1px solid ${T.accent}30`, borderRadius: 4, padding: "10px 12px" }}>
              <div style={{ fontFamily: T.font, fontSize: 9, color: T.accent, marginBottom: 5, letterSpacing: "0.06em" }}>REMEDIATION</div>
              <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1, lineHeight: 1.6 }}>{selected.fix}</div>
            </div>

            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <button style={{
                flex: 1, background: T.accent, border: "none", borderRadius: 4,
                padding: "8px", fontFamily: T.font, fontSize: 10, fontWeight: 700,
                color: T.bg0, cursor: "pointer", letterSpacing: "0.05em",
              }}>Open Ticket</button>
              <button style={{
                flex: 1, background: "transparent", border: `1px solid ${T.border}`,
                borderRadius: 4, padding: "8px", fontFamily: T.font, fontSize: 10,
                color: T.text2, cursor: "pointer",
              }}>Accept Risk</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const AssetsTab = () => {
  const { assets: SUBDOMAINS, intel } = useApp();

  const [sub, setSub] = useState("list");
  const [q, setQ] = useState("");
  const SEV_ORDER = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3 };

  const SUB_TABS = [
    { id:"list",     label:"Asset List" },
    { id:"hosting",  label:"Hosting Analysis" },
    { id:"geo",      label:"Geo Distribution" },
    { id:"graph",    label:"Asset Graph" },
    { id:"fqdn",     label:`FQDN Inventory (${(intel?.fqdn_table||[]).length})` },
  ];

  const filtered = (SUBDOMAINS||[])
    .filter(s => !q || s.fqdn.includes(q) || s.ip.includes(q) || s.org.includes(q))
    .sort((a,b) => (SEV_ORDER[a.risk]||4) - (SEV_ORDER[b.risk]||4));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>

      {/* KPI strip */}
      <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
        {["Subdomains","IPs","Ports","Services"].map((l, i) => (
          <div key={l} style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 4, padding: "7px 16px", textAlign: "center" }}>
            <div style={{ fontFamily: T.font, fontSize: 14, fontWeight: 700, color: T.accent }}>{[26,18,47,31][i]}</div>
            <div style={{ fontFamily: T.fontSans, fontSize: 9, color: T.text3, marginTop: 2 }}>{l}</div>
          </div>
        ))}
      </div>

      {/* Sub-tabs */}
      <div style={{ display: "flex", gap: 0, borderBottom: `1px solid ${T.border}`, marginBottom: 16 }}>
        {SUB_TABS.map(t => (
          <button key={t.id} onClick={() => setSub(t.id)} style={{
            padding: "8px 16px", background: "transparent", border: "none",
            borderBottom: `2px solid ${sub === t.id ? T.accent : "transparent"}`,
            fontFamily: T.fontSans, fontSize: 12,
            fontWeight: sub === t.id ? 600 : 400,
            color: sub === t.id ? T.accent : T.text1,
            cursor: "pointer", transition: "all 0.15s", marginBottom: -1,
          }}>{t.label}</button>
        ))}
      </div>

      {/* ── Asset List ── */}
      {sub === "list" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <input value={q} onChange={e => setQ(e.target.value)}
            placeholder="Filter by FQDN, IP, org..."
            style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 4,
              padding: "6px 10px", fontFamily: T.font, fontSize: 11, color: T.text0,
              outline: "none", width: 280 }} />
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, overflow: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>
                <TH>Risk</TH><TH>FQDN</TH><TH>IP Address</TH>
                <TH>Organization</TH><TH>ASN</TH><TH>Open Ports</TH>
                <TH>Discovered Via</TH><TH>Status</TH>
              </tr></thead>
              <tbody>
                {filtered.map(row => (
                  <tr key={row.fqdn} style={{ cursor: "pointer", transition: "background 0.1s" }}
                    onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                    onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                    <TD><Sev s={row.risk} small /></TD>
                    <TD>
                      <span style={{ fontFamily: T.font, fontSize: 11, color: T.accent }}>{row.fqdn}</span>
                      {row.takeover && <Tag label="TAKEOVER" color={T.red} bg={`${T.critical}12`} border={`${T.critical}40`} />}
                    </TD>
                    <TD mono muted>{row.ip || "—"}</TD>
                    <TD><span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1 }}>{row.org}</span></TD>
                    <TD mono muted>{row.asn > 0 ? `AS${row.asn}` : "—"}</TD>
                    <TD>
                      <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                        {row.ports.slice(0,4).map(p => (
                          <Tag key={p} label={String(p)}
                            color={[6274,6277,3389,8080].includes(p) ? T.red : [443,80].includes(p) ? T.accent : T.text2}
                            bg={[6274,6277,3389].includes(p) ? `${T.critical}12` : T.bg3}
                            border={[6274,6277,3389].includes(p) ? `${T.critical}40` : T.border} />
                        ))}
                        {row.ports.length > 4 && <Tag label={`+${row.ports.length-4}`} />}
                      </div>
                    </TD>
                    <TD>
                      <div style={{ display: "flex", gap: 4 }}>
                        {row.sources.map(s => <Pill key={s} label={s} color={TOOL_COLOR[s] || T.text2} />)}
                      </div>
                    </TD>
                    <TD><div style={{ width: 7, height: 7, borderRadius: "50%", background: T.accent }} /></TD>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Hosting Analysis ── */}
      {sub === "hosting" && (
        <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: 20 }}>
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, padding: 20, minWidth: 340 }}>
            <div style={{ fontFamily: T.fontSans, fontSize: 12, fontWeight: 600, color: T.text0, marginBottom: 14 }}>Hosting Organisations</div>
            <div style={{ display: "flex", gap: 20, alignItems: "center" }}>
              <DonutChart data={(intel?.hosting_orgs||[])} size={160} />
              <div style={{ flex: 1 }}>
                {(intel?.hosting_orgs||[]).map((o, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 6 }}>
                    <div style={{ width: 8, height: 8, borderRadius: "50%", background: o.color, flexShrink: 0 }} />
                    <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{o.name}</span>
                    <span style={{ fontFamily: T.font, fontSize: 10, color: o.color, fontWeight: 600 }}>{o.pct.toFixed(1)}%</span>
                    <span style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>{o.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, padding: 20 }}>
            <div style={{ fontFamily: T.fontSans, fontSize: 12, fontWeight: 600, color: T.text0, marginBottom: 14 }}>ASN Mapping</div>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>
                {["Organization","ASN","FQDNs","Distribution"].map(h => (
                  <th key={h} style={{ padding: "6px 10px", fontFamily: T.font, fontSize: 9, color: T.text3,
                    textAlign: "left", borderBottom: `1px solid ${T.border}`, letterSpacing: "0.06em" }}>{h}</th>
                ))}
              </tr></thead>
              <tbody>
                {(intel?.hosting_orgs||[]).map((o, i) => (
                  <tr key={i} onMouseEnter={e=>e.currentTarget.style.background=T.bg3}
                    onMouseLeave={e=>e.currentTarget.style.background="transparent"}
                    style={{ transition: "background 0.1s", cursor: "default" }}>
                    <td style={{ padding: "9px 10px", borderBottom: `1px solid ${T.border}` }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <div style={{ width: 8, height: 8, borderRadius: "50%", background: o.color }} />
                        <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1 }}>{o.name}</span>
                      </div>
                    </td>
                    <td style={{ padding: "9px 10px", borderBottom: `1px solid ${T.border}` }}>
                      <Pill label={`AS${o.asn}`} color={o.color} />
                    </td>
                    <td style={{ padding: "9px 10px", borderBottom: `1px solid ${T.border}` }}>
                      <span style={{ fontFamily: T.font, fontSize: 11, color: T.text0, fontWeight: 700 }}>{o.count}</span>
                    </td>
                    <td style={{ padding: "9px 10px", borderBottom: `1px solid ${T.border}` }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <div style={{ flex: 1, height: 3, background: T.bg4, borderRadius: 2 }}>
                          <div style={{ width: `${o.pct}%`, height: "100%", background: o.color, borderRadius: 2 }} />
                        </div>
                        <span style={{ fontFamily: T.font, fontSize: 10, color: o.color, minWidth: 36 }}>{o.pct.toFixed(1)}%</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Geo Distribution ── */}
      {sub === "geo" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, padding: 16 }}>
            <div style={{ fontFamily: T.fontSans, fontSize: 12, fontWeight: 600, color: T.text0, marginBottom: 10 }}>Geographic Asset Distribution</div>
            <GeoMiniMap
              assets={intel?.geo_assets || [
                { lat:50.11, lng:8.68,   city:"Frankfurt",  risk:"CRITICAL" },
                { lat:52.52, lng:13.40,  city:"Berlin",     risk:"HIGH"     },
                { lat:51.23, lng:6.78,   city:"Düsseldorf", risk:"HIGH"     },
                { lat:39.02, lng:-77.54, city:"Ashburn",    risk:"LOW"      },
                { lat:37.34, lng:-121.9, city:"San Jose",   risk:"LOW"      },
                { lat:52.37, lng:4.89,   city:"Amsterdam",  risk:"MEDIUM"   },
              ]}
              height={260}
            />
            <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
              {[["CRITICAL",T.red],["HIGH",T.high],["MEDIUM",T.medium],["LOW",T.low]].map(([s,c]) => (
                <div key={s} style={{ display:"flex", alignItems:"center", gap:5 }}>
                  <div style={{ width:7, height:7, borderRadius:"50%", background:c }}/>
                  <span style={{ fontFamily:T.font, fontSize:9, color:T.text2 }}>{s}</span>
                </div>
              ))}
              <span style={{ marginLeft:"auto", fontFamily:T.font, fontSize:9, color:T.text3 }}>6 locations · 3 countries</span>
            </div>
          </div>
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, overflow: "hidden" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>
                {["City","Country","IPs","Risk","Coordinates"].map(h => (
                  <th key={h} style={{ padding: "7px 14px", fontFamily: T.font, fontSize: 9, color: T.text3,
                    textAlign: "left", background: T.bg3, borderBottom: `1px solid ${T.border}`, letterSpacing: "0.06em" }}>{h}</th>
                ))}
              </tr></thead>
              <tbody>
                {(intel?.geo_assets||[]).map((a,i) => (
                  <tr key={i} onMouseEnter={e=>e.currentTarget.style.background=T.bg3}
                    onMouseLeave={e=>e.currentTarget.style.background="transparent"}
                    style={{ transition:"background 0.1s" }}>
                    <td style={{ padding:"9px 14px", borderBottom:`1px solid ${T.border}` }}>
                      <span style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text0, fontWeight: 500 }}>{a.city}</span>
                    </td>
                    <td style={{ padding:"9px 14px", borderBottom:`1px solid ${T.border}` }}>
                      <Tag label={a.country} />
                    </td>
                    <td style={{ padding:"9px 14px", borderBottom:`1px solid ${T.border}` }}>
                      <span style={{ fontFamily: T.font, fontSize: 11, color: T.text0, fontWeight: 700 }}>{a.ip_count}</span>
                    </td>
                    <td style={{ padding:"9px 14px", borderBottom:`1px solid ${T.border}` }}>
                      <Sev s={a.risk} small />
                    </td>
                    <td style={{ padding:"9px 14px", borderBottom:`1px solid ${T.border}` }}>
                      <span style={{ fontFamily: T.font, fontSize: 10, color: T.text2 }}>{a.lat.toFixed(3)}, {a.lng.toFixed(3)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Asset Graph ── */}
      {sub === "graph" && <IntelAssetGraph />}

      {/* ── FQDN Inventory ── */}
      {sub === "fqdn" && <FqdnInventory data={(intel?.fqdn_table||[])} />}
    </div>
  );
}

const MCPTab = () => {
  const { mcp: MCP_SERVERS, findings } = useApp();
  const mcpFindings = (findings||[]).filter(f => f.cat === "MCP" || f.cat === "mcp_exposure");
  const [sel, setSel] = useState(null);

  
  

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

      {/* Alert */}
      <div style={{
        background: `${T.critical}10`, border: `1px solid ${T.critical}50`,
        borderLeft: `3px solid ${T.critical}`, borderRadius: 4, padding: "12px 16px",
      }}>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={T.red} strokeWidth="2" style={{flexShrink:0,marginTop:1}}><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8" cy="8" r="1.5" fill={T.red}/><circle cx="16" cy="8" r="1.5" fill={T.red}/><path d="M8 14s1 2 4 2 4-2 4-2"/></svg>
          <div>
            <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.critical, marginBottom: 4 }}>
              {(MCP_SERVERS||[]).length} MCP Server{(MCP_SERVERS||[]).length !== 1 ? "s" : ""} Exposed Without Authentication
            </div>
            <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text1 }}>
              Unauthenticated MCP servers allow any attacker to call tools/list and tools/call — enabling filesystem access, shell execution, and database reads with no credentials.
              Attack chain: <span style={{ fontFamily: T.font, color: T.critical }}>POST /mcp → initialize → tools/list → tools/call → RCE</span>
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "300px 1fr", gap: 16, alignItems: "flex-start" }}>
        {/* Server list */}
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, letterSpacing: "0.08em", marginBottom: 4 }}>DISCOVERED SERVERS</div>
          {(MCP_SERVERS||[]).map(srv => (
            <div key={srv.url} onClick={() => setSel(srv)}
              style={{
                background: sel?.url === srv.url ? T.bg3 : T.bg2,
                border: `1px solid ${sel?.url === srv.url ? T.red : T.border}`,
                borderLeft: `3px solid ${T.critical}`, borderRadius: 4, padding: "12px 14px",
                cursor: "pointer",
              }}>
              <div style={{ fontFamily: T.font, fontSize: 11, color: T.accent, marginBottom: 4, wordBreak: "break-all" }}>{srv.url}</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                <Sev s="CRITICAL" small />
                {!srv.auth && <Tag label="NO AUTH" color={T.red} bg={`${T.critical}12`} border={`${T.critical}40`} />}
                {srv.cve && <Tag label={srv.cve} color={T.red} bg={`${T.critical}08`} border={`${T.critical}30`} />}
              </div>
              <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, marginTop: 6 }}>{srv.server}</div>
            </div>
          ))}

          {/* Stats */}
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 4, padding: "12px 14px", marginTop: 4 }}>
            <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, letterSpacing: "0.06em", marginBottom: 10 }}>MCP FINDINGS</div>
            {mcpFindings.map(f => (
              <div key={f.id} style={{ display: "flex", gap: 8, alignItems: "flex-start", marginBottom: 8, paddingBottom: 8, borderBottom: `1px solid ${T.border}` }}>
                <Sev s={f.sev} small />
                <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1, flex: 1 }}>{f.title}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Server detail */}
        {sel && (
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, overflow: "hidden" }}>
            <div style={{ background: T.bg3, padding: "14px 18px", borderBottom: `1px solid ${T.border}` }}>
              <div style={{ display: "flex", gap: 8, marginBottom: 8, alignItems: "center" }}>
                <Sev s="CRITICAL" />
                {!sel.auth && <Tag label="NO AUTH" color={T.red} bg={`${T.critical}12`} border={`${T.critical}40`} />}
                {sel.cve && <Tag label={sel.cve} color={T.red} bg={`${T.critical}08`} border={`${T.critical}30`} />}
                {sel.inspection_active && <Tag label="INSPECTOR ACTIVE" color={T.high} bg={`${T.high}12`} border={`${T.high}40`} />}
              </div>
              <div style={{ fontFamily: T.font, fontSize: 13, color: T.accent, marginBottom: 4 }}>{sel.url}</div>
              <div style={{ fontFamily: T.font, fontSize: 10, color: T.text3 }}>Server: {sel.server} · Port: {sel.port}</div>
            </div>

            <div style={{ padding: "18px" }}>
              {/* Tools exposed */}
              <div style={{ marginBottom: 20 }}>
                <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, letterSpacing: "0.08em", marginBottom: 10 }}>EXPOSED TOOLS (tools/list response)</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {sel.tools.map(tool => {
                    const isDangerous = ["execute_command","shell","run_script","write_file"].includes(tool);
                    return (
                      <div key={tool} style={{
                        display: "flex", alignItems: "center", gap: 10,
                        background: isDangerous ? `${T.critical}08` : T.bg3,
                        border: `1px solid ${isDangerous ? `${T.critical}30` : T.border}`,
                        borderRadius: 4, padding: "8px 12px",
                      }}>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={isDangerous ? T.red : T.text2} strokeWidth="2">
                          {isDangerous
                            ? <path d="M8 9l-4 3 4 3M16 9l4 3-4 3M12 6l-2 12"/>
                            : <path d="M9 3H5a2 2 0 0 0-2 2v14a2 2 0 0 1 2 2h10a2 2 0 0 0 2-2V8l-5-5z"/>}
                        </svg>
                        <span style={{ fontFamily: T.font, fontSize: 11, color: isDangerous ? T.red : T.text1, fontWeight: isDangerous ? 700 : 400 }}>
                          {tool}
                        </span>
                        {isDangerous && (
                          <Tag label="RCE RISK" color={T.red} bg={`${T.critical}15`} border={`${T.critical}40`} />
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Attack chain */}
              <div style={{ marginBottom: 20 }}>
                <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, letterSpacing: "0.08em", marginBottom: 10 }}>ATTACK CHAIN</div>
                <div style={{ background: T.bg3, border: `1px solid ${T.border}`, borderRadius: 4, padding: "12px 14px" }}>
                  {[
                    { step:"1", cmd:`POST ${sel.url}`, label:"Initialize (no token required)", color: T.text2 },
                    { step:"2", cmd:'{"method":"tools/list"}', label:"Enumerate all available tools", color: T.medium },
                    { step:"3", cmd:'{"method":"tools/call","params":{"name":"execute_command"}}', label:"Execute arbitrary shell command", color: T.critical },
                  ].map(s => (
                    <div key={s.step} style={{ display: "flex", gap: 10, marginBottom: 8, alignItems: "flex-start" }}>
                      <span style={{ fontFamily: T.font, fontSize: 9, color: T.text3, paddingTop: 2, minWidth: 14 }}>{s.step}.</span>
                      <div>
                        <div style={{ fontFamily: T.font, fontSize: 10, color: s.color, marginBottom: 2 }}>{s.cmd}</div>
                        <div style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text3 }}>{s.label}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Remediation */}
              <div style={{ background: `${T.accent}08`, border: `1px solid ${T.accent}25`, borderRadius: 4, padding: "12px 14px" }}>
                <div style={{ fontFamily: T.font, fontSize: 9, color: T.accent, letterSpacing: "0.08em", marginBottom: 8 }}>REMEDIATION</div>
                {[
                  "Enable Bearer-token authentication in MCP server config",
                  "Bind only to localhost — never 0.0.0.0 in production",
                  "Remove DANGEROUSLY_OMIT_AUTH=true from environment",
                  "Stop MCP Inspector: never run in production (ports 6274/6277)",
                  "Implement OAuth 2.1 for remote MCP deployments",
                ].map((r, i) => (
                  <div key={i} style={{ display: "flex", gap: 8, marginBottom: 5, alignItems: "flex-start" }}>
                    <span style={{ color: T.accent, fontSize: 10, paddingTop: 1, flexShrink: 0 }}>›</span>
                    <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1 }}>{r}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
const IntelTab = () => {
  const { intel, assets: SUBDOMAINS } = useApp();
  const [sub, setSub] = useState("hosting");
  // FQDN table state
  const [fqdnSearch, setFqdnSearch] = useState("");
  const [fqdnSev, setFqdnSev] = useState("ALL");
  const [fqdnOrg, setFqdnOrg] = useState(null);
  const [fqdnSort, setFqdnSort] = useState({col:"risk",dir:"asc"});
  const SEV_ORD = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};

  const filteredFqdn = (intel?.fqdn_table||[])
    .filter(r=>
      (fqdnSev==="ALL"||r.risk===fqdnSev)&&
      (fqdnOrg===null||r.org===fqdnOrg)&&
      (!fqdnSearch||r.fqdn.includes(fqdnSearch)||r.ip.includes(fqdnSearch)||
        r.org.toLowerCase().includes(fqdnSearch.toLowerCase())||String(r.asn).includes(fqdnSearch))
    )
    .sort((a,b)=>{
      let c=0;
      if(fqdnSort.col==="risk") c=(SEV_ORD[a.risk]||4)-(SEV_ORD[b.risk]||4);
      else if(fqdnSort.col==="fqdn") c=a.fqdn.localeCompare(b.fqdn);
      else if(fqdnSort.col==="asn") c=a.asn-b.asn;
      else if(fqdnSort.col==="org") c=a.org.localeCompare(b.org);
      return fqdnSort.dir==="asc"?c:-c;
    });

  const SUB_TABS = [
    {id:"hosting",  label:"Hosting Analysis"},
    {id:"geomap",   label:"Geo Distribution"},
    {id:"graph",    label:"Asset Graph"},
    {id:"fqdn",     label:`FQDN Inventory (${(intel?.fqdn_table||[]).length})`},
    {id:"threat",   label:"Threat Intelligence"},
  ];

  return (
    <div>
      {/* Sub-tab bar */}
      <div style={{display:"flex",gap:0,borderBottom:`1px solid ${T.border}`,marginBottom:16}}>
        {SUB_TABS.map(t=>(
          <button key={t.id} onClick={()=>setSub(t.id)} style={{
            padding:"9px 16px",background:"transparent",border:"none",
            borderBottom:`2px solid ${sub===t.id?T.accent:"transparent"}`,
            fontFamily:T.fontSans,fontSize:12,fontWeight:sub===t.id?600:400,
            color:sub===t.id?T.accent:T.text2,cursor:"pointer",marginBottom:-1,
            transition:"color 0.15s",
          }}>{t.label}</button>
        ))}
      </div>

      {/* ── Hosting Analysis ── */}
      {sub==="hosting"&&(
        <div style={{display:"grid",gridTemplateColumns:"280px 1fr",gap:16,alignItems:"flex-start"}}>
          {/* Donut + legend */}
          <div style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:6,padding:18}}>
            <div style={{fontFamily:T.font,fontSize:9,color:T.text3,letterSpacing:"0.08em",marginBottom:14}}>HOSTING ORGANISATIONS</div>
            <div style={{display:"flex",justifyContent:"center",marginBottom:16}}>
              <DonutChart data={(intel?.hosting_orgs||[])} size={160}/>
            </div>
            {(intel?.hosting_orgs||[]).map((o,i)=>(
              <div key={i} onClick={()=>setFqdnOrg(fqdnOrg===o.name?null:o.name)}
                style={{display:"flex",alignItems:"center",gap:8,padding:"5px 6px",
                  borderRadius:4,cursor:"pointer",marginBottom:3,
                  background:fqdnOrg===o.name?T.bg3:"transparent",
                  border:`1px solid ${fqdnOrg===o.name?o.color+"40":T.border+"00"}`,
                  transition:"all 0.1s"}}>
                <div style={{width:8,height:8,borderRadius:"50%",background:o.color,flexShrink:0}}/>
                <span style={{fontFamily:T.fontSans,fontSize:11,color:T.text1,flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{o.name}</span>
                <span style={{fontFamily:T.font,fontSize:9,color:o.color,fontWeight:700}}>{o.pct.toFixed(1)}%</span>
                <span style={{fontFamily:T.font,fontSize:9,color:T.text3}}>{o.count}</span>
              </div>
            ))}
            {fqdnOrg&&<button onClick={()=>setFqdnOrg(null)} style={{marginTop:8,width:"100%",padding:"5px",background:"transparent",border:`1px solid ${T.border}`,borderRadius:3,fontFamily:T.font,fontSize:9,color:T.text3,cursor:"pointer"}}>× Clear filter</button>}
          </div>

          {/* ASN breakdown table */}
          <div style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:6,overflow:"hidden"}}>
            <div style={{padding:"12px 16px",borderBottom:`1px solid ${T.border}`,background:T.bg3}}>
              <span style={{fontFamily:T.font,fontSize:9,color:T.text3,letterSpacing:"0.08em"}}>ASN MAPPING — {(intel?.hosting_orgs||[]).length} ORGANISATIONS</span>
            </div>
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead><tr>
                <TH>Organisation</TH><TH>ASN</TH><TH right>FQDNs</TH><TH right>Share</TH><TH>Distribution</TH>
              </tr></thead>
              <tbody>
                {(intel?.hosting_orgs||[]).map((o,i)=>(
                  <tr key={i} onClick={()=>{setFqdnOrg(fqdnOrg===o.name?null:o.name);setSub("fqdn");}}
                    style={{cursor:"pointer",background:fqdnOrg===o.name?T.bg3:"transparent",transition:"background 0.1s"}}
                    onMouseEnter={e=>e.currentTarget.style.background=T.bg3}
                    onMouseLeave={e=>e.currentTarget.style.background=fqdnOrg===o.name?T.bg3:"transparent"}>
                    <TD>
                      <div style={{display:"flex",alignItems:"center",gap:8}}>
                        <div style={{width:8,height:8,borderRadius:"50%",background:o.color,flexShrink:0}}/>
                        <span style={{fontFamily:T.fontSans,fontSize:12,color:T.text0}}>{o.name}</span>
                      </div>
                    </TD>
                    <TD mono muted>AS{o.asn}</TD>
                    <TD right><span style={{fontFamily:T.font,fontSize:12,fontWeight:700,color:o.color}}>{o.count}</span></TD>
                    <TD right><span style={{fontFamily:T.font,fontSize:11,color:T.text2}}>{o.pct.toFixed(1)}%</span></TD>
                    <TD>
                      <div style={{width:120,height:4,background:T.bg4,borderRadius:2}}>
                        <div style={{width:`${o.pct}%`,height:"100%",background:o.color,borderRadius:2}}/>
                      </div>
                    </TD>
                  </tr>
                ))}
              </tbody>
            </table>
            <div style={{padding:"10px 16px",borderTop:`1px solid ${T.border}`,fontFamily:T.font,fontSize:9,color:T.text3}}>
              Click row to filter FQDN inventory by organisation
            </div>
          </div>
        </div>
      )}

      {/* ── Geo Distribution ── */}
      {sub==="geomap"&&(
        <div style={{display:"flex",flexDirection:"column",gap:14}}>
          <div style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:6,padding:18}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}>
              <div style={{fontFamily:T.font,fontSize:9,color:T.text3,letterSpacing:"0.08em"}}>GEO ASSET DISTRIBUTION</div>
              <div style={{display:"flex",gap:10}}>
                {["CRITICAL","HIGH","MEDIUM","LOW"].map(r=>(
                  <div key={r} style={{display:"flex",alignItems:"center",gap:4}}>
                    <div style={{width:7,height:7,borderRadius:"50%",background:SEV[r].color}}/>
                    <span style={{fontFamily:T.font,fontSize:9,color:T.text2}}>{r}</span>
                  </div>
                ))}
              </div>
            </div>
            <GeoMiniMap
              assets={(intel?.geo_assets || [
                {lat:50.11,lng:8.68,  city:"Frankfurt",  risk:"CRITICAL"},
                {lat:52.52,lng:13.40, city:"Berlin",     risk:"MEDIUM"},
                {lat:51.23,lng:6.78,  city:"Düsseldorf", risk:"HIGH"},
                {lat:39.02,lng:-77.54,city:"Ashburn",    risk:"LOW"},
                {lat:37.34,lng:-121.9,city:"San Jose",   risk:"LOW"},
                {lat:52.37,lng:4.89,  city:"Amsterdam",  risk:"MEDIUM"},
              ])}
              height={300}
            />
          </div>
          {/* Location table */}
          <div style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:6,overflow:"hidden"}}>
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead><tr><TH>City</TH><TH>Country</TH><TH right>IPs</TH><TH>Risk</TH><TH>Coordinates</TH></tr></thead>
              <tbody>
                {[{lat:50.11,lng:8.68,city:"Frankfurt",country:"DE",ip_count:10,risk:"CRITICAL"},
                  {lat:51.23,lng:6.78,city:"Düsseldorf",country:"DE",ip_count:3,risk:"HIGH"},
                  {lat:52.52,lng:13.40,city:"Berlin",country:"DE",ip_count:4,risk:"MEDIUM"},
                  {lat:52.37,lng:4.89,city:"Amsterdam",country:"NL",ip_count:3,risk:"MEDIUM"},
                  {lat:39.02,lng:-77.54,city:"Ashburn, VA",country:"US",ip_count:4,risk:"LOW"},
                  {lat:37.34,lng:-121.9,city:"San Jose, CA",country:"US",ip_count:2,risk:"LOW"},
                ].map((a,i)=>(
                  <tr key={i} style={{transition:"background 0.1s"}}
                    onMouseEnter={e=>e.currentTarget.style.background=T.bg3}
                    onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                    <TD><span style={{fontFamily:T.font,fontSize:11,color:T.accent}}>{a.city}</span></TD>
                    <TD><Tag label={a.country}/></TD>
                    <TD right><span style={{fontFamily:T.font,fontSize:11,fontWeight:700,color:T.text0}}>{a.ip_count}</span></TD>
                    <TD><Sev s={a.risk} small/></TD>
                    <TD mono muted>{a.lat.toFixed(2)}, {a.lng.toFixed(2)}</TD>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Asset Graph ── */}
      {sub==="graph"&&<IntelAssetGraph/>}

      {/* ── FQDN Inventory ── */}
      {sub==="fqdn"&&(
        <div style={{display:"flex",flexDirection:"column",gap:12}}>
          {/* Controls */}
          <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
            <input value={fqdnSearch} onChange={e=>setFqdnSearch(e.target.value)}
              placeholder="Filter FQDN, IP, ASN, org..."
              style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:4,
                padding:"6px 10px",fontFamily:T.font,fontSize:11,color:T.text0,outline:"none",width:240}}/>
            <div style={{width:1,height:20,background:T.border}}/>
            {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(s=>(
              <button key={s} onClick={()=>setFqdnSev(s)} style={{
                padding:"4px 10px",borderRadius:3,cursor:"pointer",
                background:fqdnSev===s?(SEV[s]?.bg||T.bg3):"transparent",
                border:`1px solid ${fqdnSev===s?(SEV[s]?.color||T.accent):T.border}`,
                fontFamily:T.font,fontSize:10,fontWeight:700,
                color:fqdnSev===s?(SEV[s]?.color||T.accent):T.text2}}>
                {s==="ALL"?"All":s}
              </button>
            ))}
            {fqdnOrg&&(
              <div style={{display:"flex",alignItems:"center",gap:6,background:T.bg3,border:`1px solid ${T.border}`,borderRadius:4,padding:"4px 10px"}}>
                <div style={{width:6,height:6,borderRadius:"50%",background:(intel?.hosting_orgs||[]).find(o=>o.name===fqdnOrg)?.color||T.accent}}/>
                <span style={{fontFamily:T.font,fontSize:10,color:T.text1}}>{fqdnOrg}</span>
                <button onClick={()=>setFqdnOrg(null)} style={{background:"none",border:"none",color:T.text3,cursor:"pointer",fontSize:12,padding:0,lineHeight:1}}>×</button>
              </div>
            )}
            <span style={{marginLeft:"auto",fontFamily:T.font,fontSize:10,color:T.text3}}>
              {filteredFqdn.length} / {(intel?.fqdn_table||[]).length}
            </span>
          </div>
          {/* Table */}
          <div style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:6,overflow:"auto"}}>
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead><tr>
                <TH onClick={()=>setFqdnSort(s=>s.col==="risk"?{col:"risk",dir:s.dir==="asc"?"desc":"asc"}:{col:"risk",dir:"asc"})} sorted={fqdnSort.col==="risk"} dir={fqdnSort.dir}>Risk</TH>
                <TH onClick={()=>setFqdnSort(s=>s.col==="fqdn"?{col:"fqdn",dir:s.dir==="asc"?"desc":"asc"}:{col:"fqdn",dir:"asc"})} sorted={fqdnSort.col==="fqdn"} dir={fqdnSort.dir}>FQDN</TH>
                <TH>IP Address</TH>
                <TH>Netblock</TH>
                <TH onClick={()=>setFqdnSort(s=>s.col==="asn"?{col:"asn",dir:s.dir==="asc"?"desc":"asc"}:{col:"asn",dir:"asc"})} sorted={fqdnSort.col==="asn"} dir={fqdnSort.dir}>ASN</TH>
                <TH onClick={()=>setFqdnSort(s=>s.col==="org"?{col:"org",dir:s.dir==="asc"?"desc":"asc"}:{col:"org",dir:"asc"})} sorted={fqdnSort.col==="org"} dir={fqdnSort.dir}>Organisation</TH>
                <TH>Country</TH>
              </tr></thead>
              <tbody>
                {filteredFqdn.map((r,i)=>{
                  const orgColor=(intel?.hosting_orgs||[]).find(o=>o.name===r.org)?.color||T.text2;
                  return(
                    <tr key={i} style={{borderLeft:`2px solid ${["CRITICAL","HIGH"].includes(r.risk)?SEV[r.risk].color:"transparent"}`,transition:"background 0.1s"}}
                      onMouseEnter={e=>e.currentTarget.style.background=T.bg3}
                      onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                      <TD><Sev s={r.risk} small/></TD>
                      <TD><span style={{fontFamily:T.font,fontSize:11,color:T.accent}}>{r.fqdn}</span></TD>
                      <TD mono muted>{r.ip}</TD>
                      <TD mono muted>{r.netblock}</TD>
                      <TD><span onClick={()=>setFqdnOrg(r.org)} style={{fontFamily:T.font,fontSize:10,color:T.accent,cursor:"pointer"}}>AS{r.asn}</span></TD>
                      <TD>
                        <div style={{display:"flex",alignItems:"center",gap:6}}>
                          <div style={{width:6,height:6,borderRadius:"50%",background:orgColor,flexShrink:0}}/>
                          <span onClick={()=>setFqdnOrg(fqdnOrg===r.org?null:r.org)} style={{fontFamily:T.fontSans,fontSize:11,color:T.text1,cursor:"pointer"}}>{r.org}</span>
                        </div>
                      </TD>
                      <TD><Tag label={r.country}/></TD>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Threat Intelligence (moved from old IntelTab) ── */}
      {sub==="threat"&&(
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
          <div style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:6,padding:20,gridColumn:"1/-1"}}>
            <SectionHeader sub="OSINT + HIBP + Stealer-Log correlation">Credential Intelligence</SectionHeader>
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:16}}>
              {[{label:"Emails Harvested",value:31,color:T.accent,tool:"theHarvester"},
                {label:"In Breach DBs",value:8,color:T.high,tool:"HIBP"},
                {label:"Stealer Logs",value:3,color:T.critical,tool:"HIBP Pro"},
                {label:"LinkedIn Exposed",value:14,color:T.toolHttpx,tool:"theHarvester"},
              ].map(k=>(
                <div key={k.label} style={{background:T.bg3,border:`1px solid ${T.border}`,borderRadius:4,padding:"12px 14px"}}>
                  <div style={{fontFamily:T.font,fontSize:9,color:T.text3,marginBottom:5}}>{k.label}</div>
                  <div style={{fontFamily:T.font,fontSize:22,fontWeight:700,color:k.color}}>{k.value}</div>
                  <Pill label={k.tool} color={k.color}/>
                </div>
              ))}
            </div>
            <div style={{background:T.bg3,border:`1px solid ${T.border}`,borderRadius:4,padding:"10px 14px"}}>
              <div style={{fontFamily:T.font,fontSize:9,color:T.text3,marginBottom:8,letterSpacing:"0.06em"}}>SAMPLE HARVESTED EMAILS (anonymized)</div>
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                {["k.weber@m***-gmbh.de","m.schmidt@m***-gmbh.de","info@m***-gmbh.de","support@m***-gmbh.de","admin@m***-gmbh.de"].map(e=>(
                  <Tag key={e} label={e} color={T.accent} bg={`${T.accent}08`} border={`${T.accent}25`}/>
                ))}
              </div>
            </div>
          </div>
          <div style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:6,padding:20}}>
            <SectionHeader sub="EPSS · CISA KEV · Public Exploits">Exploit Intelligence</SectionHeader>
            {(findings||[]).filter(f=>f.cve).map(f=>(
              <div key={f.id} style={{display:"flex",gap:10,alignItems:"flex-start",marginBottom:12,paddingBottom:12,borderBottom:`1px solid ${T.border}`}}>
                <Sev s={f.sev} small/>
                <div style={{flex:1}}>
                  <div style={{fontFamily:T.font,fontSize:10,color:T.critical,marginBottom:2}}>{f.cve}</div>
                  <div style={{fontFamily:T.fontSans,fontSize:11,color:T.text1}}>{f.title.split("—")[1]?.trim()||f.title}</div>
                </div>
                <div style={{textAlign:"right",flexShrink:0}}>
                  <div style={{fontFamily:T.font,fontSize:11,fontWeight:700,color:f.cvss>=9?T.red:T.high}}>{f.cvss.toFixed(1)}</div>
                  {f.kev&&<Tag label="KEV" color={T.red} bg={`${T.critical}12`} border={`${T.critical}40`}/>}
                  {f.epss!=="—"&&<div style={{fontFamily:T.font,fontSize:9,color:T.text2,marginTop:3}}>EPSS {f.epss}</div>}
                </div>
              </div>
            ))}
          </div>
          <div style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:6,padding:20}}>
            <SectionHeader sub="Typosquatting · Phishing lookalikes · Mentions">Dark Web & Threat Intel</SectionHeader>
            {[{type:"Typosquatting",domain:"mueller-gmbh.de.fake-store.ru",date:"2026-04-28",risk:"HIGH"},
              {type:"Phishing Kit",domain:"muelIer-gmbh.de",date:"2026-04-15",risk:"HIGH"},
              {type:"Brand Mention",domain:"Telegram channel (ransomware)",date:"2026-03-02",risk:"MEDIUM"},
              {type:"Credential",domain:"3 accounts on dark web market",date:"2026-02-18",risk:"HIGH"},
            ].map((row,i)=>(
              <div key={i} style={{display:"flex",gap:10,alignItems:"center",marginBottom:10,paddingBottom:10,borderBottom:`1px solid ${T.border}`}}>
                <Sev s={row.risk} small/>
                <div style={{flex:1}}>
                  <div style={{fontFamily:T.fontSans,fontSize:11,color:T.text0}}>{row.type}</div>
                  <div style={{fontFamily:T.font,fontSize:10,color:T.text2}}>{row.domain}</div>
                </div>
                <div style={{fontFamily:T.font,fontSize:9,color:T.text3}}>{row.date}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// ─── MAIN APP ─────────────────────────────────────────────────────────────────
// ─── SCORE HISTORY SPARKLINE ──────────────────────────────────────────────────
const Sparkline = ({ data, color = T.accent, width = 120, height = 32 }) => {
  const min = Math.min(...data), max = Math.max(...data);
  const range = max - min || 1;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - ((v - min) / range) * (height - 4) - 2;
    return `${x},${y}`;
  }).join(" ");
  const last = data[data.length - 1];
  const lastX = width;
  const lastY = height - ((last-min)/range)*(height-4) - 2;
  return (
    <svg width={width} height={height} style={{ overflow: "visible" }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5"
        strokeLinecap="round" strokeLinejoin="round" opacity="0.8" />
      <circle cx={lastX} cy={lastY} r="3" fill={color} />
    </svg>
  );
};

// ─── WORLD GEO MAP — Leaflet.js (auto-loaded from CDN) ──────────────────────
// Loads leaflet CSS+JS once, renders a real interactive map per instance.

let _leafletReady = false;
let _leafletCallbacks = [];

function loadLeaflet(cb) {
  if (_leafletReady) { cb(window.L); return; }
  _leafletCallbacks.push(cb);
  if (document.getElementById("leaflet-css")) return; // already loading

  // CSS
  const link = document.createElement("link");
  link.id = "leaflet-css";
  link.rel = "stylesheet";
  link.href = "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css";
  document.head.appendChild(link);

  // JS
  const script = document.createElement("script");
  script.src = "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js";
  script.onload = () => {
    _leafletReady = true;
    _leafletCallbacks.forEach(fn => fn(window.L));
    _leafletCallbacks = [];
  };
  document.head.appendChild(script);
}

const SEV_HEX = {
  CRITICAL: "#f43f5e",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#60a5fa",
  INFO:     "#94a3b8",
};

const GeoMiniMap = ({ assets = [], height = 280 }) => {
  const containerRef = useRef(null);
  const mapRef       = useRef(null);
  const id = useRef("leaflet-map-" + Math.random().toString(36).slice(2));

  useEffect(() => {
    if (!containerRef.current) return;

    loadLeaflet((L) => {
      // Destroy previous instance if re-mounting
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }

      const map = L.map(id.current, {
        center: [30, 10],
        zoom: 2,
        zoomControl: true,
        scrollWheelZoom: false,
        attributionControl: true,
      });

      // Dark tile layer — CartoDB Dark Matter (no API key needed)
      L.tileLayer(
        "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
        {
          attribution: '&copy; <a href="https://carto.com/">CARTO</a> &copy; <a href="https://openstreetmap.org">OSM</a>',
          subdomains: "abcd",
          maxZoom: 19,
        }
      ).addTo(map);

      // Add markers for each asset location
      assets.forEach((a) => {
        const col  = SEV_HEX[a.risk] || "#94a3b8";
        const size = a.risk === "CRITICAL" ? 14 : a.risk === "HIGH" ? 12 : 10;
        const isPulsing = a.risk === "CRITICAL" || a.risk === "HIGH";

        // Custom SVG icon
        const svgIcon = L.divIcon({
          className: "",
          html: `
            <div style="position:relative;width:${size}px;height:${size}px;">
              ${isPulsing ? `
                <div style="
                  position:absolute;
                  top:50%;left:50%;
                  transform:translate(-50%,-50%);
                  width:${size + 8}px;height:${size + 8}px;
                  border-radius:50%;
                  background:${col};
                  opacity:0.25;
                  animation:leaflet-pulse 1.8s ease-out infinite;
                "></div>` : ""}
              <div style="
                width:${size}px;height:${size}px;
                border-radius:50%;
                background:${col};
                border:2px solid rgba(0,0,0,0.6);
                box-shadow:0 0 6px ${col}80;
              "></div>
            </div>`,
          iconSize:   [size + 8, size + 8],
          iconAnchor: [(size + 8) / 2, (size + 8) / 2],
        });

        const marker = L.marker([a.lat, a.lng], { icon: svgIcon }).addTo(map);
        marker.bindPopup(`
          <div style="font-family:'JetBrains Mono',monospace;font-size:11px;line-height:1.6;color:#f1f5f9;background:#0d1221;padding:4px 0;">
            <strong style="color:${col}">${a.risk}</strong> — ${a.city || ""}<br/>
            ${a.ip_count ? `<span style="color:#475569">${a.ip_count} IP${a.ip_count !== 1 ? "s" : ""}</span>` : ""}
          </div>`, {
          className: "easm-popup",
        });
      });

      // Fit map to markers if we have any
      if (assets.length > 0) {
        try {
          const bounds = L.latLngBounds(assets.map(a => [a.lat, a.lng]));
          map.fitBounds(bounds, { padding: [40, 40], maxZoom: 5 });
        } catch (e) {}
      }

      mapRef.current = map;
    });

    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, [JSON.stringify(assets)]);

  return (
    <div style={{ position: "relative" }}>
      <style>{`
        .leaflet-container { background: #050810 !important; }
        .leaflet-control-attribution {
          background: rgba(5,8,16,0.8) !important;
          color: #273548 !important;
          font-size: 9px !important;
        }
        .leaflet-control-attribution a { color: #475569 !important; }
        .leaflet-control-zoom a {
          background: #0d1221 !important;
          border-color: #1e2d45 !important;
          color: #94a3b8 !important;
        }
        .leaflet-control-zoom a:hover { background: #172131 !important; }
        .leaflet-popup-content-wrapper {
          background: #0d1221 !important;
          border: 1px solid #1e2d45 !important;
          border-radius: 4px !important;
          box-shadow: 0 4px 24px rgba(0,0,0,0.6) !important;
          color: #f1f5f9 !important;
        }
        .leaflet-popup-tip { background: #0d1221 !important; }
        .leaflet-popup-close-button { color: #475569 !important; }
        @keyframes leaflet-pulse {
          0%   { transform: translate(-50%,-50%) scale(1);   opacity: 0.25; }
          70%  { transform: translate(-50%,-50%) scale(2.2); opacity: 0; }
          100% { transform: translate(-50%,-50%) scale(2.2); opacity: 0; }
        }
      `}</style>
      <div
        id={id.current}
        ref={containerRef}
        style={{
          height,
          width: "100%",
          borderRadius: 4,
          overflow: "hidden",
          background: "#050810",
        }}
      />
    </div>
  );
};


// ─── SCAN TIMELINE ────────────────────────────────────────────────────────────
const ScanTimeline = ({ scans }) => (
  <div style={{ display:"flex", flexDirection:"column", gap:0 }}>
    {scans.map((s,i) => (
      <div key={i} style={{ display:"flex", gap:10, position:"relative" }}>
        <div style={{ display:"flex", flexDirection:"column", alignItems:"center", width:16 }}>
          <div style={{ width:8, height:8, borderRadius:"50%", flexShrink:0, marginTop:4,
            background: s.status==="completed" ? T.accent : s.status==="running" ? T.accent : T.text3 }}/>
          {i < scans.length-1 && <div style={{ width:1, flex:1, background:T.border, marginTop:2 }}/>}
        </div>
        <div style={{ flex:1, paddingBottom:14 }}>
          <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:4 }}>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:11, color:T.text0, fontWeight:600 }}>{s.label}</span>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9,
              color: s.status==="completed" ? T.accent : T.text3 }}>
              {s.status==="completed" ? "✓" : "○"} {s.status}
            </span>
            <span style={{ marginLeft:"auto", fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3 }}>{s.time}</span>
          </div>
          <div style={{ display:"flex", gap:5, flexWrap:"wrap" }}>
            {s.tags.map(tag => (
              <span key={tag} style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9,
                color:T.text2, background:T.bg3, border:"1px solid ${T.border}",
                padding:"1px 6px", borderRadius:3 }}>{tag}</span>
            ))}
          </div>
        </div>
      </div>
    ))}
  </div>
);

// ─── SCANS TAB ────────────────────────────────────────────────────────────────
const ScansTab = () => {
  const { scans, findings, triggerScan } = useApp();
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState(-1);
  const [logs, setLogs] = useState([]);
  const logRef = useRef(null);

  const PHASES = [
    { label:"Discovery",    tool:"subfinder + theHarvester", color:T.accent, secs:40 },
    { label:"Port Scan",    tool:"naabu SYN-Scan + UDP",     color:T.medium, secs:28 },
    { label:"HTTP Probing", tool:"httpx + screenshots",      color:T.toolHttpx, secs:34 },
    { label:"Vuln Scan",    tool:"nuclei 7000+ templates",   color:T.critical, secs:67 },
    { label:"MCP Analysis", tool:"ramparts + handshake",     color:T.high, secs:12 },
  ];

  const SCAN_LOG = [
    { t:"subfinder",    msg:"loading passive sources: VirusTotal, Shodan, Censys, SecurityTrails, DNSdumpster...", c:"cyan" },
    { t:"subfinder",    msg:"found 23 subdomains for mueller-gmbh.de", c:"cyan" },
    { t:"theharvester", msg:"google: 8 emails found | linkedin: 14 profiles | bing: 5 virtual hosts", c:"green" },
    { t:"theharvester", msg:"harvested: k.weber@mueller-gmbh.de, m.schmidt@mueller-gmbh.de (+21 more)", c:"green" },
    { t:"naabu",        msg:"scanning 18 IPs | top-1000 ports | SYN mode | rate: 2000pps", c:"yellow" },
    { t:"naabu",        msg:"203.0.113.45 → 443, 1194 open", c:"yellow" },
    { t:"naabu",        msg:"203.0.113.46 → 443, 3389, 8080 open ← RDP exposed!", c:"red" },
    { t:"naabu",        msg:"203.0.113.55 → 80, 443, 6274, 6277, 8080 open ← MCP ports detected!", c:"red" },
    { t:"httpx",        msg:"probing 31 services | tech-detect | favicon-hash | screenshots enabled", c:"purple" },
    { t:"httpx",        msg:"staging.mueller-gmbh.de/.env → HTTP 200 + APP_KEY exposed [CRITICAL]", c:"red" },
    { t:"httpx",        msg:"api.mueller-gmbh.de/actuator/env → propertySources visible [CRITICAL]", c:"red" },
    { t:"httpx",        msg:"tech fingerprint: Laravel, Nginx 1.24, PHP 8.2, Spring Boot 3.1", c:"purple" },
    { t:"nuclei",       msg:"loading 7,234 templates (api, mcp, cve, misconfig, default-login, exposure)", c:"red" },
    { t:"nuclei",       msg:"CVE-2024-3400 ← MATCH on vpn.mueller-gmbh.de:443 [CRITICAL / KEV]", c:"red" },
    { t:"nuclei",       msg:"CVE-2025-49596 ← MATCH on 203.0.113.55:6274 [CRITICAL / CVSS 9.4]", c:"red" },
    { t:"nuclei",       msg:"spring-boot-actuator-env ← MATCH on api.mueller-gmbh.de [CRITICAL]", c:"red" },
    { t:"ramparts",     msg:"connecting to http://203.0.113.55:8080/mcp ...", c:"orange" },
    { t:"ramparts",     msg:"MCP initialize response received WITHOUT Bearer token ← CRITICAL", c:"red" },
    { t:"ramparts",     msg:"tools/list: [execute_command, read_file, write_file, shell, list_directory]", c:"orange" },
    { t:"ramparts",     msg:"CRITICAL: RCE via tools/call → execute_command — no auth required", c:"red" },
    { t:"pipeline",     msg:"deduplicating 38 raw findings → 35 unique findings", c:"dim" },
    { t:"pipeline",     msg:"risk scoring: 5×CRITICAL(-20ea) + 10×HIGH(-10ea) + 14×MEDIUM(-4ea) = 48", c:"dim" },
    { t:"pipeline",     msg:"scan complete ✓ | score: 48/100 | grade: D | 35 findings | duration: 202s", c:"green" },
  ];

  const COLORS = { cyan:T.accent, green:T.accent, yellow:T.medium, red:T.critical, purple:T.toolHttpx, orange:T.high, dim:T.text3 };

  const startScan = () => {
    setRunning(true); setProgress(0); setPhase(0); setLogs([]);
    let p = 0, logI = 0;
    const interval = setInterval(() => {
      p = Math.min(p + 0.9, 100);
      setPhase(Math.min(Math.floor(p / 20), 4));
      const threshold = (logI / SCAN_LOG.length) * 100;
      if (p >= threshold && logI < SCAN_LOG.length) {
        setLogs(l => [...l, SCAN_LOG[logI]]);
        logI++;
      }
      setProgress(p);
      if (p >= 100) { clearInterval(interval); setRunning(false); setPhase(-1); }
    }, 90);
  };

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const histScans = [
    { label:"2026-05-05 08:03 — Full Scan", status:"completed", time:"202s", tags:["35 findings","score: 48","2 MCP CRITICAL"] },
    { label:"2026-05-04 08:00 — Full Scan", status:"completed", time:"198s", tags:["31 findings","score: 52"] },
    { label:"2026-05-03 14:22 — MCP Only",  status:"completed", time:"34s",  tags:["3 findings","1 CRITICAL"] },
    { label:"2026-05-03 08:00 — Full Scan", status:"completed", time:"207s", tags:["28 findings","score: 55"] },
    { label:"2026-05-02 08:00 — Full Scan", status:"completed", time:"195s", tags:["26 findings","score: 57"] },
  ];

  return (
    <div style={{ display:"grid", gridTemplateColumns:"1fr 360px", gap:16, alignItems:"flex-start" }}>
      <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
        {/* Scan control */}
        <div style={{ background:T.bg2, border:"1px solid ${T.border}", borderRadius:6, padding:20 }}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:16 }}>
            <div>
              <div style={{ fontFamily:"'IBM Plex Sans',sans-serif", fontSize:14, fontWeight:600, color:T.text0 }}>Scan Pipeline</div>
              <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3, marginTop:3 }}>
                mueller-gmbh.de · Full Scan · Subfinder · Naabu · theHarvester · HTTPX · Nuclei · Ramparts
              </div>
            </div>
            <button onClick={startScan} disabled={running} style={{
              background: running ? T.bg3 : T.accent,
              border:"none", borderRadius:4, padding:"9px 24px",
              fontFamily:"'JetBrains Mono',monospace", fontSize:11, fontWeight:700,
              color: running ? T.text2 : T.bg0,
              cursor: running ? "not-allowed" : "pointer", letterSpacing:"0.06em",
            }}>
              {running ? `SCANNING… ${Math.round(progress)}%` : "▶  START SCAN"}
            </button>
          </div>
          {/* Progress */}
          <div style={{ height:3, background:T.bg4, borderRadius:2, overflow:"hidden", marginBottom:8 }}>
            <div style={{ height:"100%", background:T.accent, borderRadius:2,
              width:`${progress}%`, transition:"width 0.15s" }}/>
          </div>
          <div style={{ display:"flex", justifyContent:"space-between", marginBottom:16 }}>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3 }}>
              {running ? PHASES[phase]?.tool : progress >= 100 ? "✓ Scan complete — 35 findings" : "Ready to scan"}
            </span>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.accent }}>{Math.round(progress)}%</span>
          </div>
          {/* Phase cards */}
          <div style={{ display:"flex", gap:6 }}>
            {PHASES.map((ph, i) => {
              const done = progress >= (i+1)*20;
              const active = running && phase === i;
              return (
                <div key={i} style={{
                  flex:1, padding:"10px 10px 9px",
                  background: done ? `${ph.color}10` : T.bg3,
                  border:`1px solid ${active ? ph.color : done ? `${ph.color}35` : T.border}`,
                  borderTop:`2px solid ${active||done ? ph.color : T.border}`,
                  borderRadius:4, transition:"all 0.3s",
                }}>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:7, color:ph.color, letterSpacing:"0.08em", marginBottom:4 }}>P{i+1}</div>
                  <div style={{ fontFamily:"'IBM Plex Sans',sans-serif", fontSize:10, fontWeight:600,
                    color: active||done ? T.text0 : T.text3, marginBottom:2 }}>{ph.label}</div>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, color:T.text3 }}>{ph.tool}</div>
                  <div style={{ marginTop:5, fontFamily:"'JetBrains Mono',monospace", fontSize:9,
                    color: done ? T.accent : active ? T.accent : T.text3 }}>
                    {done ? `✓ ${ph.secs}s` : active ? "running…" : `~${ph.secs}s`}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Live log */}
        <div style={{ background:T.bg0, border:"1px solid ${T.border}", borderRadius:6, overflow:"hidden" }}>
          <div style={{ padding:"8px 16px", borderBottom:"1px solid ${T.border}", background:T.bg2,
            display:"flex", justifyContent:"space-between", alignItems:"center" }}>
            <div style={{ display:"flex", gap:6 }}>
              {["#ff5f56","#ffbd2e","#27c93f"].map((c,i) => (
                <div key={i} style={{ width:10, height:10, borderRadius:"50%", background:c, opacity:0.8 }}/>
              ))}
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3, marginLeft:6, letterSpacing:"0.08em" }}>SCAN LOG — LIVE OUTPUT</span>
            </div>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3 }}>{logs.length} lines</span>
          </div>
          <div ref={logRef} style={{ padding:"14px 18px", fontFamily:"'JetBrains Mono',monospace",
            fontSize:11, lineHeight:1.9, minHeight:240, maxHeight:340, overflowY:"auto" }}>
            {logs.length === 0 ? (
              <span style={{ color:T.text3 }}>$ ./easm-pipeline run --domain mueller-gmbh.de --all-features</span>
            ) : logs.map((line, i) => (
              <div key={i} style={{ color: COLORS[line.c] || T.text2 }}>
                <span style={{ color:T.text3, userSelect:"none" }}>[{String(i+1).padStart(2,"0")}] </span>
                <span style={{ color:T.border2 }}>[{line.t}]</span>
                {"  ".slice(0, Math.max(2, 14-line.t.length))}
                <span>{line.msg}</span>
                {i === logs.length-1 && running && <span style={{ animation:"pulse 0.7s infinite" }}> ▮</span>}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Right column */}
      <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
        <div style={{ background:T.bg2, border:"1px solid ${T.border}", borderRadius:6, padding:20 }}>
          <div style={{ fontFamily:"'IBM Plex Sans',sans-serif", fontSize:13, fontWeight:600, color:T.text0, marginBottom:14 }}>Scan History</div>
          <ScanTimeline scans={histScans} />
        </div>
        <div style={{ background:T.bg2, border:"1px solid ${T.border}", borderRadius:6, padding:16 }}>
          <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3, letterSpacing:"0.08em", marginBottom:12 }}>TOOL BREAKDOWN — LAST SCAN</div>
          {Object.entries(tenant?.tool_stats||{}).map(([tool, stats]) => (
            <div key={tool} style={{ display:"flex", alignItems:"center", gap:10, marginBottom:10, paddingBottom:10, borderBottom:"1px solid ${T.border}" }}>
              <div style={{ width:5, height:5, borderRadius:"50%", background:TOOL_COLOR[tool], flexShrink:0 }}/>
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:TOOL_COLOR[tool], fontWeight:700, width:92 }}>{tool}</span>
              <div style={{ flex:1, height:2, background:T.bg4, borderRadius:2 }}>
                <div style={{ width:`${(stats.findings/12)*100}%`, height:"100%", background:TOOL_COLOR[tool], borderRadius:2 }}/>
              </div>
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color: stats.findings>5 ? T.high : T.text2, fontWeight:700, minWidth:18 }}>{stats.findings}F</span>
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3 }}>{stats.duration}s</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ─── REPORTS TAB ─────────────────────────────────────────────────────────────
const ReportsTab = () => {
  const [generating, setGenerating] = useState(null);
  const [done, setDone] = useState({});

  const generate = (id) => {
    setGenerating(id);
    setTimeout(() => { setGenerating(null); setDone(d => ({...d,[id]:true})); }, 1800);
  };

  const SCORE_HIST = [68,64,59,62,57,55,48];
  const MONTHS = ["Nov","Dez","Jan","Feb","Mär","Apr","Mai"];

  const REPORTS = [
    { id:"exec",       title:"Executive Summary",       fmt:"PDF", pages:"4–6",  desc:"High-level risk overview for management — score, grade, critical findings, trend.",
      items:["Risk score & grade","Critical findings summary","Score trend (6 months)","Top 5 action items"] },
    { id:"tech",       title:"Technical Report",         fmt:"PDF", pages:"20–40",desc:"Full finding list with CVSS, EPSS, KEV, asset details and remediation steps.",
      items:["All findings with context","CVSS / EPSS / KEV enrichment","Asset inventory","Per-tool breakdown"] },
    { id:"mcp",        title:"MCP Exposure Report",      fmt:"PDF", pages:"8–12", desc:"Dedicated MCP server exposure report — attack chains, tool inventory, remediation.",
      items:["All MCP servers found","Exposed tool inventory","Attack chain walkthrough","Remediation checklist"] },
    { id:"nis2",       title:"NIS2 Compliance Report",   fmt:"PDF", pages:"15–25",desc:"Maps findings to NIS2 obligations for critical infrastructure operators.",
      items:["NIS2 Article mapping","Gap analysis","Remediation timeline","Evidence collection"] },
    { id:"csv",        title:"Findings CSV Export",      fmt:"CSV", pages:"—",    desc:"Raw findings for SIEM ingestion, ticketing systems or custom analysis.",
      items:["All findings","All metadata fields","Tool attribution","Asset details"] },
    { id:"json",       title:"API / JSON Export",         fmt:"JSON",pages:"—",    desc:"Machine-readable findings for Splunk, XSOAR, Jira, custom integrations.",
      items:["Full pipeline data","Raw tool output","Risk scores","Timestamp metadata"] },
  ];

  const fmtColor = { PDF:T.critical, CSV:T.accent, JSON:T.accent };

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      {/* Score trend */}
      <div style={{ background:T.bg2, border:"1px solid ${T.border}", borderRadius:6, padding:20 }}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:16 }}>
          <div>
            <div style={{ fontFamily:"'IBM Plex Sans',sans-serif", fontSize:14, fontWeight:600, color:T.text0 }}>Risk Score Trend</div>
            <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3, marginTop:3 }}>6 months · All features · Daily scans</div>
          </div>
          <div style={{ textAlign:"right" }}>
            <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:30, fontWeight:700, color:T.critical, lineHeight:1 }}>48</div>
            <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.critical, marginTop:2 }}>▼ −20 vs 6 months ago</div>
          </div>
        </div>
        <div style={{ display:"flex", gap:0, alignItems:"flex-end", height:90 }}>
          {SCORE_HIST.map((v,i) => {
            const col = v>=65 ? T.accent : v>=50 ? T.medium : v>=35 ? T.high : T.critical;
            const isLast = i === SCORE_HIST.length-1;
            return (
              <div key={i} style={{ flex:1, display:"flex", flexDirection:"column", alignItems:"center" }}>
                <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:col, marginBottom:4, fontWeight:isLast?700:400 }}>{v}</div>
                <div style={{ width:"68%", background:col, opacity:isLast?1:0.35,
                  height:`${(v/100)*65}px`, borderRadius:"2px 2px 0 0",
                  border: isLast ? `1px solid ${col}` : "none" }}/>
                <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, color:T.text3, marginTop:5 }}>{MONTHS[i]}</div>
              </div>
            );
          })}
        </div>
        <div style={{ marginTop:12, display:"flex", gap:10, flexWrap:"wrap" }}>
          {[["2 CVEs (KEV)",T.critical],["1 MCP exposed",T.high],["31 emails harvested",T.accent],["Subdomain takeover",T.medium]].map(([l,c]) => (
            <span key={l} style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9,
              color:c, background:`${c}10`, border:`1px solid ${c}35`,
              padding:"2px 8px", borderRadius:3 }}>● {l}</span>
          ))}
        </div>
      </div>

      {/* Report cards */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12 }}>
        {REPORTS.map(r => (
          <div key={r.id} style={{ background:T.bg2, border:"1px solid ${T.border}", borderRadius:6, padding:18, display:"flex", flexDirection:"column" }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
              <div style={{ fontFamily:"'IBM Plex Sans',sans-serif", fontSize:13, fontWeight:600, color:T.text0 }}>{r.title}</div>
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, fontWeight:700,
                color:fmtColor[r.fmt], background:`${fmtColor[r.fmt]}12`,
                border:`1px solid ${fmtColor[r.fmt]}35`, padding:"1px 7px", borderRadius:3 }}>{r.fmt}</span>
            </div>
            <div style={{ fontFamily:"'IBM Plex Sans',sans-serif", fontSize:11, color:T.text2, lineHeight:1.5, marginBottom:12, flex:1 }}>{r.desc}</div>
            <div style={{ marginBottom:14 }}>
              {r.items.map(item => (
                <div key={item} style={{ display:"flex", gap:6, marginBottom:3 }}>
                  <span style={{ color:T.accent, fontSize:9, paddingTop:1, flexShrink:0 }}>›</span>
                  <span style={{ fontFamily:"'IBM Plex Sans',sans-serif", fontSize:10, color:T.text2 }}>{item}</span>
                </div>
              ))}
              {r.pages!=="—" && <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3, marginTop:6 }}>~{r.pages} pages</div>}
            </div>
            <button onClick={() => generate(r.id)} disabled={!!generating} style={{
              background: done[r.id] ? "#00ff8812" : generating===r.id ? T.bg3 : T.bg4,
              border:`1px solid ${done[r.id] ? "#00ff8840" : T.border2}`,
              borderRadius:4, padding:"9px", fontFamily:"'JetBrains Mono',monospace",
              fontSize:10, fontWeight:700, letterSpacing:"0.05em",
              color: done[r.id] ? T.accent : generating===r.id ? T.accent : T.text1,
              cursor: generating ? "not-allowed" : "pointer",
            }}>
              {done[r.id] ? "✓ READY — DOWNLOAD" : generating===r.id ? "GENERATING…" : `GENERATE ${r.fmt}`}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};


// ─── ADMIN / SETTINGS TAB ────────────────────────────────────────────────────
const AdminTab = () => {
  const [section, setSection] = useState("domains");

  // ── Domain state ──
  const [domains, setDomains] = useState([
    { id:1, domain:"mueller-gmbh.de",       status:"active",  last_scan:"2026-05-05 08:03", findings:35, score:48,  ip_ranges:["203.0.113.0/24"], panos:"10.2.7",  added:"2025-11-01" },
    { id:2, domain:"mueller-logistics.de",  status:"active",  last_scan:"2026-05-05 08:08", findings:12, score:71,  ip_ranges:["198.51.100.0/24"],panos:"11.1.3",  added:"2025-11-01" },
    { id:3, domain:"shop.mueller-group.eu", status:"paused",  last_scan:"2026-04-28 08:00", findings:8,  score:82,  ip_ranges:[],                 panos:"",        added:"2026-01-15" },
    { id:4, domain:"mueller-group.com",     status:"pending", last_scan:"—",                findings:0,  score:null,ip_ranges:[],                 panos:"",        added:"2026-05-05" },
  ]);
  const [showAddDomain, setShowAddDomain] = useState(false);
  const [editDomain, setEditDomain] = useState(null);
  const [newDomain, setNewDomain] = useState({ domain:"", ip_ranges:"", panos:"" });
  const [addError, setAddError] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(null);


  // ── Schedule state ──
  const [schedule, setSchedule] = useState({
    full_scan:    { enabled:true,  interval:"daily",   time:"08:00", days:"mon-fri" },
    mcp_scan:     { enabled:true,  interval:"daily",   time:"04:00", days:"all" },
    hibp_check:   { enabled:true,  interval:"daily",   time:"06:00", days:"all" },
    nuclei_update:{ enabled:true,  interval:"daily",   time:"01:00", days:"all" },
    deep_scan:    { enabled:false, interval:"weekly",  time:"02:00", days:"sun" },
  });

  // ── Notification state ──
  const [notif, setNotif] = useState({
    email:         { enabled:true,  value:"security@mueller-gmbh.de" },
    slack_webhook: { enabled:false, value:"" },
    critical_only: { enabled:false },
    report_weekly: { enabled:true  },
  });

  const [saved, setSaved] = useState({});
  const showSaved = (key) => { setSaved(s=>({...s,[key]:true})); setTimeout(()=>setSaved(s=>({...s,[key]:false})),2000); };

  const SECTIONS = [
    { id:"domains",      label:"Domains & Targets" },
    { id:"schedule",     label:"Scan Schedule" },
    { id:"notifications",label:"Notifications" },
    { id:"access",       label:"Access & RBAC" },
  ];

  // Domain validation
  const validateDomain = (d) => {
    if (!d.domain.trim()) return "Domain darf nicht leer sein";
    if (!/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(d.domain.trim())) return "Ungültiges Domain-Format (z.B. example.de)";
    if (domains.find(x => x.domain === d.domain.trim() && x.id !== editDomain?.id)) return "Domain bereits vorhanden";
    return "";
  };

  const handleAddDomain = () => {
    const err = validateDomain(newDomain);
    if (err) { setAddError(err); return; }
    const ranges = newDomain.ip_ranges.split(",").map(s=>s.trim()).filter(Boolean);
    setDomains(d => [...d, {
      id: Date.now(), domain: newDomain.domain.trim().toLowerCase(),
      status:"pending", last_scan:"—", findings:0, score:null,
      ip_ranges: ranges, panos: newDomain.panos.trim(), added: new Date().toISOString().slice(0,10),
    }]);
    setNewDomain({ domain:"", ip_ranges:"", panos:"" });
    setAddError(""); setShowAddDomain(false);
    showSaved("domain_added");
  };

  const handleSaveEdit = () => {
    const err = validateDomain(editDomain);
    if (err) { setAddError(err); return; }
    setDomains(d => d.map(x => x.id === editDomain.id ? editDomain : x));
    setEditDomain(null); setAddError(""); showSaved("domain_saved");
  };

  const statusColor = { active: T.accent, paused: T.medium, pending: T.text2, error: T.red };
  const statusBg    = { active: `${T.accent}12`, paused: `${T.medium}12`, pending: T.bg3, error: `${T.critical}12` };

  return (
    <div style={{ display:"grid", gridTemplateColumns:"200px 1fr", gap:0, minHeight:500 }}>

      {/* Sidebar nav */}
      <div style={{ background:T.bg2, borderRight:`1px solid ${T.border}`, borderRadius:"6px 0 0 6px", padding:"8px 0" }}>
        {SECTIONS.map(s => (
          <button key={s.id} onClick={() => { setSection(s.id); setShowAddDomain(false); setEditDomain(null); setAddError(""); }}
            style={{
              display:"block", width:"100%", textAlign:"left",
              padding:"10px 16px", background:"transparent", border:"none",
              borderLeft:`2px solid ${section===s.id?T.accent:"transparent"}`,
              fontFamily: T.fontSans, fontSize:12, fontWeight: section===s.id?600:400,
              color: section===s.id?T.accent:T.text1, cursor:"pointer", transition:"all 0.1s",
            }}>
            {s.label}
            {s.id==="domains" && <span style={{ float:"right", fontFamily:T.font, fontSize:9, color:T.text3 }}>{domains.length}</span>}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={{ background:T.bg2, border:`1px solid ${T.border}`, borderLeft:"none",
        borderRadius:"0 6px 6px 0", padding:24 }}>

        {/* ══ DOMAINS ══ */}
        {section==="domains" && (
          <div>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:20 }}>
              <div>
                <div style={{ fontFamily:T.fontSans, fontSize:15, fontWeight:700, color:T.text0, marginBottom:3 }}>Domains & Targets</div>
                <div style={{ fontFamily:T.font, fontSize:9, color:T.text3 }}>
                  Domains und IP-Ranges die kontinuierlich gescannt werden. Alle Features für alle Domains.
                </div>
              </div>
              <button onClick={() => { setShowAddDomain(true); setEditDomain(null); setAddError(""); }}
                style={{ background:T.accent, border:"none", borderRadius:4, padding:"8px 18px",
                  fontFamily:T.font, fontSize:11, fontWeight:700, color:T.bg0, cursor:"pointer", letterSpacing:"0.05em", flexShrink:0 }}>
                + ADD DOMAIN
              </button>
            </div>

            {/* Add domain form */}
            {showAddDomain && (
              <div style={{ background:T.bg3, border:`1px solid ${T.border2}`, borderRadius:6,
                padding:18, marginBottom:18, borderLeft:`3px solid ${T.accent}` }}>
                <div style={{ fontFamily:T.font, fontSize:9, color:T.accent, letterSpacing:"0.08em", marginBottom:14 }}>NEW DOMAIN</div>
                <div style={{ display:"grid", gridTemplateColumns:"2fr 2fr 1fr", gap:10, marginBottom:10 }}>
                  {[
                    { key:"domain",    label:"Domain *",                  ph:"example.de",           type:"text"  },
                    { key:"ip_ranges", label:"IP Ranges (komma-getrennt)", ph:"203.0.113.0/24, ...",  type:"text"  },
                    { key:"panos",     label:"PAN-OS Version",             ph:"11.1.3",               type:"text"  },
                  ].map(f => (
                    <div key={f.key}>
                      <div style={{ fontFamily:T.font, fontSize:9, color:T.text3, marginBottom:5, letterSpacing:"0.06em" }}>{f.label.toUpperCase()}</div>
                      <input value={newDomain[f.key]} onChange={e => setNewDomain(d=>({...d,[f.key]:e.target.value}))}
                        placeholder={f.ph} onKeyDown={e => e.key==="Enter" && handleAddDomain()}
                        style={{ width:"100%", background:T.bg2, border:`1px solid ${addError&&f.key==="domain"?T.red:T.border}`,
                          borderRadius:4, padding:"7px 10px", fontFamily:T.font, fontSize:11,
                          color:T.text0, outline:"none" }}/>
                    </div>
                  ))}
                </div>
                {addError && <div style={{ fontFamily:T.font, fontSize:10, color:T.critical, marginBottom:10 }}>⚠ {addError}</div>}
                <div style={{ display:"flex", gap:8 }}>
                  <button onClick={handleAddDomain} style={{ background:T.accent, border:"none", borderRadius:4,
                    padding:"7px 18px", fontFamily:T.font, fontSize:11, fontWeight:700, color:T.bg0, cursor:"pointer" }}>
                    ADD DOMAIN
                  </button>
                  <button onClick={() => { setShowAddDomain(false); setAddError(""); }}
                    style={{ background:"transparent", border:`1px solid ${T.border}`, borderRadius:4,
                      padding:"7px 14px", fontFamily:T.font, fontSize:11, color:T.text2, cursor:"pointer" }}>
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {/* Edit domain form */}
            {editDomain && (
              <div style={{ background:T.bg3, border:`1px solid ${T.border2}`, borderRadius:6,
                padding:18, marginBottom:18, borderLeft:`3px solid ${T.medium}` }}>
                <div style={{ fontFamily:T.font, fontSize:9, color:T.medium, letterSpacing:"0.08em", marginBottom:14 }}>EDIT DOMAIN</div>
                <div style={{ display:"grid", gridTemplateColumns:"2fr 2fr 1fr", gap:10, marginBottom:10 }}>
                  {[
                    { key:"domain",    label:"Domain *" },
                    { key:"ip_ranges_str", label:"IP Ranges (komma-getrennt)" },
                    { key:"panos",     label:"PAN-OS Version" },
                  ].map(f => (
                    <div key={f.key}>
                      <div style={{ fontFamily:T.font, fontSize:9, color:T.text3, marginBottom:5, letterSpacing:"0.06em" }}>{f.label.toUpperCase()}</div>
                      <input
                        value={f.key==="ip_ranges_str" ? (editDomain.ip_ranges||[]).join(", ") : editDomain[f.key]||""}
                        onChange={e => {
                          if (f.key==="ip_ranges_str") setEditDomain(d=>({...d, ip_ranges: e.target.value.split(",").map(s=>s.trim()).filter(Boolean)}));
                          else setEditDomain(d=>({...d,[f.key]:e.target.value}));
                        }}
                        style={{ width:"100%", background:T.bg2, border:`1px solid ${addError&&f.key==="domain"?T.red:T.border}`,
                          borderRadius:4, padding:"7px 10px", fontFamily:T.font, fontSize:11, color:T.text0, outline:"none" }}/>
                    </div>
                  ))}
                </div>
                {addError && <div style={{ fontFamily:T.font, fontSize:10, color:T.critical, marginBottom:10 }}>⚠ {addError}</div>}
                <div style={{ display:"flex", gap:8 }}>
                  <button onClick={handleSaveEdit} style={{ background:T.medium, border:"none", borderRadius:4,
                    padding:"7px 18px", fontFamily:T.font, fontSize:11, fontWeight:700, color:T.bg0, cursor:"pointer" }}>
                    SAVE CHANGES
                  </button>
                  <button onClick={() => { setEditDomain(null); setAddError(""); }}
                    style={{ background:"transparent", border:`1px solid ${T.border}`, borderRadius:4,
                      padding:"7px 14px", fontFamily:T.font, fontSize:11, color:T.text2, cursor:"pointer" }}>
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {saved.domain_added && (
              <div style={{ background:`${T.accent}12`, border:`1px solid ${T.accent}40`, borderRadius:4,
                padding:"8px 14px", marginBottom:14, fontFamily:T.font, fontSize:10, color:T.accent }}>
                ✓ Domain hinzugefügt — Scan wird beim nächsten Zyklus gestartet
              </div>
            )}
            {saved.domain_saved && (
              <div style={{ background:`${T.accent}12`, border:`1px solid ${T.accent}40`, borderRadius:4,
                padding:"8px 14px", marginBottom:14, fontFamily:T.font, fontSize:10, color:T.accent }}>
                ✓ Änderungen gespeichert
              </div>
            )}

            {/* Domains table */}
            <div style={{ border:`1px solid ${T.border}`, borderRadius:6, overflow:"hidden" }}>
              <table style={{ width:"100%", borderCollapse:"collapse" }}>
                <thead><tr>
                  <TH>Status</TH>
                  <TH>Domain</TH>
                  <TH>IP Ranges</TH>
                  <TH>PAN-OS</TH>
                  <TH right>Findings</TH>
                  <TH right>Score</TH>
                  <TH>Last Scan</TH>
                  <TH>Added</TH>
                  <TH>Actions</TH>
                </tr></thead>
                <tbody>
                  {domains.map(d => (
                    <tr key={d.id} style={{ transition:"background 0.1s" }}
                      onMouseEnter={e=>e.currentTarget.style.background=T.bg3}
                      onMouseLeave={e=>e.currentTarget.style.background="transparent"}>

                      <TD>
                        <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                          <div style={{ width:7, height:7, borderRadius:"50%",
                            background:statusColor[d.status]||T.text3,
                            ...(d.status==="active"?{animation:"pulse 2.5s infinite"}:{}) }}/>
                          <span style={{ fontFamily:T.font, fontSize:9, fontWeight:700,
                            color:statusColor[d.status]||T.text3,
                            background:statusBg[d.status]||T.bg3,
                            border:`1px solid ${statusColor[d.status]||T.border}40`,
                            padding:"1px 7px", borderRadius:3, textTransform:"uppercase" }}>
                            {d.status}
                          </span>
                        </div>
                      </TD>

                      <TD>
                        <span style={{ fontFamily:T.font, fontSize:12, color:T.accent, fontWeight:600 }}>{d.domain}</span>
                      </TD>

                      <TD>
                        <div style={{ display:"flex", gap:4, flexWrap:"wrap" }}>
                          {d.ip_ranges.length > 0
                            ? d.ip_ranges.map(r => <Tag key={r} label={r} />)
                            : <span style={{ fontFamily:T.font, fontSize:9, color:T.text3 }}>—</span>}
                        </div>
                      </TD>

                      <TD mono muted>{d.panos || "—"}</TD>

                      <TD right>
                        <span style={{ fontFamily:T.font, fontSize:11, fontWeight:700,
                          color: d.findings>20?T.red:d.findings>5?T.high:T.text2 }}>
                          {d.findings || "—"}
                        </span>
                      </TD>

                      <TD right>
                        {d.score != null ? (
                          <span style={{ fontFamily:T.font, fontSize:11, fontWeight:700,
                            color: d.score>=75?T.accent:d.score>=50?T.medium:d.score>=25?T.high:T.red }}>
                            {d.score}
                          </span>
                        ) : <span style={{ color:T.text3, fontFamily:T.font, fontSize:11 }}>—</span>}
                      </TD>

                      <TD mono muted>{d.last_scan}</TD>
                      <TD mono muted>{d.added}</TD>

                      <TD>
                        <div style={{ display:"flex", gap:6 }}>
                          <button onClick={() => { setEditDomain({...d}); setShowAddDomain(false); setAddError(""); }}
                            style={{ background:"transparent", border:`1px solid ${T.border}`,
                              borderRadius:3, padding:"3px 10px", fontFamily:T.font, fontSize:9,
                              color:T.text2, cursor:"pointer" }}>Edit</button>
                          {d.status==="paused"
                            ? <button onClick={() => setDomains(ds=>ds.map(x=>x.id===d.id?{...x,status:"active"}:x))}
                                style={{ background:"transparent", border:`1px solid ${T.accent}50`,
                                  borderRadius:3, padding:"3px 10px", fontFamily:T.font, fontSize:9,
                                  color:T.accent, cursor:"pointer" }}>Resume</button>
                            : <button onClick={() => setDomains(ds=>ds.map(x=>x.id===d.id?{...x,status:"paused"}:x))}
                                style={{ background:"transparent", border:`1px solid ${T.medium}50`,
                                  borderRadius:3, padding:"3px 10px", fontFamily:T.font, fontSize:9,
                                  color:T.medium, cursor:"pointer" }}>Pause</button>}
                          {confirmDelete===d.id
                            ? <button onClick={() => { setDomains(ds=>ds.filter(x=>x.id!==d.id)); setConfirmDelete(null); }}
                                style={{ background:`${T.critical}15`, border:`1px solid ${T.critical}50`,
                                  borderRadius:3, padding:"3px 10px", fontFamily:T.font, fontSize:9,
                                  color:T.critical, cursor:"pointer", fontWeight:700 }}>Confirm</button>
                            : <button onClick={() => setConfirmDelete(d.id)}
                                style={{ background:"transparent", border:`1px solid ${T.border}`,
                                  borderRadius:3, padding:"3px 10px", fontFamily:T.font, fontSize:9,
                                  color:T.text3, cursor:"pointer" }}>Delete</button>}
                        </div>
                      </TD>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div style={{ marginTop:12, fontFamily:T.font, fontSize:9, color:T.text3 }}>
              {domains.filter(d=>d.status==="active").length} active · {domains.filter(d=>d.status==="paused").length} paused · {domains.filter(d=>d.status==="pending").length} pending
            </div>
          </div>
        )}

        {/* ══ SCAN SCHEDULE ══ */}
        {section==="schedule" && (
          <div>
            <div style={{ fontFamily:T.fontSans, fontSize:15, fontWeight:700, color:T.text0, marginBottom:4 }}>Scan Schedule</div>
            <div style={{ fontFamily:T.font, fontSize:9, color:T.text3, marginBottom:20 }}>Konfiguriert wann welche Scan-Phasen ausgeführt werden.</div>
            {[
              { key:"full_scan",     label:"Full Pipeline Scan",      desc:"Subfinder · Naabu · theHarvester · HTTPX · Nuclei · Ramparts" },
              { key:"mcp_scan",      label:"MCP-Only Scan",           desc:"Dedizierter MCP-Server-Scan (Nuclei + Ramparts)" },
              { key:"hibp_check",    label:"HIBP Credential Check",   desc:"Credential-Leak-Prüfung via HIBP API" },
              { key:"nuclei_update", label:"Nuclei Template Update",  desc:"Aktualisiert Nuclei-Templates aus der Community" },
              { key:"deep_scan",     label:"Deep Scan (UDP + full)",  desc:"Vollständiger Scan inkl. UDP-Ports, recursive Subfinder" },
            ].map(item => {
              const s = schedule[item.key];
              return (
                <div key={item.key} style={{ background:T.bg3, border:`1px solid ${s.enabled?T.border2:T.border}`,
                  borderLeft:`3px solid ${s.enabled?T.accent:T.text3}`,
                  borderRadius:4, padding:"14px 16px", marginBottom:10 }}>
                  <div style={{ display:"flex", alignItems:"flex-start", gap:14 }}>
                    <label style={{ display:"flex", alignItems:"center", gap:0, cursor:"pointer", marginTop:2 }}>
                      <input type="checkbox" checked={s.enabled}
                        onChange={e => setSchedule(sc=>({...sc,[item.key]:{...sc[item.key],enabled:e.target.checked}}))}
                        style={{ width:14, height:14, accentColor: T.accent }}/>
                    </label>
                    <div style={{ flex:1 }}>
                      <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:3 }}>
                        <span style={{ fontFamily:T.fontSans, fontSize:13, fontWeight:600,
                          color:s.enabled?T.text0:T.text3 }}>{item.label}</span>
                        {s.enabled && <Tag label={`${s.interval} · ${s.time}`} color={T.accent} bg={`${T.accent}08`} border={`${T.accent}25`}/>}
                      </div>
                      <div style={{ fontFamily:T.font, fontSize:9, color:T.text3 }}>{item.desc}</div>
                    </div>
                    {s.enabled && (
                      <div style={{ display:"flex", gap:8, alignItems:"center", flexShrink:0 }}>
                        <select value={s.interval}
                          onChange={e=>setSchedule(sc=>({...sc,[item.key]:{...sc[item.key],interval:e.target.value}}))}
                          style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:4,
                            padding:"5px 8px", fontFamily:T.font, fontSize:10, color:T.text1, outline:"none" }}>
                          {["hourly","daily","weekly","monthly"].map(v=><option key={v} value={v}>{v}</option>)}
                        </select>
                        <input type="time" value={s.time}
                          onChange={e=>setSchedule(sc=>({...sc,[item.key]:{...sc[item.key],time:e.target.value}}))}
                          style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:4,
                            padding:"5px 8px", fontFamily:T.font, fontSize:10, color:T.text1, outline:"none", width:90 }}/>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
            <button onClick={() => showSaved("schedule")} style={{ marginTop:8, background:T.accent, border:"none",
              borderRadius:4, padding:"8px 24px", fontFamily:T.font, fontSize:11, fontWeight:700,
              color:T.bg0, cursor:"pointer", letterSpacing:"0.05em" }}>
              {saved.schedule ? "✓ SAVED" : "SAVE SCHEDULE"}
            </button>
          </div>
        )}

        {/* ══ NOTIFICATIONS ══ */}
        {section==="notifications" && (
          <div>
            <div style={{ fontFamily:T.fontSans, fontSize:15, fontWeight:700, color:T.text0, marginBottom:4 }}>Notifications</div>
            <div style={{ fontFamily:T.font, fontSize:9, color:T.text3, marginBottom:20 }}>Alert-Kanäle und Regeln für neue Findings.</div>
            {[
              { key:"email",         label:"E-Mail Alerts",       type:"input", ph:"security@example.de",  desc:"Alert-E-Mail bei kritischen Findings" },
              { key:"slack_webhook", label:"Slack Webhook",       type:"input", ph:"https://hooks.slack.com/...", desc:"Slack-Kanal für Sofort-Alerts" },
            ].map(item => (
              <div key={item.key} style={{ background:T.bg3, border:`1px solid ${T.border}`, borderRadius:4, padding:"14px 16px", marginBottom:10 }}>
                <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom: notif[item.key].enabled?10:0 }}>
                  <label style={{ display:"flex", alignItems:"center", gap:8, cursor:"pointer", flex:1 }}>
                    <input type="checkbox" checked={notif[item.key].enabled}
                      onChange={e=>setNotif(n=>({...n,[item.key]:{...n[item.key],enabled:e.target.checked}}))}/>
                    <div>
                      <div style={{ fontFamily:T.fontSans, fontSize:12, fontWeight:600, color:T.text0 }}>{item.label}</div>
                      <div style={{ fontFamily:T.font, fontSize:9, color:T.text3 }}>{item.desc}</div>
                    </div>
                  </label>
                </div>
                {notif[item.key].enabled && (
                  <input value={notif[item.key].value}
                    onChange={e=>setNotif(n=>({...n,[item.key]:{...n[item.key],value:e.target.value}}))}
                    placeholder={item.ph}
                    style={{ width:"100%", background:T.bg2, border:`1px solid ${T.border}`, borderRadius:4,
                      padding:"7px 10px", fontFamily:T.font, fontSize:11, color:T.text0, outline:"none" }}/>
                )}
              </div>
            ))}
            <div style={{ background:T.bg3, border:`1px solid ${T.border}`, borderRadius:4, padding:"14px 16px", marginBottom:10 }}>
              <div style={{ fontFamily:T.fontSans, fontSize:12, fontWeight:600, color:T.text0, marginBottom:10 }}>Alert Rules</div>
              {[
                { key:"critical_only", label:"Critical & KEV only",  desc:"Nur CRITICAL-Findings und CISA-KEV-Treffer alertieren" },
                { key:"report_weekly", label:"Weekly Summary Report", desc:"Wöchentlicher Zusammenfassungs-Report per E-Mail" },
              ].map(item => (
                <label key={item.key} style={{ display:"flex", alignItems:"center", gap:10, cursor:"pointer", marginBottom:8 }}>
                  <input type="checkbox" checked={notif[item.key].enabled}
                    onChange={e=>setNotif(n=>({...n,[item.key]:{...n[item.key],enabled:e.target.checked}}))}/>
                  <div>
                    <div style={{ fontFamily:T.fontSans, fontSize:12, color:T.text1 }}>{item.label}</div>
                    <div style={{ fontFamily:T.font, fontSize:9, color:T.text3 }}>{item.desc}</div>
                  </div>
                </label>
              ))}
            </div>
            <button onClick={()=>showSaved("notif")} style={{ marginTop:8, background:T.accent, border:"none",
              borderRadius:4, padding:"8px 24px", fontFamily:T.font, fontSize:11, fontWeight:700,
              color:T.bg0, cursor:"pointer", letterSpacing:"0.05em" }}>
              {saved.notif?"✓ SAVED":"SAVE NOTIFICATIONS"}
            </button>
          </div>
        )}

        {/* ══ ACCESS / RBAC ══ */}
        {section==="access" && (
          <div>
            <div style={{ fontFamily:T.fontSans, fontSize:15, fontWeight:700, color:T.text0, marginBottom:4 }}>Access & RBAC</div>
            <div style={{ fontFamily:T.font, fontSize:9, color:T.text3, marginBottom:20 }}>Benutzer, Rollen und API-Tokens für den Plattform-Zugriff.</div>
            {[
              { name:"Klaus Weber",   email:"k.weber@mueller-gmbh.de",  role:"Admin",    last:"2026-05-05", status:"active" },
              { name:"Maria Schmidt", email:"m.schmidt@mueller-gmbh.de",role:"Analyst",  last:"2026-05-04", status:"active" },
              { name:"Tom Bauer",     email:"t.bauer@mueller-gmbh.de",  role:"Read-Only",last:"2026-04-28", status:"active" },
              { name:"SIEM API Token",email:"—",                         role:"API",      last:"2026-05-05", status:"active" },
            ].map((u,i) => (
              <div key={i} style={{ display:"flex", alignItems:"center", gap:14,
                background:T.bg3, border:`1px solid ${T.border}`, borderRadius:4,
                padding:"12px 16px", marginBottom:8 }}>
                <div style={{ width:32, height:32, borderRadius:"50%",
                  background:`${T.accent}20`, border:`1px solid ${T.accent}40`,
                  display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>
                  <span style={{ fontFamily:T.font, fontSize:11, color:T.accent, fontWeight:700 }}>
                    {u.name.split(" ").map(w=>w[0]).join("").slice(0,2)}
                  </span>
                </div>
                <div style={{ flex:1 }}>
                  <div style={{ fontFamily:T.fontSans, fontSize:12, fontWeight:600, color:T.text0 }}>{u.name}</div>
                  <div style={{ fontFamily:T.font, fontSize:9, color:T.text3 }}>{u.email}</div>
                </div>
                <Tag label={u.role} color={u.role==="Admin"?T.red:u.role==="Analyst"?T.accent:u.role==="API"?T.high:T.text2}
                  bg={T.bg2} border={T.border}/>
                <div style={{ fontFamily:T.font, fontSize:9, color:T.text3, minWidth:80, textAlign:"right" }}>Last: {u.last}</div>
                <button style={{ background:"transparent", border:`1px solid ${T.border}`, borderRadius:3,
                  padding:"4px 10px", fontFamily:T.font, fontSize:9, color:T.text2, cursor:"pointer" }}>Edit</button>
              </div>
            ))}
            <button style={{ marginTop:10, background:"transparent", border:`1px solid ${T.accent}`, borderRadius:4,
              padding:"7px 18px", fontFamily:T.font, fontSize:11, color:T.accent, cursor:"pointer" }}>
              + Invite User
            </button>
          </div>
        )}

      </div>
    </div>
  );
};



function buildTabs(findings, assets, mcp) {
  return [
    { id:"overview",   label:"Overview" },
    { id:"findings",   label:"Findings",     count: (findings||[]).filter(f=>f.status==="open").length },
    { id:"assets",     label:"Assets",       count: (assets||[]).length },
    { id:"mcp",        label:"MCP Exposure", count: (mcp||[]).length, alert: (mcp||[]).length > 0 },
    { id:"intel",      label:"Intelligence" },
    { id:"scans",      label:"Scans" },
    { id:"reports",    label:"Reports" },
  ];
}

// ─── LOGIN SCREEN ─────────────────────────────────────────────────────────────
// ─── LOGIN / SETUP SCREEN ─────────────────────────────────────────────────────
function LoginScreen({ onLogin }) {
  const [mode, setMode]         = useState(null); // null=checking, "login", "setup"
  const [email, setEmail]       = useState("");
  const [password, setPassword] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [name, setName]         = useState("");
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState("");
  const [pwStrength, setPwStrength] = useState(0);

  // On mount: ask API if setup is required
  useEffect(() => {
    fetch("/api/v1/auth/status")
      .then(r => r.json())
      .then(d => setMode(d.setup_required ? "setup" : "login"))
      .catch(() => setMode("login")); // fallback if API unreachable
  }, []);

  // Password strength (0–4)
  useEffect(() => {
    if (!password) { setPwStrength(0); return; }
    let s = 0;
    if (password.length >= 8)  s++;
    if (password.length >= 12) s++;
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) s++;
    if (/[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password)) s++;
    setPwStrength(s);
  }, [password]);

  const pwStrengthLabel = ["", "Schwach", "Mäßig", "Gut", "Stark"][pwStrength];
  const pwStrengthColor = ["", T.critical, T.high, T.medium, T.accent][pwStrength];

  const handleSetup = async () => {
    setError("");
    if (!name.trim())            return setError("Bitte Namen eingeben.");
    if (!email.trim())           return setError("Bitte E-Mail eingeben.");
    if (password.length < 8)     return setError("Passwort muss mindestens 8 Zeichen haben.");
    if (password !== confirmPw)  return setError("Passwörter stimmen nicht überein.");
    setLoading(true);
    try {
      const res = await fetch("/api/v1/auth/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, name, tenant_id: "t-mueller" }),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error(e.detail || "Einrichtung fehlgeschlagen.");
      }
      const { access_token, tenant_id } = await res.json();
      saveToken(access_token);
      onLogin(tenant_id || "t-mueller");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async () => {
    setError("");
    if (!email.trim() || !password) return setError("Bitte E-Mail und Passwort eingeben.");
    setLoading(true);
    try {
      const res = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error(e.detail || "Login fehlgeschlagen.");
      }
      const { access_token, tenant_id } = await res.json();
      saveToken(access_token);
      onLogin(tenant_id || "t-mueller");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e) => {
    if (e.key === "Enter") mode === "setup" ? handleSetup() : handleLogin();
  };

  const inputStyle = {
    width: "100%", background: T.bg3, border: `1px solid ${T.border}`,
    borderRadius: 4, padding: "10px 12px", fontFamily: T.font, fontSize: 12,
    color: T.text0, outline: "none", boxSizing: "border-box",
    transition: "border-color 0.15s",
  };
  const labelStyle = {
    fontFamily: T.font, fontSize: 10, color: T.text2,
    letterSpacing: "0.06em", display: "block", marginBottom: 6,
  };

  return (
    <div style={{
      minHeight: "100vh", background: T.bg0, display: "flex",
      alignItems: "center", justifyContent: "center", fontFamily: T.fontSans,
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
        @keyframes fadeSlideIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:none} }
      `}</style>

      <div style={{
        background: T.bg2, border: `1px solid ${T.border}`,
        borderRadius: 8, padding: "40px 48px", width: 400,
        boxShadow: "0 24px 64px rgba(0,0,0,0.5)",
        animation: "fadeSlideIn 0.25s ease",
      }}>
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 28 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8,
            background: "linear-gradient(135deg, #22c55e, #15803d)",
            display: "flex", alignItems: "center", justifyContent: "center",
            flexShrink: 0,
          }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#050810" strokeWidth="2.5">
              <path d="M12 2L3 7v5c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V7L12 2z"/>
            </svg>
          </div>
          <div>
            <div style={{ fontFamily: T.font, fontSize: 16, fontWeight: 700, color: T.text0 }}>
              EASM Platform
            </div>
            <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, letterSpacing: "0.08em" }}>
              MSSP · EXTERNAL ATTACK SURFACE
            </div>
          </div>
        </div>

        {/* Checking state */}
        {mode === null && (
          <div style={{ textAlign: "center", padding: "24px 0", color: T.text3,
            fontFamily: T.font, fontSize: 11 }}>Verbinde...</div>
        )}

        {/* ── SETUP MODE ── */}
        {mode === "setup" && (
          <>
            {/* Setup badge */}
            <div style={{
              display: "flex", alignItems: "center", gap: 8, marginBottom: 20,
              padding: "10px 14px", background: `${T.accent}10`,
              border: `1px solid ${T.accent}30`, borderRadius: 4,
            }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                stroke={T.accent} strokeWidth="2" strokeLinecap="round">
                <circle cx="12" cy="12" r="10"/>
                <path d="M12 8v4M12 16h.01"/>
              </svg>
              <div>
                <div style={{ fontFamily: T.font, fontSize: 10, fontWeight: 700,
                  color: T.accent, letterSpacing: "0.06em" }}>ERSTEINRICHTUNG</div>
                <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text2, marginTop: 2 }}>
                  Lege deinen Admin-Account an.
                </div>
              </div>
            </div>

            {/* Name */}
            <div style={{ marginBottom: 14 }}>
              <label style={labelStyle}>VOLLSTÄNDIGER NAME</label>
              <input value={name} onChange={e => setName(e.target.value)}
                onKeyDown={handleKey} placeholder="Max Mustermann"
                style={inputStyle} autoFocus />
            </div>

            {/* Email */}
            <div style={{ marginBottom: 14 }}>
              <label style={labelStyle}>E-MAIL</label>
              <input value={email} onChange={e => setEmail(e.target.value)}
                onKeyDown={handleKey} placeholder="admin@beispiel.de"
                type="email" style={inputStyle} />
            </div>

            {/* Password */}
            <div style={{ marginBottom: 6 }}>
              <label style={labelStyle}>PASSWORT</label>
              <input type="password" value={password}
                onChange={e => setPassword(e.target.value)}
                onKeyDown={handleKey} placeholder="Mindestens 8 Zeichen"
                style={inputStyle} />
            </div>

            {/* Strength bar */}
            {password.length > 0 && (
              <div style={{ marginBottom: 14 }}>
                <div style={{ height: 3, background: T.bg4, borderRadius: 2,
                  overflow: "hidden", marginBottom: 4 }}>
                  <div style={{
                    height: "100%", borderRadius: 2,
                    width: `${pwStrength * 25}%`,
                    background: pwStrengthColor,
                    transition: "width 0.2s, background 0.2s",
                  }}/>
                </div>
                <div style={{ fontFamily: T.font, fontSize: 9,
                  color: pwStrengthColor }}>{pwStrengthLabel}</div>
              </div>
            )}

            {/* Confirm password */}
            <div style={{ marginBottom: 20 }}>
              <label style={labelStyle}>PASSWORT BESTÄTIGEN</label>
              <input type="password" value={confirmPw}
                onChange={e => setConfirmPw(e.target.value)}
                onKeyDown={handleKey}
                style={{
                  ...inputStyle,
                  borderColor: confirmPw && confirmPw !== password
                    ? T.critical : confirmPw && confirmPw === password
                    ? T.accent : T.border,
                }} />
              {confirmPw && confirmPw === password && (
                <div style={{ fontFamily: T.font, fontSize: 9,
                  color: T.accent, marginTop: 4 }}>✓ Passwörter stimmen überein</div>
              )}
            </div>

            {error && (
              <div style={{ background: T.criticalBg, border: `1px solid ${T.criticalBorder}`,
                borderRadius: 4, padding: "8px 12px", marginBottom: 14,
                fontFamily: T.fontSans, fontSize: 12, color: T.critical }}>{error}</div>
            )}

            <button onClick={handleSetup} disabled={loading} style={{
              width: "100%", background: loading ? T.bg4 : T.accent,
              border: "none", borderRadius: 4, padding: "12px",
              fontFamily: T.font, fontSize: 12, fontWeight: 700,
              color: loading ? T.text3 : "#052e16",
              cursor: loading ? "default" : "pointer",
              letterSpacing: "0.06em", transition: "all 0.15s",
            }}>
              {loading ? "EINRICHTEN..." : "ACCOUNT ERSTELLEN"}
            </button>
          </>
        )}

        {/* ── LOGIN MODE ── */}
        {mode === "login" && (
          <>
            <div style={{ marginBottom: 20 }}>
              <label style={labelStyle}>E-MAIL</label>
              <input value={email} onChange={e => setEmail(e.target.value)}
                onKeyDown={handleKey} type="email"
                style={inputStyle} autoFocus />
            </div>
            <div style={{ marginBottom: 24 }}>
              <label style={labelStyle}>PASSWORT</label>
              <input type="password" value={password}
                onChange={e => setPassword(e.target.value)}
                onKeyDown={handleKey}
                style={inputStyle} />
            </div>

            {error && (
              <div style={{ background: T.criticalBg, border: `1px solid ${T.criticalBorder}`,
                borderRadius: 4, padding: "8px 12px", marginBottom: 16,
                fontFamily: T.fontSans, fontSize: 12, color: T.critical }}>{error}</div>
            )}

            <button onClick={handleLogin} disabled={loading} style={{
              width: "100%", background: loading ? T.bg4 : T.accent,
              border: "none", borderRadius: 4, padding: "12px",
              fontFamily: T.font, fontSize: 12, fontWeight: 700,
              color: loading ? T.text3 : "#052e16",
              cursor: loading ? "default" : "pointer",
              letterSpacing: "0.06em", transition: "all 0.15s",
            }}>
              {loading ? "ANMELDEN..." : "ANMELDEN"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}


// ─── LOADING / ERROR STATES ───────────────────────────────────────────────────
function LoadingScreen() {
  return (
    <div style={{ minHeight: "100vh", background: T.bg0, display: "flex",
      alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 16 }}>
      <div style={{ width: 36, height: 36, borderRadius: 8,
        background: "linear-gradient(135deg, #22c55e, #15803d)",
        display: "flex", alignItems: "center", justifyContent: "center",
        animation: "pulse 1.5s ease-in-out infinite" }}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#050810" strokeWidth="2.5">
          <path d="M12 2L3 7v5c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V7L12 2z"/>
        </svg>
      </div>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "#273548",
        letterSpacing: "0.1em" }}>LADEN...</div>
    </div>
  );
}

// ─── MAIN APP ─────────────────────────────────────────────────────────────────
function AppShell() {
  const { tenant, findings, assets, mcp, loading, error, reload, triggerScan } = useApp();
  const [tab, setTab]               = useState("overview");
  const [searchQuery, setSearchQuery] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [searchResult, setSearchResult] = useState(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const now = new Date().toISOString().slice(0,16).replace("T"," ") + " UTC";

  const tabs = buildTabs(findings, assets, mcp);

  const handleSearch = async (q) => {
    if (!q.trim()) { setSearchResult(null); setSearchQuery(""); return; }
    setSearchQuery(q);
    setSearchInput(q);
    setSearchLoading(true);
    setSearchResult(null);
    try {
      const params = new URLSearchParams({ q, scope: "all", limit: 50 });
      const res = await apiFetch(`/search?${params}`);
      setSearchResult(res);
    } catch(e) {
      setSearchResult({ error: e.message, results: { findings:[], assets:[] },
        total: { findings:0, assets:0 }, took_ms: 0 });
    } finally {
      setSearchLoading(false);
    }
  };

  if (loading) return <LoadingScreen />;

  const scoreColor = tenant.score >= 70 ? T.accent : tenant.score >= 40 ? T.medium : T.critical;
  const lastScanStr = tenant.last_scan
    ? new Date(tenant.last_scan).toLocaleString("de-DE", { dateStyle:"short", timeStyle:"short" })
    : "—";
  const nextScanStr = tenant.next_scan
    ? new Date(tenant.next_scan).toLocaleString("de-DE", { dateStyle:"short", timeStyle:"short" })
    : "—";

  return (
    <div style={{ minHeight: "100vh", background: T.bg0, color: T.text0, fontFamily: T.fontSans }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: ${T.bg1}; }
        ::-webkit-scrollbar-thumb { background: ${T.border2}; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: ${T.text3}; }
        ::placeholder { color: ${T.text3}; }
        input[type=checkbox] { accent-color: ${T.accent}; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:none} }
      `}</style>

      {/* Top Navigation */}
      <div style={{ background: T.bg1, borderBottom: `1px solid ${T.border}`,
        position: "sticky", top: 0, zIndex: 100 }}>

        {/* Brand bar */}
        <div style={{ display: "flex", alignItems: "center", gap: 0,
          padding: "0 24px", height: 48, borderBottom: `1px solid ${T.border}` }}>

          <div style={{ display: "flex", alignItems: "center", gap: 10, marginRight: 32 }}>
            <div style={{ width: 28, height: 28, borderRadius: 6,
              background: "linear-gradient(135deg, #22c55e, #15803d)",
              display: "flex", alignItems: "center", justifyContent: "center" }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={T.bg0} strokeWidth="2.5">
                <path d="M12 2L3 7v5c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V7L12 2z"/>
              </svg>
            </div>
            <div>
              <div style={{ fontFamily: T.font, fontSize: 13, fontWeight: 700, color: T.text0, letterSpacing: "0.02em" }}>EASM</div>
              <div style={{ fontFamily: T.font, fontSize: 8, color: T.text3, letterSpacing: "0.06em" }}>MSSP PLATFORM</div>
            </div>
          </div>

          {/* Domain pill */}
          <div style={{ display: "flex", alignItems: "center", gap: 8,
            background: T.bg2, border: `1px solid ${T.border}`,
            borderRadius: 4, padding: "5px 12px", marginRight: 24 }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%",
              background: T.accent, animation: "pulse 2s infinite" }} />
            <span style={{ fontFamily: T.font, fontSize: 11, color: T.accent, fontWeight: 600 }}>
              {tenant.domain || "mueller-gmbh.de"}
            </span>
          </div>

          {/* Score + grade */}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <Tag label={`Score: ${tenant.score}`} color={scoreColor}
              bg={`${scoreColor}12`} border={`${scoreColor}30`} />
            <Tag label={`Grade ${tenant.grade}`} color={scoreColor}
              bg={`${scoreColor}12`} border={`${scoreColor}30`} />
            {error && <Tag label="API Error" color={T.medium} bg={T.mediumBg} border={T.mediumBorder} />}
          </div>

          {/* Right: scan info + button */}
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>
              Letzter Scan: <span style={{ color: T.text2 }}>{lastScanStr}</span>
            </div>
            <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>
              Nächster: <span style={{ color: T.accent }}>{nextScanStr}</span>
            </div>
            <Btn onClick={() => triggerScan("full")} variant="primary" size="sm">↺ SCAN NOW</Btn>
            <button onClick={() => { clearToken(); window.location.reload(); }}
              style={{ background: "transparent", border: `1px solid ${T.border}`,
                borderRadius: 4, padding: "4px 10px", fontFamily: T.font, fontSize: 9,
                color: T.text3, cursor: "pointer" }}>Logout</button>
          </div>
        </div>

        {/* Search bar */}
        <div style={{ padding: "10px 24px" }}>
          <SearchBar
            onSearch={handleSearch}
            liveQuery={searchInput}
            onInputChange={setSearchInput}
          />
        </div>
      </div>

      {/* Tab navigation */}
      <div style={{ background: T.bg1, borderBottom: `1px solid ${T.border}`,
        display: "flex", gap: 0, padding: "0 24px",
        position: "sticky", top: 118, zIndex: 99 }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => { setTab(t.id); setSearchResult(null); setSearchInput(""); }}
            style={{ padding: "12px 18px", background: "transparent", border: "none",
              borderBottom: `2px solid ${tab === t.id ? T.accent : "transparent"}`,
              fontFamily: T.fontSans, fontSize: 12, fontWeight: tab === t.id ? 600 : 400,
              color: tab === t.id ? T.accent : T.text1, cursor: "pointer",
              display: "flex", alignItems: "center", gap: 7, transition: "color 0.15s",
              marginBottom: -1 }}>
            {t.label}
            {t.count != null && (
              <span style={{ fontFamily: T.font, fontSize: 9, fontWeight: 700,
                background: t.alert ? `${T.critical}20` : T.bg3,
                color: t.alert ? T.red : T.text2,
                border: `1px solid ${t.alert ? `${T.critical}40` : T.border}`,
                padding: "1px 6px", borderRadius: 999 }}>{t.count}</span>
            )}
          </button>
        ))}
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 0 }}>
          <button onClick={() => setTab("admin")} style={{ padding: "12px 18px",
            background: "transparent", border: "none",
            borderBottom: `2px solid ${tab === "admin" ? T.accent : "transparent"}`,
            fontFamily: T.fontSans, fontSize: 12, fontWeight: tab === "admin" ? 600 : 400,
            color: tab === "admin" ? T.accent : T.text2, cursor: "pointer",
            display: "flex", alignItems: "center", gap: 6, marginBottom: -1 }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
            Settings
          </button>
          <div style={{ width: 1, height: 20, background: T.border, margin: "0 12px" }}/>
          <span style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>{now}</span>
        </div>
      </div>

      {/* Main content */}
      <main style={{ padding: "24px", maxWidth: 1600, margin: "0 auto" }}>
        {(searchResult !== null || searchLoading) ? (
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`,
            borderRadius: 6, overflow: "hidden" }}>
            <SearchResults
              result={searchResult}
              query={searchQuery}
              loading={searchLoading}
              onClear={() => { setSearchResult(null); setSearchQuery(""); setSearchInput(""); }}
            />
          </div>
        ) : (
          <>
            {tab === "overview"  && <OverviewTab setTab={setTab} />}
            {tab === "findings"  && <FindingsTab />}
            {tab === "assets"    && <AssetsTab />}
            {tab === "mcp"       && <MCPTab />}
            {tab === "intel"     && <IntelTab />}
            {tab === "scans"     && <ScansTab />}
            {tab === "reports"   && <ReportsTab />}
            {tab === "admin"     && <AdminTab />}
          </>
        )}
      </main>
    </div>
  );
}

// ─── ROOT EXPORT ──────────────────────────────────────────────────────────────
export default function FullHuntUI() {
  const [authed, setAuthed]   = useState(!!getToken());
  const [tenantId, setTenantId] = useState(TENANT_ID);

  if (!authed) {
    return <LoginScreen onLogin={(tid) => { setTenantId(tid); setAuthed(true); }} />;
  }

  return (
    <AppProvider tenantId={tenantId}>
      <AppShell />
    </AppProvider>
  );
}
