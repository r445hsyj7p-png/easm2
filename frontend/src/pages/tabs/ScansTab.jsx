import { useState, useRef, useEffect } from "react";
import { T, TOOL_COLOR } from "../../theme";
import { useApp } from "../../context/AppContext";

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
                color:T.text2, background:T.bg3, border:`1px solid ${T.border}`,
                padding:"1px 6px", borderRadius:3 }}>{tag}</span>
            ))}
          </div>
        </div>
      </div>
    ))}
  </div>
);

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

const histScans = [
  { label:"2026-05-05 08:03 — Full Scan", status:"completed", time:"202s", tags:["35 findings","score: 48","2 MCP CRITICAL"] },
  { label:"2026-05-04 08:00 — Full Scan", status:"completed", time:"198s", tags:["31 findings","score: 52"] },
  { label:"2026-05-03 14:22 — MCP Only",  status:"completed", time:"34s",  tags:["3 findings","1 CRITICAL"] },
  { label:"2026-05-03 08:00 — Full Scan", status:"completed", time:"207s", tags:["28 findings","score: 55"] },
  { label:"2026-05-02 08:00 — Full Scan", status:"completed", time:"195s", tags:["26 findings","score: 57"] },
];

const ScansTab = () => {
  const { tenant, triggerScan } = useApp();
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState(-1);
  const [logs, setLogs] = useState([]);
  const logRef = useRef(null);

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

  return (
    <div style={{ display:"grid", gridTemplateColumns:"1fr 360px", gap:16, alignItems:"flex-start" }}>
      <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
        {/* Scan control */}
        <div style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:6, padding:20 }}>
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
        <div style={{ background:T.bg0, border:`1px solid ${T.border}`, borderRadius:6, overflow:"hidden" }}>
          <div style={{ padding:"8px 16px", borderBottom:`1px solid ${T.border}`, background:T.bg2,
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
        <div style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:6, padding:20 }}>
          <div style={{ fontFamily:"'IBM Plex Sans',sans-serif", fontSize:13, fontWeight:600, color:T.text0, marginBottom:14 }}>Scan History</div>
          <ScanTimeline scans={histScans} />
        </div>
        <div style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:6, padding:16 }}>
          <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3, letterSpacing:"0.08em", marginBottom:12 }}>TOOL BREAKDOWN — LAST SCAN</div>
          {Object.entries(tenant?.tool_stats||{}).map(([tool, stats]) => (
            <div key={tool} style={{ display:"flex", alignItems:"center", gap:10, marginBottom:10, paddingBottom:10, borderBottom:`1px solid ${T.border}` }}>
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

export default ScansTab;
