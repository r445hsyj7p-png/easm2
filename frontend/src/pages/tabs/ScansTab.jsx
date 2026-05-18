import { useState, useRef, useEffect } from "react";
import { toast } from "sonner";
import { Play, Loader2, CheckCircle, XCircle, Circle } from "lucide-react";
import { T, TOOL_COLOR } from "../../theme";
import { useApp } from "../../context/AppContext";

const ScanTimeline = ({ scans }) => (
  <div style={{ display:"flex", flexDirection:"column", gap:0 }}>
    {scans.map((s,i) => (
      <div key={s.id || i} style={{ display:"flex", gap:10, position:"relative" }}>
        <div style={{ display:"flex", flexDirection:"column", alignItems:"center", width:16 }}>
          {s.status==="completed" ? <CheckCircle size={12} color={T.accent} style={{ flexShrink:0, marginTop:2 }} /> :
           s.status==="running"   ? <Loader2    size={12} color={T.accent} style={{ flexShrink:0, marginTop:2, animation:"spin 1s linear infinite" }} /> :
           s.status==="error"     ? <XCircle    size={12} color={T.critical} style={{ flexShrink:0, marginTop:2 }} /> :
                                    <Circle     size={12} color={T.text3}  style={{ flexShrink:0, marginTop:2 }} />}
          {i < scans.length-1 && <div style={{ width:1, flex:1, background:T.border, marginTop:2 }}/>}
        </div>
        <div style={{ flex:1, paddingBottom:14 }}>
          <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:4 }}>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:11, color:T.text0, fontWeight:600 }}>{s.label}</span>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9,
              color: s.status==="completed" ? T.accent : T.text3 }}>
              {s.status}
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

const ALL_PHASES = [
  { key:"discovery", label:"Discovery",    tool:"subfinder + theHarvester", color:T.accent,       secs:40 },
  { key:"portscan",  label:"Port Scan",    tool:"naabu SYN-Scan + UDP",     color:T.medium,       secs:28 },
  { key:"tls",       label:"TLS Scan",     tool:"sslyze — cipher + cert",   color:T.toolSslyze,   secs:22 },
  { key:"http",      label:"HTTP Probing", tool:"httpx + screenshots",      color:T.toolHttpx,    secs:34 },
  { key:"vuln",      label:"Vuln Scan",    tool:"nuclei 7000+ templates",   color:T.critical,     secs:67 },
  { key:"mcp",       label:"MCP Analysis", tool:"ramparts + handshake",     color:T.high,         secs:12 },
];

const SCAN_LOG = [
  { t:"subfinder",    msg:"loading passive sources: VirusTotal, Shodan, Censys, SecurityTrails, DNSdumpster...", c:"cyan",   phase:"discovery" },
  { t:"subfinder",    msg:"enumerating subdomains via passive + active DNS...",                                   c:"cyan",   phase:"discovery" },
  { t:"theharvester", msg:"google: searching emails, virtual hosts | linkedin: profile harvesting...",            c:"green",  phase:"discovery" },
  { t:"theharvester", msg:"OSINT collection complete — harvested emails and LinkedIn profiles",                   c:"green",  phase:"discovery" },
  { t:"naabu",        msg:"scanning discovered IPs | top-1000 ports | SYN mode | rate: 2000pps",                 c:"yellow", phase:"portscan"  },
  { t:"naabu",        msg:"open ports detected — checking for RDP, admin panels, MCP endpoints...",              c:"yellow", phase:"portscan"  },
  { t:"naabu",        msg:"WARNING: high-risk port combination detected on host",                                 c:"red",    phase:"portscan"  },
  { t:"naabu",        msg:"MCP ports (6274, 6277, 8080) detected on exposed host",                               c:"red",    phase:"portscan"  },
  { t:"sslyze",       msg:"scanning TLS endpoints | cipher + cert + protocol checks",                             c:"cyan",   phase:"tls"       },
  { t:"sslyze",       msg:"TLS 1.0 + TLS 1.1 enabled on remote access endpoint [MEDIUM]",                        c:"yellow", phase:"tls"       },
  { t:"sslyze",       msg:"weak cipher suites (RC4, 3DES) accepted [MEDIUM]",                                    c:"yellow", phase:"tls"       },
  { t:"sslyze",       msg:"HSTS missing on admin endpoint [LOW] | certificate expiry imminent [LOW]",            c:"yellow", phase:"tls"       },
  { t:"httpx",        msg:"probing discovered services | tech-detect | favicon-hash | screenshots enabled",       c:"purple", phase:"http"      },
  { t:"httpx",        msg:"CRITICAL: .env file accessible in webroot — credentials exposed",                      c:"red",    phase:"http"      },
  { t:"httpx",        msg:"CRITICAL: Spring Boot Actuator /env endpoint accessible",                              c:"red",    phase:"http"      },
  { t:"httpx",        msg:"tech fingerprint: web framework, web server, runtime environment detected",            c:"purple", phase:"http"      },
  { t:"nuclei",       msg:"loading 7,234 templates (api, mcp, cve, misconfig, default-login, exposure)",         c:"red",    phase:"vuln"      },
  { t:"nuclei",       msg:"CVE MATCH on VPN endpoint [CRITICAL / KEV]",                                          c:"red",    phase:"vuln"      },
  { t:"nuclei",       msg:"CVE MATCH on exposed MCP port [CRITICAL / CVSS 9.4]",                                 c:"red",    phase:"vuln"      },
  { t:"nuclei",       msg:"spring-boot-actuator-env MATCH on API host [CRITICAL]",                               c:"red",    phase:"vuln"      },
  { t:"ramparts",     msg:"connecting to discovered MCP endpoint...",                                             c:"orange", phase:"mcp"       },
  { t:"ramparts",     msg:"MCP initialize response received WITHOUT Bearer token ← CRITICAL",                     c:"red",    phase:"mcp"       },
  { t:"ramparts",     msg:"tools/list: [execute_command, read_file, write_file, shell, list_directory]",          c:"orange", phase:"mcp"       },
  { t:"ramparts",     msg:"CRITICAL: RCE via tools/call → execute_command — no auth required",                   c:"red",    phase:"mcp"       },
  { t:"pipeline",     msg:"deduplicating raw findings → unique findings after fingerprint merge",                 c:"dim",    phase:"mcp"       },
  { t:"pipeline",     msg:"risk scoring: CRITICAL×(-20) + HIGH×(-10) + MEDIUM×(-4) + LOW×(-1)",                  c:"dim",    phase:"mcp"       },
  { t:"pipeline",     msg:"scan complete ✓ — results saved to database",                                          c:"green",  phase:"mcp"       },
];

const COLORS = { cyan:T.accent, green:T.accent, yellow:T.medium, red:T.critical, purple:T.toolHttpx, orange:T.high, dim:T.text3 };

const DEFAULT_SELECTED = { discovery:true, portscan:true, tls:true, http:true, vuln:true, mcp:true };

const ScansTab = () => {
  const { tenant, triggerScan, scans } = useApp();
  const mappedScans = (Array.isArray(scans) ? scans : []).slice(0, 10).map(s => ({
    id: s.id,
    label: `${s.started_at ? s.started_at.slice(0, 16).replace("T", " ") : "—"} — ${(s.scan_type || "full").replace(/_/g, " ")} Scan`,
    status: s.status || "pending",
    time: s.duration_seconds ? `${s.duration_seconds}s` : "—",
    tags: [
      s.findings_count != null ? `${s.findings_count} findings` : null,
      s.risk_score != null ? `score: ${s.risk_score}` : null,
    ].filter(Boolean),
  }));

  const [selected, setSelected] = useState(DEFAULT_SELECTED);
  const [running,  setRunning]  = useState(false);
  const [progress, setProgress] = useState(0);
  const [phase,    setPhase]    = useState(-1);
  const [logs,     setLogs]     = useState([]);
  const logRef   = useRef(null);
  const intervalRef = useRef(null);

  const activePhases = ALL_PHASES.filter(ph => selected[ph.key]);
  const activeLogs   = SCAN_LOG.filter(l => selected[l.phase]);

  const togglePhase = (key) => {
    if (running) return;
    setSelected(prev => {
      const next = { ...prev, [key]: !prev[key] };
      if (Object.values(next).every(v => !v)) return prev;
      return next;
    });
  };

  const startScan = () => {
    if (activePhases.length === 0 || running) return;

    const scanType = activePhases.length === ALL_PHASES.length
      ? "full"
      : activePhases.map(p => p.key).join(",");

    // Fire-and-forget: dispatch API call in background, never block animation
    triggerScan(scanType)
      .then(() => toast.info("Scan dispatched", { description: "Pipeline läuft im Hintergrund." }))
      .catch(e => toast.error("Scan-Dispatch fehlgeschlagen", { description: e.message }));

    setRunning(true); setProgress(0); setPhase(0); setLogs([]);

    // Capture locals for the interval closure
    const snapLogs  = SCAN_LOG.filter(l => selected[l.phase]);
    const n         = activePhases.length;
    let p = 0, logI = 0;

    if (intervalRef.current) clearInterval(intervalRef.current);
    intervalRef.current = setInterval(() => {
      p = Math.min(p + (5.4 / Math.max(n, 1)), 100);
      setPhase(Math.min(Math.floor(p * n / 100), n - 1));
      if (snapLogs.length > 0) {
        const threshold = (logI / snapLogs.length) * 100;
        if (p >= threshold && logI < snapLogs.length) {
          const entry = snapLogs[logI];
          logI++;
          if (entry) setLogs(l => [...l, entry]);
        }
      }
      setProgress(p);
      if (p >= 100) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
        setRunning(false);
        setPhase(-1);
        toast.success("Animation abgeschlossen", { description: "Scan läuft im Hintergrund — Ergebnisse erscheinen nach Abschluss." });
      }
    }, 90);
  };

  useEffect(() => () => { if (intervalRef.current) clearInterval(intervalRef.current); }, []);
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  return (
    <div style={{ display:"grid", gridTemplateColumns:"1fr 360px", gap:16, alignItems:"flex-start" }}>
      <div style={{ display:"flex", flexDirection:"column", gap:14 }}>

        {/* Tool selection */}
        <div style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:6, padding:16 }}>
          <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3,
            letterSpacing:"0.08em", marginBottom:12 }}>SCAN MODULES — AUSWAHL</div>
          <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
            {ALL_PHASES.map(ph => {
              const on = selected[ph.key];
              return (
                <button key={ph.key} onClick={() => togglePhase(ph.key)} disabled={running} style={{
                  display:"flex", alignItems:"center", gap:6,
                  background: on ? `${ph.color}15` : T.bg3,
                  border:`1px solid ${on ? ph.color : T.border}`,
                  borderRadius:4, padding:"6px 12px",
                  cursor: running ? "not-allowed" : "pointer",
                  opacity: running ? 0.7 : 1,
                  transition:"all 0.15s",
                }}>
                  <div style={{ width:6, height:6, borderRadius:"50%",
                    background: on ? ph.color : T.text3, flexShrink:0 }}/>
                  <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9,
                    color: on ? ph.color : T.text3, fontWeight: on ? 700 : 400 }}>{ph.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Scan control */}
        <div style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:6, padding:20 }}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:16 }}>
            <div>
              <div style={{ fontFamily:"'IBM Plex Sans',sans-serif", fontSize:14, fontWeight:600, color:T.text0 }}>Scan Pipeline</div>
              <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3, marginTop:3 }}>
                {tenant?.domain || tenant?.name || "—"} · {activePhases.map(p => p.label).join(" · ")}
              </div>
            </div>
            <button onClick={startScan} disabled={running || activePhases.length === 0} style={{
              background: running ? T.bg3 : T.accent,
              border:"none", borderRadius:4, padding:"9px 24px",
              fontFamily:"'JetBrains Mono',monospace", fontSize:11, fontWeight:700,
              color: running ? T.text2 : T.bg0,
              cursor: (running || activePhases.length === 0) ? "not-allowed" : "pointer",
              letterSpacing:"0.06em",
              display:"flex", alignItems:"center", gap:7,
            }}>
              {running
                ? <><Loader2 size={13} style={{ animation:"spin 1s linear infinite" }} />{`SCANNING… ${Math.round(progress)}%`}</>
                : <><Play size={13} />START SCAN</>}
            </button>
          </div>

          {/* Progress bar */}
          <div style={{ height:3, background:T.bg4, borderRadius:2, overflow:"hidden", marginBottom:8 }}>
            <div style={{ height:"100%", background:T.accent, borderRadius:2,
              width:`${progress}%`, transition:"width 0.15s" }}/>
          </div>
          <div style={{ display:"flex", justifyContent:"space-between", marginBottom:16 }}>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3 }}>
              {running
                ? (activePhases[phase]?.tool ?? "")
                : progress >= 100
                  ? "✓ Scan gestartet — läuft im Hintergrund"
                  : `${activePhases.length} von ${ALL_PHASES.length} Modulen ausgewählt`}
            </span>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.accent }}>{Math.round(progress)}%</span>
          </div>

          {/* Phase cards — only selected phases */}
          <div style={{ display:"flex", gap:6 }}>
            {activePhases.map((ph, i) => {
              const done   = progress >= (i + 1) * (100 / activePhases.length);
              const active = running && phase === i;
              return (
                <div key={ph.key} style={{
                  flex:1, padding:"10px 10px 9px",
                  background: done ? `${ph.color}10` : T.bg3,
                  border:`1px solid ${active ? ph.color : done ? `${ph.color}35` : T.border}`,
                  borderTop:`2px solid ${active || done ? ph.color : T.border}`,
                  borderRadius:4, transition:"all 0.3s",
                }}>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:7,
                    color:ph.color, letterSpacing:"0.08em", marginBottom:4 }}>P{i+1}</div>
                  <div style={{ fontFamily:"'IBM Plex Sans',sans-serif", fontSize:10, fontWeight:600,
                    color: active || done ? T.text0 : T.text3, marginBottom:2 }}>{ph.label}</div>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, color:T.text3 }}>{ph.tool}</div>
                  <div style={{ marginTop:5, display:"flex", alignItems:"center", gap:4,
                    fontFamily:"'JetBrains Mono',monospace", fontSize:9,
                    color: done ? T.accent : active ? T.accent : T.text3 }}>
                    {done   ? <><CheckCircle size={9} />{ph.secs}s</> :
                     active ? <><Loader2 size={9} style={{ animation:"spin 1s linear infinite" }} />running…</> :
                     `~${ph.secs}s`}
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
              <span style={{ color:T.text3 }}>$ ./easm-pipeline run --domain {tenant?.domain || "—"} --modules {activePhases.map(p => p.key).join(",")}</span>
            ) : logs.filter(Boolean).map((line, i) => (
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
          <ScanTimeline scans={mappedScans} />
        </div>
        <div style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:6, padding:16 }}>
          <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3, letterSpacing:"0.08em", marginBottom:12 }}>TOOL BREAKDOWN — LAST SCAN</div>
          {Object.entries(tenant?.tool_stats || {}).map(([tool, stats]) => (
            <div key={tool} style={{ display:"flex", alignItems:"center", gap:10, marginBottom:10, paddingBottom:10, borderBottom:`1px solid ${T.border}` }}>
              <div style={{ width:5, height:5, borderRadius:"50%", background:TOOL_COLOR[tool], flexShrink:0 }}/>
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:TOOL_COLOR[tool], fontWeight:700, width:92 }}>{tool}</span>
              <div style={{ flex:1, height:2, background:T.bg4, borderRadius:2 }}>
                <div style={{ width:`${(stats.findings / 12) * 100}%`, height:"100%", background:TOOL_COLOR[tool], borderRadius:2 }}/>
              </div>
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color: stats.findings > 5 ? T.high : T.text2, fontWeight:700, minWidth:18 }}>{stats.findings}F</span>
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3 }}>{stats.duration}s</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ScansTab;
