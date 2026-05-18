import { useState, useRef, useEffect, useCallback } from "react";
import { toast } from "sonner";
import { Play, Loader2, CheckCircle, XCircle, Circle, AlertTriangle } from "lucide-react";
import { T, TOOL_COLOR } from "../../theme";
import { useApp } from "../../context/AppContext";
import { apiFetch } from "../../api/client";

const ScanTimeline = ({ scans }) => (
  <div style={{ display:"flex", flexDirection:"column", gap:0 }}>
    {scans.map((s,i) => (
      <div key={s.id || i} style={{ display:"flex", gap:10, position:"relative" }}>
        <div style={{ display:"flex", flexDirection:"column", alignItems:"center", width:16 }}>
          {s.status==="completed" ? <CheckCircle size={12} color={T.accent}    style={{ flexShrink:0, marginTop:2 }} /> :
           s.status==="running"   ? <Loader2    size={12} color={T.accent}    style={{ flexShrink:0, marginTop:2, animation:"spin 1s linear infinite" }} /> :
           s.status==="error"     ? <XCircle    size={12} color={T.critical}  style={{ flexShrink:0, marginTop:2 }} /> :
                                    <Circle     size={12} color={T.text3}     style={{ flexShrink:0, marginTop:2 }} />}
          {i < scans.length-1 && <div style={{ width:1, flex:1, background:T.border, marginTop:2 }}/>}
        </div>
        <div style={{ flex:1, paddingBottom:14 }}>
          <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:4 }}>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:11, color:T.text0, fontWeight:600 }}>{s.label}</span>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9,
              color: s.status==="completed" ? T.accent : s.status==="error" ? T.critical : T.text3 }}>
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
  { key:"discovery", label:"Discovery",    tool:"subfinder + theHarvester", color:T.accent,     pct:[0,20]  },
  { key:"portscan",  label:"Port Scan",    tool:"naabu SYN-Scan + UDP",     color:T.medium,     pct:[20,35] },
  { key:"tls",       label:"TLS Scan",     tool:"sslyze — cipher + cert",   color:T.toolSslyze, pct:[35,50] },
  { key:"http",      label:"HTTP Probing", tool:"httpx + screenshots",      color:T.toolHttpx,  pct:[50,70] },
  { key:"vuln",      label:"Vuln Scan",    tool:"nuclei 7000+ templates",   color:T.critical,   pct:[70,88] },
  { key:"mcp",       label:"MCP Analysis", tool:"ramparts + handshake",     color:T.high,       pct:[88,99] },
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

// Elapsed-time counter that ticks every second while a scan is active
function useElapsed(startedAt) {
  const [secs, setSecs] = useState(0);
  useEffect(() => {
    if (!startedAt) { setSecs(0); return; }
    const base = new Date(startedAt).getTime();
    const tick = () => setSecs(Math.floor((Date.now() - base) / 1000));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [startedAt]);
  return secs;
}

const ScansTab = () => {
  const { tenant, triggerScan, scans, tenantId, refresh } = useApp();

  const mappedScans = (Array.isArray(scans) ? scans : []).slice(0, 10).map(s => ({
    id: s.id,
    label: `${s.started_at ? s.started_at.slice(0, 16).replace("T", " ") : "—"} — ${(s.scan_type || "full").replace(/_/g, " ")} Scan`,
    status: s.status || "pending",
    time: s.duration_seconds ? `${s.duration_seconds}s` : "—",
    tags: [
      s.findings_count != null ? `${s.findings_count} findings` : null,
      s.risk_score     != null ? `score: ${s.risk_score}`       : null,
    ].filter(Boolean),
  }));

  const [selected,      setSelected]      = useState(DEFAULT_SELECTED);
  const [logs,          setLogs]          = useState([]);

  // Real scan tracking
  const [scanId,        setScanId]        = useState(null);
  const [scanStatus,    setScanStatus]    = useState(null); // full poll response
  const [scanStartedAt, setScanStartedAt] = useState(null);

  // Cosmetic animation (log drip only — progress driven by real data)
  const [cosmeticPhase, setCosmeticPhase] = useState(-1);
  const cosmeticRef = useRef(null);
  const pollRef     = useRef(null);
  const logRef      = useRef(null);

  const elapsed = useElapsed(scanStartedAt);

  // Derived display values
  const realPct = scanStatus?.progress_pct ?? 0;
  const displayPct = realPct;

  // Map backend current_phase name → local index in activePhases
  // (current_phase is a key like "discovery","portscan" etc. — look it up directly)
  const activePhaseKeys = ALL_PHASES.filter(ph => selected[ph.key]).map(ph => ph.key);
  const realPhaseLocalIdx = activePhaseKeys.indexOf(scanStatus?.current_phase ?? "");
  const displayPhaseIdx = cosmeticPhase >= 0 ? cosmeticPhase : realPhaseLocalIdx;

  const isActive   = scanStatus?.status === "running" || scanStatus?.status === "pending";
  const isDone     = scanStatus?.status === "completed";
  const isError    = scanStatus?.status === "error";

  const activePhases = ALL_PHASES.filter(ph => selected[ph.key]);

  const togglePhase = (key) => {
    if (isActive) return;
    setSelected(prev => {
      const next = { ...prev, [key]: !prev[key] };
      if (Object.values(next).every(v => !v)) return prev;
      return next;
    });
  };

  // Poll scan status
  const startPolling = useCallback((id) => {
    if (pollRef.current) clearInterval(pollRef.current);

    const poll = async () => {
      try {
        const data = await apiFetch(`/tenants/${tenantId}/scans/${id}`);
        setScanStatus(data);
        if (data.started_at) setScanStartedAt(data.started_at);

        if (data.status === "completed") {
          clearInterval(pollRef.current); pollRef.current = null;
          if (cosmeticRef.current) { clearInterval(cosmeticRef.current); cosmeticRef.current = null; }
          setCosmeticPhase(-1);
          const cnt   = data.findings_count ?? "—";
          const score = data.risk_score     ?? "—";
          const dur   = data.duration_seconds ? `${data.duration_seconds}s` : "";
          toast.success(`Scan abgeschlossen ${dur ? `(${dur})` : ""}`, {
            description: `${cnt} Findings · Risk Score: ${score}`,
            duration: 10000,
          });
          refresh();
        } else if (data.status === "error") {
          clearInterval(pollRef.current); pollRef.current = null;
          if (cosmeticRef.current) { clearInterval(cosmeticRef.current); cosmeticRef.current = null; }
          setCosmeticPhase(-1);
          toast.error("Scan fehlgeschlagen", { description: data.error_message || "Unbekannter Fehler" });
        }
      } catch {
        // ignore transient poll errors
      }
    };

    poll();
    pollRef.current = setInterval(poll, 5000);
  }, [tenantId, refresh]);

  // Cosmetic log drip — independent of real progress
  const startCosmeticLog = useCallback((sel) => {
    const snapLogs = SCAN_LOG.filter(l => sel[l.phase]);
    const n = ALL_PHASES.filter(ph => sel[ph.key]).length;
    let p = 0, logI = 0;
    if (cosmeticRef.current) clearInterval(cosmeticRef.current);
    cosmeticRef.current = setInterval(() => {
      p = Math.min(p + (5.4 / Math.max(n, 1)), 100);
      setCosmeticPhase(Math.min(Math.floor(p * n / 100), n - 1));
      if (snapLogs.length > 0) {
        const threshold = (logI / snapLogs.length) * 100;
        if (p >= threshold && logI < snapLogs.length) {
          const entry = snapLogs[logI]; logI++;
          if (entry) setLogs(l => [...l, entry]);
        }
      }
      if (p >= 100) {
        clearInterval(cosmeticRef.current); cosmeticRef.current = null;
        setCosmeticPhase(-1);
      }
    }, 90);
  }, []);

  const startScan = async () => {
    if (isActive || activePhases.length === 0) return;

    const scanType = activePhases.length === ALL_PHASES.length
      ? "full"
      : activePhases.map(p => p.key).join(",");

    // Optimistic UI
    setScanStatus({ status: "pending", progress_pct: 0, current_phase: "starting" });
    setScanStartedAt(new Date().toISOString());
    setLogs([]);
    setScanId(null);

    // Start cosmetic log animation
    startCosmeticLog(selected);

    try {
      const job = await triggerScan(scanType);
      setScanId(job.id);
      toast.info("Scan gestartet", { description: "Status wird alle 5s aktualisiert." });
      startPolling(job.id);
    } catch (e) {
      toast.error("Scan-Dispatch fehlgeschlagen", { description: e.message });
      if (cosmeticRef.current) { clearInterval(cosmeticRef.current); cosmeticRef.current = null; }
      setScanStatus(null);
      setScanStartedAt(null);
    }
  };

  useEffect(() => () => {
    clearInterval(cosmeticRef.current);
    clearInterval(pollRef.current);
  }, []);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  // findings_count may be a JSONB object {LOW,HIGH,...} from older rows — normalize to int
  const findingsCount = (() => {
    const fc = scanStatus?.findings_count;
    if (fc == null) return "—";
    if (typeof fc === "object") return Object.values(fc).reduce((a, b) => a + (Number(b) || 0), 0);
    return fc;
  })();

  // Status-bar text
  const statusText = () => {
    if (isDone)  return `✓ Abgeschlossen · ${findingsCount} Findings · Score: ${scanStatus?.risk_score ?? "—"}`;
    if (isError) return `✗ Fehler: ${scanStatus?.error_message || "Unbekannt"}`;
    if (isActive) {
      const phaseName = scanStatus?.current_phase || "";
      const ph = activePhases[displayPhaseIdx];
      return phaseName ? `[${phaseName}] ${ph?.tool ?? ""}` : (ph?.tool ?? "");
    }
    return `${activePhases.length} von ${ALL_PHASES.length} Modulen ausgewählt`;
  };

  // Progress bar color
  const barColor = isError ? T.critical : isDone ? T.accent : T.accent;

  return (
    <div style={{ display:"grid", gridTemplateColumns:"1fr 360px", gap:16, alignItems:"flex-start" }}>
      <div style={{ display:"flex", flexDirection:"column", gap:14 }}>

        {/* Module selection */}
        <div style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:6, padding:16 }}>
          <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3,
            letterSpacing:"0.08em", marginBottom:12 }}>SCAN MODULES — AUSWAHL</div>
          <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
            {ALL_PHASES.map(ph => {
              const on = selected[ph.key];
              return (
                <button key={ph.key} onClick={() => togglePhase(ph.key)} disabled={isActive} style={{
                  display:"flex", alignItems:"center", gap:6,
                  background: on ? `${ph.color}15` : T.bg3,
                  border:`1px solid ${on ? ph.color : T.border}`,
                  borderRadius:4, padding:"6px 12px",
                  cursor: isActive ? "not-allowed" : "pointer",
                  opacity: isActive ? 0.7 : 1,
                  transition:"all 0.15s",
                }}>
                  <div style={{ width:6, height:6, borderRadius:"50%", background: on ? ph.color : T.text3, flexShrink:0 }}/>
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
            <div style={{ display:"flex", alignItems:"center", gap:10 }}>
              {isActive && (
                <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:10, color:T.text2 }}>
                  {Math.floor(elapsed / 60)}:{String(elapsed % 60).padStart(2,"0")} elapsed
                </span>
              )}
              <button onClick={startScan} disabled={isActive || activePhases.length === 0} style={{
                background: isActive ? T.bg3 : T.accent,
                border:"none", borderRadius:4, padding:"9px 24px",
                fontFamily:"'JetBrains Mono',monospace", fontSize:11, fontWeight:700,
                color: isActive ? T.text2 : T.bg0,
                cursor: (isActive || activePhases.length === 0) ? "not-allowed" : "pointer",
                letterSpacing:"0.06em",
                display:"flex", alignItems:"center", gap:7,
              }}>
                {isActive
                  ? <><Loader2 size={13} style={{ animation:"spin 1s linear infinite" }} />SCANNING… {displayPct}%</>
                  : <><Play size={13} />START SCAN</>}
              </button>
            </div>
          </div>

          {/* Progress bar — driven by real backend progress_pct */}
          <div style={{ height:3, background:T.bg4, borderRadius:2, overflow:"hidden", marginBottom:8 }}>
            <div style={{ height:"100%", background: barColor, borderRadius:2,
              width:`${isDone ? 100 : displayPct}%`, transition:"width 0.6s ease" }}/>
          </div>
          <div style={{ display:"flex", justifyContent:"space-between", marginBottom:16 }}>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9,
              color: isError ? T.critical : T.text3, maxWidth:"80%" }}>
              {statusText()}
            </span>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color: isDone ? T.accent : T.accent }}>
              {isDone ? "100%" : `${displayPct}%`}
            </span>
          </div>

          {/* Phase cards */}
          <div style={{ display:"flex", gap:6 }}>
            {activePhases.map((ph, i) => {
              const done   = isDone || (displayPct >= ph.pct[1]);
              const active = isActive && displayPhaseIdx === i;
              return (
                <div key={ph.key} style={{
                  flex:1, padding:"10px 10px 9px",
                  background: done ? `${ph.color}10` : T.bg3,
                  border:`1px solid ${active ? ph.color : done ? `${ph.color}35` : T.border}`,
                  borderTop:`2px solid ${active || done ? ph.color : T.border}`,
                  borderRadius:4, transition:"all 0.4s",
                }}>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:7,
                    color:ph.color, letterSpacing:"0.08em", marginBottom:4 }}>P{i+1}</div>
                  <div style={{ fontFamily:"'IBM Plex Sans',sans-serif", fontSize:10, fontWeight:600,
                    color: active || done ? T.text0 : T.text3, marginBottom:2 }}>{ph.label}</div>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, color:T.text3 }}>{ph.tool}</div>
                  <div style={{ marginTop:5, display:"flex", alignItems:"center", gap:4,
                    fontFamily:"'JetBrains Mono',monospace", fontSize:9,
                    color: done ? T.accent : active ? T.accent : T.text3 }}>
                    {done   ? <><CheckCircle size={9} />done</> :
                     active ? <><Loader2 size={9} style={{ animation:"spin 1s linear infinite" }} />running…</> :
                     "pending"}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Final stats bar when done */}
          {isDone && scanStatus && (
            <div style={{ marginTop:12, display:"flex", gap:16, padding:"10px 14px",
              background:T.bg3, border:`1px solid ${T.accent}22`, borderRadius:4 }}>
              {[
                ["findings",      findingsCount],
                ["risk score",    scanStatus.risk_score ?? "—"],
                ["duration",      scanStatus.duration_seconds ? `${scanStatus.duration_seconds}s` : "—"],
              ].map(([label, val]) => (
                <div key={label}>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, color:T.text3, marginBottom:2 }}>{label.toUpperCase()}</div>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:13, fontWeight:700, color:T.accent }}>{val}</div>
                </div>
              ))}
            </div>
          )}

          {/* Error details */}
          {isError && (
            <div style={{ marginTop:12, display:"flex", alignItems:"center", gap:8, padding:"10px 14px",
              background:`${T.critical}10`, border:`1px solid ${T.critical}30`, borderRadius:4 }}>
              <AlertTriangle size={14} color={T.critical} />
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:10, color:T.critical }}>
                {scanStatus?.error_message || "Scan fehlgeschlagen"}
              </span>
            </div>
          )}
        </div>

        {/* Live log — cosmetic drip, labeled as such */}
        <div style={{ background:T.bg0, border:`1px solid ${T.border}`, borderRadius:6, overflow:"hidden" }}>
          <div style={{ padding:"8px 16px", borderBottom:`1px solid ${T.border}`, background:T.bg2,
            display:"flex", justifyContent:"space-between", alignItems:"center" }}>
            <div style={{ display:"flex", gap:6, alignItems:"center" }}>
              {["#ff5f56","#ffbd2e","#27c93f"].map((c,i) => (
                <div key={i} style={{ width:10, height:10, borderRadius:"50%", background:c, opacity:0.8 }}/>
              ))}
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3, marginLeft:6, letterSpacing:"0.08em" }}>
                SCAN LOG — SIMULIERTER OUTPUT
              </span>
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
                {i === logs.length-1 && isActive && <span style={{ animation:"pulse 0.7s infinite" }}> ▮</span>}
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
