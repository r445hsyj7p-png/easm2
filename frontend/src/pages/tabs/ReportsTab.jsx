import { useState } from "react";
import { T } from "../../theme";

const SCORE_HIST = [68,64,59,62,57,55,48];
const MONTHS = ["Nov","Dez","Jan","Feb","Mär","Apr","Mai"];

const REPORTS = [
  { id:"exec",  title:"Executive Summary",     fmt:"PDF", pages:"4–6",   desc:"High-level risk overview for management — score, grade, critical findings, trend.",
    items:["Risk score & grade","Critical findings summary","Score trend (6 months)","Top 5 action items"] },
  { id:"tech",  title:"Technical Report",       fmt:"PDF", pages:"20–40", desc:"Full finding list with CVSS, EPSS, KEV, asset details and remediation steps.",
    items:["All findings with context","CVSS / EPSS / KEV enrichment","Asset inventory","Per-tool breakdown"] },
  { id:"mcp",   title:"MCP Exposure Report",    fmt:"PDF", pages:"8–12",  desc:"Dedicated MCP server exposure report — attack chains, tool inventory, remediation.",
    items:["All MCP servers found","Exposed tool inventory","Attack chain walkthrough","Remediation checklist"] },
  { id:"nis2",  title:"NIS2 Compliance Report", fmt:"PDF", pages:"15–25", desc:"Maps findings to NIS2 obligations for critical infrastructure operators.",
    items:["NIS2 Article mapping","Gap analysis","Remediation timeline","Evidence collection"] },
  { id:"csv",   title:"Findings CSV Export",    fmt:"CSV", pages:"—",     desc:"Raw findings for SIEM ingestion, ticketing systems or custom analysis.",
    items:["All findings","All metadata fields","Tool attribution","Asset details"] },
  { id:"json",  title:"API / JSON Export",      fmt:"JSON",pages:"—",     desc:"Machine-readable findings for Splunk, XSOAR, Jira, custom integrations.",
    items:["Full pipeline data","Raw tool output","Risk scores","Timestamp metadata"] },
];

const fmtColor = { PDF:T.critical, CSV:T.accent, JSON:T.accent };

const ReportsTab = () => {
  const [generating, setGenerating] = useState(null);
  const [done, setDone] = useState({});

  const generate = (id) => {
    setGenerating(id);
    setTimeout(() => { setGenerating(null); setDone(d => ({...d,[id]:true})); }, 1800);
  };

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      {/* Score trend */}
      <div style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:6, padding:20 }}>
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
          <div key={r.id} style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:6, padding:18, display:"flex", flexDirection:"column" }}>
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

export default ReportsTab;
