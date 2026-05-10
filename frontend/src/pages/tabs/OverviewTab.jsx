import { useState } from "react";
import { T, SEV } from "../../theme";
import { KPI, ScoreBar, Card, CardHeader, Sev, Tag, Pill } from "../ui/index";
import { useApp } from "../../context/AppContext";
import { EFFORT_COLOR, buildRemediations } from "../../utils/remediations";

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

const OverviewDashboard = ({ setTab, tenant, findings, intel, total, setSub }) => {
  const { triggerScan } = useApp();
  const SS = { CRITICAL:10, HIGH:7, MEDIUM:4, LOW:1, INFO:0 };
  const openF = (findings||[]).filter(f => f.status === "open");
  const critCount = (findings||[]).filter(f => f.sev === "CRITICAL" && f.status === "open").length;
  const kevCount  = (findings||[]).filter(f => f.kev && f.status === "open").length;
  const scoreColor = (tenant.score||0) >= 70 ? T.accent : (tenant.score||0) >= 40 ? T.medium : T.critical;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* KPI row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10 }}>
        <KPI label="Risk Score" value={tenant.score ?? "—"} color={scoreColor}
          sub={`Grade ${tenant.grade || "?"}`} />
        <KPI label="Open Findings" value={openF.length} color={T.text0}
          sub={`${total} total`} onClick={() => setTab("findings")} />
        <KPI label="Critical" value={critCount} color={T.critical}
          onClick={() => setTab("findings")} />
        <KPI label="KEV Findings" value={kevCount} color={T.red}
          sub="CISA Known Exploited" onClick={() => setTab("findings")} />
        <KPI label="Assets" value={(tenant.assets?.subdomains||0)} color={T.accent}
          sub={`${tenant.assets?.ips||0} IPs · ${tenant.assets?.ports||0} ports`}
          onClick={() => setTab("assets")} />
      </div>

      {/* Severity breakdown */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, padding: 20 }}>
          <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0, marginBottom: 14 }}>
            Findings by Severity
          </div>
          {["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(sev => {
            const count = (findings||[]).filter(f => f.sev === sev && f.status === "open").length;
            const maxCount = Math.max(...["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(s =>
              (findings||[]).filter(f => f.sev === s && f.status === "open").length), 1);
            const sc = SEV[sev];
            return (
              <div key={sev} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}
                onClick={() => setTab("findings")} style={{ cursor: "pointer", display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                <Sev s={sev} small />
                <div style={{ flex: 1, height: 4, background: T.bg4, borderRadius: 2, overflow: "hidden" }}>
                  <div style={{ width: `${(count/maxCount)*100}%`, height: "100%", background: sc.color, borderRadius: 2 }} />
                </div>
                <span style={{ fontFamily: T.font, fontSize: 11, color: sc.color, fontWeight: 700, minWidth: 20 }}>{count}</span>
              </div>
            );
          })}
        </div>

        <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, padding: 20 }}>
          <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0, marginBottom: 14 }}>
            Quick Actions
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <button onClick={() => setTab("findings")} style={{
              background: T.bg3, border: `1px solid ${T.border}`, borderRadius: 4,
              padding: "10px 14px", fontFamily: T.fontSans, fontSize: 12, color: T.text1,
              cursor: "pointer", textAlign: "left", display: "flex", justifyContent: "space-between", alignItems: "center",
            }}>
              <span>View all findings</span>
              <span style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>→</span>
            </button>
            <button onClick={() => setSub("remediation")} style={{
              background: `${T.accent}10`, border: `1px solid ${T.accent}30`, borderRadius: 4,
              padding: "10px 14px", fontFamily: T.fontSans, fontSize: 12, color: T.accent,
              cursor: "pointer", textAlign: "left", display: "flex", justifyContent: "space-between", alignItems: "center",
            }}>
              <span>Remediation Roadmap</span>
              <span style={{ fontFamily: T.font, fontSize: 9, color: T.accent }}>→</span>
            </button>
            <button onClick={() => triggerScan("full")} style={{
              background: T.bg3, border: `1px solid ${T.border}`, borderRadius: 4,
              padding: "10px 14px", fontFamily: T.fontSans, fontSize: 12, color: T.text1,
              cursor: "pointer", textAlign: "left", display: "flex", justifyContent: "space-between", alignItems: "center",
            }}>
              <span>Start new scan</span>
              <span style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>↺</span>
            </button>
            <button onClick={() => setTab("mcp")} style={{
              background: `${T.critical}08`, border: `1px solid ${T.critical}30`, borderRadius: 4,
              padding: "10px 14px", fontFamily: T.fontSans, fontSize: 12, color: T.critical,
              cursor: "pointer", textAlign: "left", display: "flex", justifyContent: "space-between", alignItems: "center",
            }}>
              <span>MCP Exposure</span>
              <span style={{ fontFamily: T.font, fontSize: 9, color: T.critical }}>→</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

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

export default OverviewTab;
