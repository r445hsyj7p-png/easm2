import { useState } from "react";
import { T, SEV } from "../../theme";
import { Sev, Tag, Pill, TH, TD, SectionHeader } from "../../components/ui/index";
import { useApp } from "../../context/AppContext";
import { DonutChart, GeoMiniMap, IntelAssetGraph } from "./AssetsTab";

const SUB_TABS = [
  {id:"hosting",  label:"Hosting Analysis"},
  {id:"geomap",   label:"Geo Distribution"},
  {id:"graph",    label:"Asset Graph"},
  {id:"fqdn",     label:"FQDN Inventory"},
  {id:"threat",   label:"Threat Intelligence"},
];

const SEV_ORD = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};

const IntelTab = () => {
  const { intel, findings } = useApp();
  const [sub, setSub] = useState("hosting");
  const [fqdnSearch, setFqdnSearch] = useState("");
  const [fqdnSev, setFqdnSev] = useState("ALL");
  const [fqdnOrg, setFqdnOrg] = useState(null);
  const [fqdnSort, setFqdnSort] = useState({col:"risk",dir:"asc"});

  const filteredFqdn = (intel?.fqdn_table||[])
    .filter(r=>
      (fqdnSev==="ALL"||r.risk===fqdnSev)&&
      (fqdnOrg===null||r.org===fqdnOrg)&&
      (!fqdnSearch||r.fqdn.includes(fqdnSearch)||r.ip.includes(fqdnSearch)||
        (r.org||"").toLowerCase().includes(fqdnSearch.toLowerCase())||String(r.asn).includes(fqdnSearch))
    )
    .sort((a,b)=>{
      let c=0;
      if(fqdnSort.col==="risk") c=(SEV_ORD[a.risk]||4)-(SEV_ORD[b.risk]||4);
      else if(fqdnSort.col==="fqdn") c=(a.fqdn||"").localeCompare(b.fqdn||"");
      else if(fqdnSort.col==="asn") c=(a.asn||0)-(b.asn||0);
      else if(fqdnSort.col==="org") c=(a.org||"").localeCompare(b.org||"");
      return fqdnSort.dir==="asc"?c:-c;
    });

  const fqdnCount = (intel?.fqdn_table||[]).length;

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
          }}>{t.id==="fqdn" ? `FQDN Inventory (${fqdnCount})` : t.label}</button>
        ))}
      </div>

      {/* ── Hosting Analysis ── */}
      {sub==="hosting"&&(
        <div style={{display:"grid",gridTemplateColumns:"280px 1fr",gap:16,alignItems:"flex-start"}}>
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
              assets={intel?.geo_assets || []}
              height={300}
            />
          </div>
          <div style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:6,overflow:"hidden"}}>
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead><tr><TH>City</TH><TH>Country</TH><TH right>IPs</TH><TH>Risk</TH><TH>Coordinates</TH></tr></thead>
              <tbody>
                {(intel?.geo_assets||[]).length === 0 ? (
                  <tr><td colSpan={5} style={{padding:"20px",textAlign:"center",fontFamily:T.font,fontSize:11,color:T.text3}}>Keine Geo-Daten — nach dem ersten Scan verfügbar</td></tr>
                ) : (intel?.geo_assets||[]).map((a,i)=>(
                  <tr key={i} style={{transition:"background 0.1s"}}
                    onMouseEnter={e=>e.currentTarget.style.background=T.bg3}
                    onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                    <TD><span style={{fontFamily:T.font,fontSize:11,color:T.accent}}>{a.city}</span></TD>
                    <TD><Tag label={a.country}/></TD>
                    <TD right><span style={{fontFamily:T.font,fontSize:11,fontWeight:700,color:T.text0}}>{a.ip_count}</span></TD>
                    <TD><Sev s={a.risk} small/></TD>
                    <TD mono muted>{a.lat?.toFixed(2)}, {a.lng?.toFixed(2)}</TD>
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
              {filteredFqdn.length} / {fqdnCount}
            </span>
          </div>
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

      {/* ── Threat Intelligence ── */}
      {sub==="threat"&&(
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
          <div style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:6,padding:20,gridColumn:"1/-1"}}>
            <SectionHeader sub="OSINT + HIBP + Stealer-Log correlation">Credential Intelligence</SectionHeader>
            {!(intel?.credential_intel) ? (
              <div style={{padding:"20px 0",textAlign:"center",fontFamily:T.font,fontSize:11,color:T.text3}}>Keine Credential-Daten — nach dem ersten HIBP-Check verfügbar</div>
            ) : (
              <>
                <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:16}}>
                  {[
                    {label:"Emails Harvested", value:intel.credential_intel.emails_found||0,    color:T.accent,    tool:"theHarvester"},
                    {label:"In Breach DBs",    value:intel.credential_intel.breached_count||0,  color:T.high,      tool:"HIBP"},
                    {label:"Stealer Logs",     value:intel.credential_intel.stealer_logs||0,    color:T.critical,  tool:"HIBP Pro"},
                    {label:"LinkedIn Exposed", value:intel.credential_intel.linkedin_count||0,  color:T.toolHttpx, tool:"theHarvester"},
                  ].map(k=>(
                    <div key={k.label} style={{background:T.bg3,border:`1px solid ${T.border}`,borderRadius:4,padding:"12px 14px"}}>
                      <div style={{fontFamily:T.font,fontSize:9,color:T.text3,marginBottom:5}}>{k.label}</div>
                      <div style={{fontFamily:T.font,fontSize:22,fontWeight:700,color:k.color}}>{k.value}</div>
                      <Pill label={k.tool} color={k.color}/>
                    </div>
                  ))}
                </div>
                {(intel.credential_intel.sample_emails||[]).length > 0 && (
                  <div style={{background:T.bg3,border:`1px solid ${T.border}`,borderRadius:4,padding:"10px 14px"}}>
                    <div style={{fontFamily:T.font,fontSize:9,color:T.text3,marginBottom:8,letterSpacing:"0.06em"}}>SAMPLE HARVESTED EMAILS (anonymized)</div>
                    <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                      {(intel.credential_intel.sample_emails||[]).map(e=>(
                        <Tag key={e} label={e} color={T.accent} bg={`${T.accent}08`} border={`${T.accent}25`}/>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
          <div style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:6,padding:20}}>
            <SectionHeader sub="EPSS · CISA KEV · Public Exploits">Exploit Intelligence</SectionHeader>
            {(findings||[]).filter(f=>f.cve).map(f=>(
              <div key={f.id} style={{display:"flex",gap:10,alignItems:"flex-start",marginBottom:12,paddingBottom:12,borderBottom:`1px solid ${T.border}`}}>
                <Sev s={f.sev} small/>
                <div style={{flex:1}}>
                  <div style={{fontFamily:T.font,fontSize:10,color:T.critical,marginBottom:2}}>{f.cve}</div>
                  <div style={{fontFamily:T.fontSans,fontSize:11,color:T.text1}}>{(f.title||"").split("—")[1]?.trim()||(f.title||"")}</div>
                </div>
                <div style={{textAlign:"right",flexShrink:0}}>
                  <div style={{fontFamily:T.font,fontSize:11,fontWeight:700,color:(f.cvss||0)>=9?T.red:T.high}}>{(f.cvss||0).toFixed(1)}</div>
                  {f.kev&&<Tag label="KEV" color={T.red} bg={`${T.critical}12`} border={`${T.critical}40`}/>}
                  {f.epss&&f.epss!=="—"&&<div style={{fontFamily:T.font,fontSize:9,color:T.text2,marginTop:3}}>EPSS {f.epss}</div>}
                </div>
              </div>
            ))}
          </div>
          <div style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:6,padding:20}}>
            <SectionHeader sub="Typosquatting · Phishing lookalikes · Mentions">Dark Web &amp; Threat Intel</SectionHeader>
            {!(intel?.dark_web) || (intel.dark_web||[]).length === 0 ? (
              <div style={{padding:"20px 0",textAlign:"center",fontFamily:T.font,fontSize:11,color:T.text3}}>Keine Dark-Web-Daten — nach dem ersten Threat-Intel-Check verfügbar</div>
            ) : (intel.dark_web||[]).map((row,i)=>(
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

export default IntelTab;
