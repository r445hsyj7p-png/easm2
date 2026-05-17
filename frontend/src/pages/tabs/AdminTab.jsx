import { useState } from "react";
import { toast } from "sonner";
import { T } from "../../theme";
import { Tag, TH, TD } from "../../components/ui/index";

const AdminTab = () => {
  const [section, setSection] = useState("domains");

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

  const [schedule, setSchedule] = useState({
    full_scan:    { enabled:true,  interval:"daily",  time:"08:00", days:"mon-fri" },
    mcp_scan:     { enabled:true,  interval:"daily",  time:"04:00", days:"all" },
    hibp_check:   { enabled:true,  interval:"daily",  time:"06:00", days:"all" },
    nuclei_update:{ enabled:true,  interval:"daily",  time:"01:00", days:"all" },
    deep_scan:    { enabled:false, interval:"weekly", time:"02:00", days:"sun" },
  });

  const [notif, setNotif] = useState({
    email:         { enabled:true,  value:"security@mueller-gmbh.de" },
    slack_webhook: { enabled:false, value:"" },
    critical_only: { enabled:false },
    report_weekly: { enabled:true  },
  });

  const [saved, setSaved] = useState({});
  const showSaved = (key, msg = "Gespeichert") => {
    setSaved(s=>({...s,[key]:true}));
    setTimeout(()=>setSaved(s=>({...s,[key]:false})),2000);
    toast.success(msg);
  };

  const SECTIONS = [
    { id:"domains",      label:"Domains & Targets" },
    { id:"schedule",     label:"Scan Schedule" },
    { id:"notifications",label:"Notifications" },
    { id:"access",       label:"Access & RBAC" },
  ];

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
    showSaved("domain_added", "Domain hinzugefügt — Scan startet beim nächsten Zyklus");
  };

  const handleSaveEdit = () => {
    const err = validateDomain(editDomain);
    if (err) { setAddError(err); return; }
    setDomains(d => d.map(x => x.id === editDomain.id ? editDomain : x));
    setEditDomain(null); setAddError(""); showSaved("domain_saved", "Domain-Änderungen gespeichert");
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

            {showAddDomain && (
              <div style={{ background:T.bg3, border:`1px solid ${T.border2}`, borderRadius:6,
                padding:18, marginBottom:18, borderLeft:`3px solid ${T.accent}` }}>
                <div style={{ fontFamily:T.font, fontSize:9, color:T.accent, letterSpacing:"0.08em", marginBottom:14 }}>NEW DOMAIN</div>
                <div style={{ display:"grid", gridTemplateColumns:"2fr 2fr 1fr", gap:10, marginBottom:10 }}>
                  {[
                    { key:"domain",    label:"Domain *",                   ph:"example.de" },
                    { key:"ip_ranges", label:"IP Ranges (komma-getrennt)", ph:"203.0.113.0/24, ..." },
                    { key:"panos",     label:"PAN-OS Version",              ph:"11.1.3" },
                  ].map(f => (
                    <div key={f.key}>
                      <div style={{ fontFamily:T.font, fontSize:9, color:T.text3, marginBottom:5, letterSpacing:"0.06em" }}>{f.label.toUpperCase()}</div>
                      <input value={newDomain[f.key]} onChange={e => setNewDomain(d=>({...d,[f.key]:e.target.value}))}
                        placeholder={f.ph} onKeyDown={e => e.key==="Enter" && handleAddDomain()}
                        style={{ width:"100%", background:T.bg2, border:`1px solid ${addError&&f.key==="domain"?T.red:T.border}`,
                          borderRadius:4, padding:"7px 10px", fontFamily:T.font, fontSize:11, color:T.text0, outline:"none" }}/>
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

            {editDomain && (
              <div style={{ background:T.bg3, border:`1px solid ${T.border2}`, borderRadius:6,
                padding:18, marginBottom:18, borderLeft:`3px solid ${T.medium}` }}>
                <div style={{ fontFamily:T.font, fontSize:9, color:T.medium, letterSpacing:"0.08em", marginBottom:14 }}>EDIT DOMAIN</div>
                <div style={{ display:"grid", gridTemplateColumns:"2fr 2fr 1fr", gap:10, marginBottom:10 }}>
                  {[
                    { key:"domain",       label:"Domain *" },
                    { key:"ip_ranges_str",label:"IP Ranges (komma-getrennt)" },
                    { key:"panos",        label:"PAN-OS Version" },
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

            <div style={{ border:`1px solid ${T.border}`, borderRadius:6, overflow:"hidden" }}>
              <table style={{ width:"100%", borderCollapse:"collapse" }}>
                <thead><tr>
                  <TH>Status</TH><TH>Domain</TH><TH>IP Ranges</TH><TH>PAN-OS</TH>
                  <TH right>Findings</TH><TH right>Score</TH><TH>Last Scan</TH><TH>Added</TH><TH>Actions</TH>
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
                      <TD><span style={{ fontFamily:T.font, fontSize:12, color:T.accent, fontWeight:600 }}>{d.domain}</span></TD>
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
                              borderRadius:3, padding:"3px 10px", fontFamily:T.font, fontSize:9, color:T.text2, cursor:"pointer" }}>Edit</button>
                          {d.status==="paused"
                            ? <button onClick={() => setDomains(ds=>ds.map(x=>x.id===d.id?{...x,status:"active"}:x))}
                                style={{ background:"transparent", border:`1px solid ${T.accent}50`,
                                  borderRadius:3, padding:"3px 10px", fontFamily:T.font, fontSize:9, color:T.accent, cursor:"pointer" }}>Resume</button>
                            : <button onClick={() => setDomains(ds=>ds.map(x=>x.id===d.id?{...x,status:"paused"}:x))}
                                style={{ background:"transparent", border:`1px solid ${T.medium}50`,
                                  borderRadius:3, padding:"3px 10px", fontFamily:T.font, fontSize:9, color:T.medium, cursor:"pointer" }}>Pause</button>}
                          {confirmDelete===d.id
                            ? <button onClick={() => { setDomains(ds=>ds.filter(x=>x.id!==d.id)); setConfirmDelete(null); }}
                                style={{ background:`${T.critical}15`, border:`1px solid ${T.critical}50`,
                                  borderRadius:3, padding:"3px 10px", fontFamily:T.font, fontSize:9, color:T.critical, cursor:"pointer", fontWeight:700 }}>Confirm</button>
                            : <button onClick={() => setConfirmDelete(d.id)}
                                style={{ background:"transparent", border:`1px solid ${T.border}`,
                                  borderRadius:3, padding:"3px 10px", fontFamily:T.font, fontSize:9, color:T.text3, cursor:"pointer" }}>Delete</button>}
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
              { key:"full_scan",     label:"Full Pipeline Scan",     desc:"Subfinder · Naabu · theHarvester · HTTPX · Nuclei · Ramparts" },
              { key:"mcp_scan",      label:"MCP-Only Scan",          desc:"Dedizierter MCP-Server-Scan (Nuclei + Ramparts)" },
              { key:"hibp_check",    label:"HIBP Credential Check",  desc:"Credential-Leak-Prüfung via HIBP API" },
              { key:"nuclei_update", label:"Nuclei Template Update", desc:"Aktualisiert Nuclei-Templates aus der Community" },
              { key:"deep_scan",     label:"Deep Scan (UDP + full)", desc:"Vollständiger Scan inkl. UDP-Ports, recursive Subfinder" },
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
            <button onClick={() => showSaved("schedule", "Scan-Schedule gespeichert")} style={{ marginTop:8, background:T.accent, border:"none",
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
              { key:"email",         label:"E-Mail Alerts",  ph:"security@example.de",        desc:"Alert-E-Mail bei kritischen Findings" },
              { key:"slack_webhook", label:"Slack Webhook",  ph:"https://hooks.slack.com/...", desc:"Slack-Kanal für Sofort-Alerts" },
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
                { key:"critical_only", label:"Critical & KEV only",   desc:"Nur CRITICAL-Findings und CISA-KEV-Treffer alertieren" },
                { key:"report_weekly", label:"Weekly Summary Report",  desc:"Wöchentlicher Zusammenfassungs-Report per E-Mail" },
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
            <button onClick={()=>showSaved("notif", "Notification-Einstellungen gespeichert")} style={{ marginTop:8, background:T.accent, border:"none",
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
              { name:"Klaus Weber",    email:"k.weber@mueller-gmbh.de",  role:"Admin",     last:"2026-05-05", status:"active" },
              { name:"Maria Schmidt",  email:"m.schmidt@mueller-gmbh.de",role:"Analyst",   last:"2026-05-04", status:"active" },
              { name:"Tom Bauer",      email:"t.bauer@mueller-gmbh.de",  role:"Read-Only", last:"2026-04-28", status:"active" },
              { name:"SIEM API Token", email:"—",                         role:"API",       last:"2026-05-05", status:"active" },
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

export default AdminTab;
