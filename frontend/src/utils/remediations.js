export const EFFORT_COLOR = {"Sofort":"#f43f5e","Kurzfristig":"#f97316","Mittelfristig":"#eab308","Langfristig":"#60a5fa"};

export function buildRemediations(findings) {
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
