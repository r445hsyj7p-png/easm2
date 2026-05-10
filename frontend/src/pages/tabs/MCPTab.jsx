import { useState } from "react";
import { T } from "../../theme";
import { Sev, Tag } from "../../components/ui/index";
import { useApp } from "../../context/AppContext";

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
};

export default MCPTab;
