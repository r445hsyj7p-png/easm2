import { useState } from "react";
import { toast } from "sonner";
import { T, SEV, TOOL_COLOR } from "../../theme";
import { Sev, Tag, TH, TD } from "../../components/ui/index";
import { useApp } from "../../context/AppContext";

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
      (!search || (f.title||"").toLowerCase().includes(search.toLowerCase()) ||
        (f.asset||"").toLowerCase().includes(search.toLowerCase()))
    )
    .sort((a, b) => {
      let cmp = 0;
      if (sort.col === "sev")   cmp = SEV_ORDER[a.sev] - SEV_ORDER[b.sev];
      if (sort.col === "cvss")  cmp = (b.cvss||0) - (a.cvss||0);
      if (sort.col === "epss")  cmp = (parseFloat(b.epss)||0) - (parseFloat(a.epss)||0);
      if (sort.col === "kev")   cmp = (b.kev?1:0) - (a.kev?1:0);
      if (sort.col === "age")   cmp = b.age - a.age;
      if (sort.col === "title") cmp = (a.title||"").localeCompare(b.title||"");
      return sort.dir === "asc" ? cmp : -cmp;
    });

  const toggleSort = (col) => setSort(s => s.col === col ? { col, dir: s.dir === "asc" ? "desc" : "asc" } : { col, dir: "asc" });
  const cats = [...new Set((findings||[]).map(f=>f.cat).filter(Boolean))];
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
              <button onClick={() => toast.success("Ticket erstellt", { description: `${selected.title} — ${selected.asset}` })}
                style={{
                  flex: 1, background: T.accent, border: "none", borderRadius: 4,
                  padding: "8px", fontFamily: T.font, fontSize: 10, fontWeight: 700,
                  color: T.bg0, cursor: "pointer", letterSpacing: "0.05em",
                }}>Open Ticket</button>
              <button onClick={() => toast.info("Risiko akzeptiert", { description: `${selected.title} als akzeptiert markiert.` })}
                style={{
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
};

export default FindingsTab;
