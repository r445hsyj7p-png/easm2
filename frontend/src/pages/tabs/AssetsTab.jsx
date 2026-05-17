import { useState } from "react";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, AreaChart, Area } from "recharts";
import "leaflet/dist/leaflet.css";
import { T, SEV, TOOL_COLOR } from "../../theme";
import { Sev, Tag, Pill, TH, TD, Skeleton } from "../../components/ui/index";
import { useApp } from "../../context/AppContext";

const SEV_HEX = {
  CRITICAL: "#f43f5e",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#60a5fa",
  INFO:     "#94a3b8",
};

/* ── Sparkline via Recharts ─────────────────────────────────────────────── */
export const Sparkline = ({ data, color = T.accent, width = 120, height = 32 }) => (
  <ResponsiveContainer width={width} height={height}>
    <AreaChart data={data.map((v, i) => ({ i, v }))} margin={{ top: 2, right: 0, bottom: 2, left: 0 }}>
      <defs>
        <linearGradient id={`sg-${color.replace("#","")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="5%"  stopColor={color} stopOpacity={0.3} />
          <stop offset="95%" stopColor={color} stopOpacity={0}   />
        </linearGradient>
      </defs>
      <Area type="monotone" dataKey="v" stroke={color} strokeWidth={1.5}
        fill={`url(#sg-${color.replace("#","")})`} dot={false}
        activeDot={{ r: 3, fill: color }} />
    </AreaChart>
  </ResponsiveContainer>
);

/* ── Geo Map via react-leaflet ──────────────────────────────────────────── */
export const GeoMiniMap = ({ assets = [], height = 280 }) => {
  const center = assets.length > 0
    ? [assets[0].lat, assets[0].lng]
    : [30, 10];

  return (
    <div style={{ position: "relative" }}>
      <style>{`
        .leaflet-container { background: #050810 !important; }
        .leaflet-control-attribution {
          background: rgba(5,8,16,0.8) !important;
          color: #273548 !important; font-size: 9px !important;
        }
        .leaflet-control-attribution a { color: #475569 !important; }
        .leaflet-control-zoom a {
          background: #0d1221 !important; border-color: #1e2d45 !important;
          color: #94a3b8 !important;
        }
        .leaflet-control-zoom a:hover { background: #172131 !important; }
        .leaflet-popup-content-wrapper {
          background: #0d1221 !important; border: 1px solid #1e2d45 !important;
          border-radius: 4px !important; box-shadow: 0 4px 24px rgba(0,0,0,0.6) !important;
          color: #f1f5f9 !important;
        }
        .leaflet-popup-tip { background: #0d1221 !important; }
        .leaflet-popup-close-button { color: #475569 !important; }
      `}</style>
      <MapContainer
        center={center}
        zoom={2}
        scrollWheelZoom={false}
        style={{ height, width: "100%", borderRadius: 4, background: "#050810" }}
      >
        <TileLayer
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          attribution='&copy; <a href="https://carto.com/">CARTO</a> &copy; <a href="https://openstreetmap.org">OSM</a>'
          subdomains="abcd"
          maxZoom={19}
        />
        {assets.map((a, i) => {
          const col  = SEV_HEX[a.risk] || "#94a3b8";
          const r    = a.risk === "CRITICAL" ? 8 : a.risk === "HIGH" ? 7 : 5;
          return (
            <CircleMarker key={i} center={[a.lat, a.lng]}
              radius={r} pathOptions={{ color: col, fillColor: col, fillOpacity: 0.85, weight: 1.5 }}>
              <Popup>
                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, lineHeight: 1.6 }}>
                  <strong style={{ color: col }}>{a.risk}</strong> — {a.city || ""}<br />
                  {a.ip_count ? <span>{a.ip_count} IP{a.ip_count !== 1 ? "s" : ""}</span> : null}
                </div>
              </Popup>
            </CircleMarker>
          );
        })}
      </MapContainer>
    </div>
  );
};

/* ── DonutChart via Recharts ────────────────────────────────────────────── */
export const DonutChart = ({ data = [], size = 160 }) => {
  const chartData = data.map(d => ({ name: d.name, value: d.count, color: d.color, pct: d.pct }));

  const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null;
    const d = payload[0];
    return (
      <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 4,
        padding: "6px 10px", fontFamily: T.font, fontSize: 10 }}>
        <div style={{ color: d.payload.color, fontWeight: 700 }}>{d.payload.name}</div>
        <div style={{ color: T.text2 }}>{d.payload.pct?.toFixed(1)}% · {d.value} Assets</div>
      </div>
    );
  };

  return (
    <ResponsiveContainer width={size} height={size}>
      <PieChart>
        <Pie data={chartData} cx="50%" cy="50%"
          innerRadius={size * 0.28} outerRadius={size * 0.44}
          dataKey="value" strokeWidth={0}>
          {chartData.map((d, i) => (
            <Cell key={i} fill={d.color} opacity={0.9} />
          ))}
        </Pie>
        <Tooltip content={<CustomTooltip />} />
      </PieChart>
    </ResponsiveContainer>
  );
};

export const IntelAssetGraph = () => (
  <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, padding: 40,
    textAlign: "center", color: T.text3, fontFamily: T.font, fontSize: 11 }}>
    Asset Graph — interactive visualization coming soon
  </div>
);

const FqdnInventory = ({ data = [] }) => (
  <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, overflow: "auto" }}>
    <table style={{ width: "100%", borderCollapse: "collapse" }}>
      <thead><tr>
        <TH>Risk</TH><TH>FQDN</TH><TH>IP</TH><TH>ASN</TH><TH>Organisation</TH><TH>Country</TH>
      </tr></thead>
      <tbody>
        {data.map((r, i) => (
          <tr key={i} style={{ transition: "background 0.1s" }}
            onMouseEnter={e => e.currentTarget.style.background = T.bg3}
            onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
            <TD><Sev s={r.risk} small /></TD>
            <TD><span style={{ fontFamily: T.font, fontSize: 11, color: T.accent }}>{r.fqdn}</span></TD>
            <TD mono muted>{r.ip}</TD>
            <TD mono muted>{r.asn > 0 ? `AS${r.asn}` : "—"}</TD>
            <TD><span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1 }}>{r.org}</span></TD>
            <TD><Tag label={r.country} /></TD>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

const AssetsTab = () => {
  const { assets: SUBDOMAINS, intel, loading } = useApp();

  const [sub, setSub] = useState("list");
  const [q, setQ] = useState("");
  const SEV_ORDER = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3 };

  const SUB_TABS = [
    { id:"list",    label:"Asset List" },
    { id:"hosting", label:"Hosting Analysis" },
    { id:"geo",     label:"Geo Distribution" },
    { id:"graph",   label:"Asset Graph" },
    { id:"fqdn",    label:`FQDN Inventory (${(intel?.fqdn_table||[]).length})` },
  ];

  const filtered = (SUBDOMAINS||[])
    .filter(s => !q || s.fqdn?.includes(q) || s.ip?.includes(q) || s.org?.includes(q))
    .sort((a,b) => (SEV_ORDER[a.risk]||4) - (SEV_ORDER[b.risk]||4));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>

      {/* KPI strip */}
      <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
        {[
          { label: "Subdomains", value: (SUBDOMAINS||[]).length || 26 },
          { label: "IPs",        value: [...new Set((SUBDOMAINS||[]).map(s=>s.ip).filter(Boolean))].length || 18 },
          { label: "Ports",      value: (SUBDOMAINS||[]).flatMap(s=>s.ports||[]).length || 47 },
          { label: "Services",   value: 31 },
        ].map(({ label, value }) => (
          <div key={label} style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 4, padding: "7px 16px", textAlign: "center" }}>
            {loading
              ? <Skeleton width={32} height={14} style={{ margin: "0 auto 4px" }} />
              : <div style={{ fontFamily: T.font, fontSize: 14, fontWeight: 700, color: T.accent }}>{value}</div>}
            <div style={{ fontFamily: T.fontSans, fontSize: 9, color: T.text3, marginTop: 2 }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Sub-tabs */}
      <div style={{ display: "flex", gap: 0, borderBottom: `1px solid ${T.border}`, marginBottom: 16 }}>
        {SUB_TABS.map(t => (
          <button key={t.id} onClick={() => setSub(t.id)} style={{
            padding: "8px 16px", background: "transparent", border: "none",
            borderBottom: `2px solid ${sub === t.id ? T.accent : "transparent"}`,
            fontFamily: T.fontSans, fontSize: 12,
            fontWeight: sub === t.id ? 600 : 400,
            color: sub === t.id ? T.accent : T.text1,
            cursor: "pointer", transition: "all 0.15s", marginBottom: -1,
          }}>{t.label}</button>
        ))}
      </div>

      {/* ── Asset List ── */}
      {sub === "list" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <input value={q} onChange={e => setQ(e.target.value)}
            placeholder="Filter by FQDN, IP, org..."
            style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 4,
              padding: "6px 10px", fontFamily: T.font, fontSize: 11, color: T.text0,
              outline: "none", width: 280 }} />
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, overflow: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>
                <TH>Risk</TH><TH>FQDN</TH><TH>IP Address</TH>
                <TH>Organization</TH><TH>ASN</TH><TH>Open Ports</TH>
                <TH>Discovered Via</TH><TH>Status</TH>
              </tr></thead>
              <tbody>
                {loading
                  ? Array.from({ length: 6 }).map((_, i) => (
                      <tr key={i}>
                        {Array.from({ length: 8 }).map((_, j) => (
                          <td key={j} style={{ padding: "9px 12px", borderBottom: `1px solid ${T.border}` }}>
                            <Skeleton height={12} width={j === 1 ? 140 : j === 2 ? 100 : 60} />
                          </td>
                        ))}
                      </tr>
                    ))
                  : filtered.map(row => (
                    <tr key={row.fqdn} style={{ cursor: "pointer", transition: "background 0.1s" }}
                      onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                      <TD><Sev s={row.risk} small /></TD>
                      <TD>
                        <span style={{ fontFamily: T.font, fontSize: 11, color: T.accent }}>{row.fqdn}</span>
                        {row.takeover && <Tag label="TAKEOVER" color={T.red} bg={`${T.critical}12`} border={`${T.critical}40`} />}
                      </TD>
                      <TD mono muted>{row.ip || "—"}</TD>
                      <TD><span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1 }}>{row.org}</span></TD>
                      <TD mono muted>{row.asn > 0 ? `AS${row.asn}` : "—"}</TD>
                      <TD>
                        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                          {(row.ports||[]).slice(0,4).map(p => (
                            <Tag key={p} label={String(p)}
                              color={[6274,6277,3389,8080].includes(p) ? T.red : [443,80].includes(p) ? T.accent : T.text2}
                              bg={[6274,6277,3389].includes(p) ? `${T.critical}12` : T.bg3}
                              border={[6274,6277,3389].includes(p) ? `${T.critical}40` : T.border} />
                          ))}
                          {(row.ports||[]).length > 4 && <Tag label={`+${row.ports.length-4}`} />}
                        </div>
                      </TD>
                      <TD>
                        <div style={{ display: "flex", gap: 4 }}>
                          {(row.sources||[]).map(s => <Pill key={s} label={s} color={TOOL_COLOR[s] || T.text2} />)}
                        </div>
                      </TD>
                      <TD><div style={{ width: 7, height: 7, borderRadius: "50%", background: T.accent }} /></TD>
                    </tr>
                  ))
                }
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Hosting Analysis ── */}
      {sub === "hosting" && (
        <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: 20 }}>
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, padding: 20, minWidth: 340 }}>
            <div style={{ fontFamily: T.fontSans, fontSize: 12, fontWeight: 600, color: T.text0, marginBottom: 14 }}>Hosting Organisations</div>
            <div style={{ display: "flex", gap: 20, alignItems: "center" }}>
              <DonutChart data={(intel?.hosting_orgs||[])} size={160} />
              <div style={{ flex: 1 }}>
                {(intel?.hosting_orgs||[]).map((o, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 6 }}>
                    <div style={{ width: 8, height: 8, borderRadius: "50%", background: o.color, flexShrink: 0 }} />
                    <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{o.name}</span>
                    <span style={{ fontFamily: T.font, fontSize: 10, color: o.color, fontWeight: 600 }}>{o.pct?.toFixed(1)}%</span>
                    <span style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>{o.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, padding: 20 }}>
            <div style={{ fontFamily: T.fontSans, fontSize: 12, fontWeight: 600, color: T.text0, marginBottom: 14 }}>ASN Mapping</div>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>
                {["Organization","ASN","FQDNs","Distribution"].map(h => (
                  <th key={h} style={{ padding: "6px 10px", fontFamily: T.font, fontSize: 9, color: T.text3,
                    textAlign: "left", borderBottom: `1px solid ${T.border}`, letterSpacing: "0.06em" }}>{h}</th>
                ))}
              </tr></thead>
              <tbody>
                {(intel?.hosting_orgs||[]).map((o, i) => (
                  <tr key={i} onMouseEnter={e=>e.currentTarget.style.background=T.bg3}
                    onMouseLeave={e=>e.currentTarget.style.background="transparent"}
                    style={{ transition: "background 0.1s" }}>
                    <td style={{ padding: "9px 10px", borderBottom: `1px solid ${T.border}` }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <div style={{ width: 8, height: 8, borderRadius: "50%", background: o.color }} />
                        <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1 }}>{o.name}</span>
                      </div>
                    </td>
                    <td style={{ padding: "9px 10px", borderBottom: `1px solid ${T.border}` }}>
                      <Pill label={`AS${o.asn}`} color={o.color} />
                    </td>
                    <td style={{ padding: "9px 10px", borderBottom: `1px solid ${T.border}` }}>
                      <span style={{ fontFamily: T.font, fontSize: 11, color: T.text0, fontWeight: 700 }}>{o.count}</span>
                    </td>
                    <td style={{ padding: "9px 10px", borderBottom: `1px solid ${T.border}` }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <div style={{ flex: 1, height: 3, background: T.bg4, borderRadius: 2 }}>
                          <div style={{ width: `${o.pct}%`, height: "100%", background: o.color, borderRadius: 2 }} />
                        </div>
                        <span style={{ fontFamily: T.font, fontSize: 10, color: o.color, minWidth: 36 }}>{o.pct?.toFixed(1)}%</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Geo Distribution ── */}
      {sub === "geo" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, padding: 16 }}>
            <div style={{ fontFamily: T.fontSans, fontSize: 12, fontWeight: 600, color: T.text0, marginBottom: 10 }}>Geographic Asset Distribution</div>
            <GeoMiniMap
              assets={intel?.geo_assets || []}
              height={260}
            />
            <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
              {[["CRITICAL",T.critical],["HIGH",T.high],["MEDIUM",T.medium],["LOW",T.low]].map(([s,c]) => (
                <div key={s} style={{ display:"flex", alignItems:"center", gap:5 }}>
                  <div style={{ width:7, height:7, borderRadius:"50%", background:c }}/>
                  <span style={{ fontFamily:T.font, fontSize:9, color:T.text2 }}>{s}</span>
                </div>
              ))}
              <span style={{ marginLeft:"auto", fontFamily:T.font, fontSize:9, color:T.text3 }}>6 locations · 3 countries</span>
            </div>
          </div>
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, overflow: "hidden" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>
                {["City","Country","IPs","Risk","Coordinates"].map(h => (
                  <th key={h} style={{ padding: "7px 14px", fontFamily: T.font, fontSize: 9, color: T.text3,
                    textAlign: "left", background: T.bg3, borderBottom: `1px solid ${T.border}`, letterSpacing: "0.06em" }}>{h}</th>
                ))}
              </tr></thead>
              <tbody>
                {(intel?.geo_assets||[]).map((a,i) => (
                  <tr key={i} onMouseEnter={e=>e.currentTarget.style.background=T.bg3}
                    onMouseLeave={e=>e.currentTarget.style.background="transparent"}
                    style={{ transition:"background 0.1s" }}>
                    <td style={{ padding:"9px 14px", borderBottom:`1px solid ${T.border}` }}>
                      <span style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text0, fontWeight: 500 }}>{a.city}</span>
                    </td>
                    <td style={{ padding:"9px 14px", borderBottom:`1px solid ${T.border}` }}>
                      <Tag label={a.country} />
                    </td>
                    <td style={{ padding:"9px 14px", borderBottom:`1px solid ${T.border}` }}>
                      <span style={{ fontFamily: T.font, fontSize: 11, color: T.text0, fontWeight: 700 }}>{a.ip_count}</span>
                    </td>
                    <td style={{ padding:"9px 14px", borderBottom:`1px solid ${T.border}` }}>
                      <Sev s={a.risk} small />
                    </td>
                    <td style={{ padding:"9px 14px", borderBottom:`1px solid ${T.border}` }}>
                      <span style={{ fontFamily: T.font, fontSize: 10, color: T.text2 }}>{a.lat?.toFixed(3)}, {a.lng?.toFixed(3)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Asset Graph ── */}
      {sub === "graph" && <IntelAssetGraph />}

      {/* ── FQDN Inventory ── */}
      {sub === "fqdn" && <FqdnInventory data={(intel?.fqdn_table||[])} />}
    </div>
  );
};

export default AssetsTab;
