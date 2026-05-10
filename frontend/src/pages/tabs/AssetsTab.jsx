import { useState, useEffect, useRef } from "react";
import { T, SEV, TOOL_COLOR } from "../../theme";
import { Sev, Tag, Pill, TH, TD } from "../../components/ui/index";
import { useApp } from "../../context/AppContext";

export const Sparkline = ({ data, color = T.accent, width = 120, height = 32 }) => {
  const min = Math.min(...data), max = Math.max(...data);
  const range = max - min || 1;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - ((v - min) / range) * (height - 4) - 2;
    return `${x},${y}`;
  }).join(" ");
  const last = data[data.length - 1];
  const lastX = width;
  const lastY = height - ((last-min)/range)*(height-4) - 2;
  return (
    <svg width={width} height={height} style={{ overflow: "visible" }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5"
        strokeLinecap="round" strokeLinejoin="round" opacity="0.8" />
      <circle cx={lastX} cy={lastY} r="3" fill={color} />
    </svg>
  );
};

let _leafletReady = false;
let _leafletCallbacks = [];

function loadLeaflet(cb) {
  if (_leafletReady) { cb(window.L); return; }
  _leafletCallbacks.push(cb);
  if (document.getElementById("leaflet-css")) return;

  const link = document.createElement("link");
  link.id = "leaflet-css";
  link.rel = "stylesheet";
  link.href = "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css";
  document.head.appendChild(link);

  const script = document.createElement("script");
  script.src = "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js";
  script.onload = () => {
    _leafletReady = true;
    _leafletCallbacks.forEach(fn => fn(window.L));
    _leafletCallbacks = [];
  };
  document.head.appendChild(script);
}

const SEV_HEX = {
  CRITICAL: "#f43f5e",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#60a5fa",
  INFO:     "#94a3b8",
};

export const GeoMiniMap = ({ assets = [], height = 280 }) => {
  const containerRef = useRef(null);
  const mapRef       = useRef(null);
  const id = useRef("leaflet-map-" + Math.random().toString(36).slice(2));

  useEffect(() => {
    if (!containerRef.current) return;

    loadLeaflet((L) => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }

      const map = L.map(id.current, {
        center: [30, 10],
        zoom: 2,
        zoomControl: true,
        scrollWheelZoom: false,
        attributionControl: true,
      });

      L.tileLayer(
        "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
        {
          attribution: '&copy; <a href="https://carto.com/">CARTO</a> &copy; <a href="https://openstreetmap.org">OSM</a>',
          subdomains: "abcd",
          maxZoom: 19,
        }
      ).addTo(map);

      assets.forEach((a) => {
        const col  = SEV_HEX[a.risk] || "#94a3b8";
        const size = a.risk === "CRITICAL" ? 14 : a.risk === "HIGH" ? 12 : 10;
        const isPulsing = a.risk === "CRITICAL" || a.risk === "HIGH";

        const svgIcon = L.divIcon({
          className: "",
          html: `
            <div style="position:relative;width:${size}px;height:${size}px;">
              ${isPulsing ? `
                <div style="
                  position:absolute;
                  top:50%;left:50%;
                  transform:translate(-50%,-50%);
                  width:${size + 8}px;height:${size + 8}px;
                  border-radius:50%;
                  background:${col};
                  opacity:0.25;
                  animation:leaflet-pulse 1.8s ease-out infinite;
                "></div>` : ""}
              <div style="
                width:${size}px;height:${size}px;
                border-radius:50%;
                background:${col};
                border:2px solid rgba(0,0,0,0.6);
                box-shadow:0 0 6px ${col}80;
              "></div>
            </div>`,
          iconSize:   [size + 8, size + 8],
          iconAnchor: [(size + 8) / 2, (size + 8) / 2],
        });

        const marker = L.marker([a.lat, a.lng], { icon: svgIcon }).addTo(map);
        marker.bindPopup(`
          <div style="font-family:'JetBrains Mono',monospace;font-size:11px;line-height:1.6;color:#f1f5f9;background:#0d1221;padding:4px 0;">
            <strong style="color:${col}">${a.risk}</strong> — ${a.city || ""}<br/>
            ${a.ip_count ? `<span style="color:#475569">${a.ip_count} IP${a.ip_count !== 1 ? "s" : ""}</span>` : ""}
          </div>`, {
          className: "easm-popup",
        });
      });

      if (assets.length > 0) {
        try {
          const bounds = L.latLngBounds(assets.map(a => [a.lat, a.lng]));
          map.fitBounds(bounds, { padding: [40, 40], maxZoom: 5 });
        } catch (e) {}
      }

      mapRef.current = map;
    });

    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, [JSON.stringify(assets)]);

  return (
    <div style={{ position: "relative" }}>
      <style>{`
        .leaflet-container { background: #050810 !important; }
        .leaflet-control-attribution {
          background: rgba(5,8,16,0.8) !important;
          color: #273548 !important;
          font-size: 9px !important;
        }
        .leaflet-control-attribution a { color: #475569 !important; }
        .leaflet-control-zoom a {
          background: #0d1221 !important;
          border-color: #1e2d45 !important;
          color: #94a3b8 !important;
        }
        .leaflet-control-zoom a:hover { background: #172131 !important; }
        .leaflet-popup-content-wrapper {
          background: #0d1221 !important;
          border: 1px solid #1e2d45 !important;
          border-radius: 4px !important;
          box-shadow: 0 4px 24px rgba(0,0,0,0.6) !important;
          color: #f1f5f9 !important;
        }
        .leaflet-popup-tip { background: #0d1221 !important; }
        .leaflet-popup-close-button { color: #475569 !important; }
        @keyframes leaflet-pulse {
          0%   { transform: translate(-50%,-50%) scale(1);   opacity: 0.25; }
          70%  { transform: translate(-50%,-50%) scale(2.2); opacity: 0; }
          100% { transform: translate(-50%,-50%) scale(2.2); opacity: 0; }
        }
      `}</style>
      <div
        id={id.current}
        ref={containerRef}
        style={{
          height,
          width: "100%",
          borderRadius: 4,
          overflow: "hidden",
          background: "#050810",
        }}
      />
    </div>
  );
};

export const DonutChart = ({ data = [], size = 160 }) => {
  const [hovered, setHovered] = useState(null);
  const r = size / 2 - 16;
  const cx = size / 2;
  const cy = size / 2;
  const total = data.reduce((s, d) => s + (d.count || 0), 0) || 1;

  let angle = -Math.PI / 2;
  const slices = data.map((d, i) => {
    const sweep = (d.count / total) * 2 * Math.PI;
    const x1 = cx + r * Math.cos(angle);
    const y1 = cy + r * Math.sin(angle);
    angle += sweep;
    const x2 = cx + r * Math.cos(angle);
    const y2 = cy + r * Math.sin(angle);
    const large = sweep > Math.PI ? 1 : 0;
    return { ...d, x1, y1, x2, y2, large, sweep, startAngle: angle - sweep };
  });

  const innerR = r * 0.55;

  return (
    <svg width={size} height={size}>
      {slices.map((s, i) => (
        <path
          key={i}
          d={`M ${cx} ${cy} L ${s.x1} ${s.y1} A ${r} ${r} 0 ${s.large} 1 ${s.x2} ${s.y2} Z`}
          fill={s.color || T.text2}
          opacity={hovered === null || hovered === i ? 1 : 0.4}
          onMouseEnter={() => setHovered(i)}
          onMouseLeave={() => setHovered(null)}
          style={{ cursor: "pointer", transition: "opacity 0.15s" }}
        />
      ))}
      <circle cx={cx} cy={cy} r={innerR} fill={T.bg2} />
      {hovered !== null && slices[hovered] && (
        <>
          <text x={cx} y={cy - 6} textAnchor="middle"
            style={{ fontFamily: T.font, fontSize: 13, fontWeight: 700, fill: slices[hovered].color || T.text0 }}>
            {slices[hovered].pct?.toFixed(1)}%
          </text>
          <text x={cx} y={cy + 10} textAnchor="middle"
            style={{ fontFamily: T.fontSans, fontSize: 9, fill: T.text2 }}>
            {slices[hovered].name}
          </text>
        </>
      )}
    </svg>
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
  const { assets: SUBDOMAINS, intel } = useApp();

  const [sub, setSub] = useState("list");
  const [q, setQ] = useState("");
  const SEV_ORDER = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3 };

  const SUB_TABS = [
    { id:"list",     label:"Asset List" },
    { id:"hosting",  label:"Hosting Analysis" },
    { id:"geo",      label:"Geo Distribution" },
    { id:"graph",    label:"Asset Graph" },
    { id:"fqdn",     label:`FQDN Inventory (${(intel?.fqdn_table||[]).length})` },
  ];

  const filtered = (SUBDOMAINS||[])
    .filter(s => !q || s.fqdn.includes(q) || s.ip.includes(q) || s.org.includes(q))
    .sort((a,b) => (SEV_ORDER[a.risk]||4) - (SEV_ORDER[b.risk]||4));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>

      {/* KPI strip */}
      <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
        {["Subdomains","IPs","Ports","Services"].map((l, i) => (
          <div key={l} style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 4, padding: "7px 16px", textAlign: "center" }}>
            <div style={{ fontFamily: T.font, fontSize: 14, fontWeight: 700, color: T.accent }}>{[26,18,47,31][i]}</div>
            <div style={{ fontFamily: T.fontSans, fontSize: 9, color: T.text3, marginTop: 2 }}>{l}</div>
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
                {filtered.map(row => (
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
                        {row.ports.slice(0,4).map(p => (
                          <Tag key={p} label={String(p)}
                            color={[6274,6277,3389,8080].includes(p) ? T.red : [443,80].includes(p) ? T.accent : T.text2}
                            bg={[6274,6277,3389].includes(p) ? `${T.critical}12` : T.bg3}
                            border={[6274,6277,3389].includes(p) ? `${T.critical}40` : T.border} />
                        ))}
                        {row.ports.length > 4 && <Tag label={`+${row.ports.length-4}`} />}
                      </div>
                    </TD>
                    <TD>
                      <div style={{ display: "flex", gap: 4 }}>
                        {row.sources.map(s => <Pill key={s} label={s} color={TOOL_COLOR[s] || T.text2} />)}
                      </div>
                    </TD>
                    <TD><div style={{ width: 7, height: 7, borderRadius: "50%", background: T.accent }} /></TD>
                  </tr>
                ))}
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
                    <span style={{ fontFamily: T.font, fontSize: 10, color: o.color, fontWeight: 600 }}>{o.pct.toFixed(1)}%</span>
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
                    style={{ transition: "background 0.1s", cursor: "default" }}>
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
                        <span style={{ fontFamily: T.font, fontSize: 10, color: o.color, minWidth: 36 }}>{o.pct.toFixed(1)}%</span>
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
              assets={intel?.geo_assets || [
                { lat:50.11, lng:8.68,   city:"Frankfurt",  risk:"CRITICAL" },
                { lat:52.52, lng:13.40,  city:"Berlin",     risk:"HIGH"     },
                { lat:51.23, lng:6.78,   city:"Düsseldorf", risk:"HIGH"     },
                { lat:39.02, lng:-77.54, city:"Ashburn",    risk:"LOW"      },
                { lat:37.34, lng:-121.9, city:"San Jose",   risk:"LOW"      },
                { lat:52.37, lng:4.89,   city:"Amsterdam",  risk:"MEDIUM"   },
              ]}
              height={260}
            />
            <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
              {[["CRITICAL",T.red],["HIGH",T.high],["MEDIUM",T.medium],["LOW",T.low]].map(([s,c]) => (
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
                      <span style={{ fontFamily: T.font, fontSize: 10, color: T.text2 }}>{a.lat.toFixed(3)}, {a.lng.toFixed(3)}</span>
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
