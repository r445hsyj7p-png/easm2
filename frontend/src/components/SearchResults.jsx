/**
 * SearchResults.jsx — Globales Suchergebnis-Panel
 * Zeigt Findings + Assets aus einer API-Suche an.
 */
import { useState } from "react";

const SEV_COLOR = {
  CRITICAL: "#f43f5e", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#60a5fa", INFO: "#94a3b8"
};
const SEV_BG = {
  CRITICAL: "#1c0810", HIGH: "#1c0e00", MEDIUM: "#1a1400", LOW: "#00111e", INFO: "#0d1221"
};

function SevBadge({ s }) {
  const col = SEV_COLOR[s] || "#94a3b8";
  const bg  = SEV_BG[s]  || "#0d1221";
  return (
    <span style={{
      fontFamily: "JetBrains Mono, monospace", fontSize: 9, fontWeight: 700,
      letterSpacing: "0.06em", color: col, background: bg,
      border: `1px solid ${col}50`, padding: "1px 6px", borderRadius: 3,
      whiteSpace: "nowrap",
    }}>{s}</span>
  );
}

function ParsedQueryDisplay({ parsed }) {
  if (!parsed?.filters?.length && !parsed?.freetext) return null;
  return (
    <div style={{
      display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center",
      padding: "8px 14px", background: "#0d1221",
      borderBottom: "1px solid #1e2d45", fontSize: 11,
    }}>
      <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 9,
        color: "#475569", letterSpacing: "0.08em" }}>PARSED:</span>
      {parsed.filters.map((f, i) => (
        <span key={i} style={{
          fontFamily: "JetBrains Mono, monospace", fontSize: 10,
          color: f.negate ? "#f43f5e" : "#22c55e",
          background: f.negate ? "#1c081020" : "#0f3d2020",
          border: `1px solid ${f.negate ? "#7f1d1d" : "#14532d"}`,
          padding: "1px 7px", borderRadius: 3,
        }}>
          {f.negate ? "NOT " : ""}{f.field}:{Array.isArray(f.value) ? f.value.join(",") : String(f.value ?? "✓")}
        </span>
      ))}
      {parsed.freetext && (
        <span style={{
          fontFamily: "JetBrains Mono, monospace", fontSize: 10, color: "#94a3b8",
          background: "#172131", border: "1px solid #1e2d45",
          padding: "1px 7px", borderRadius: 3,
        }}>"{parsed.freetext}"</span>
      )}
      {parsed.warnings?.map((w, i) => (
        <span key={i} style={{ fontFamily: "IBM Plex Sans, sans-serif", fontSize: 10,
          color: "#eab308" }}>⚠ {w}</span>
      ))}
    </div>
  );
}

function FindingRow({ f }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr onClick={() => setOpen(!open)} style={{
        cursor: "pointer", transition: "background 0.1s",
        borderLeft: `2px solid ${SEV_COLOR[f.severity] || "#1e2d45"}`,
      }}
        onMouseEnter={e => e.currentTarget.style.background = "#172131"}
        onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
        <td style={{ padding: "9px 12px", borderBottom: "1px solid #1e2d45" }}>
          <SevBadge s={f.severity} />
        </td>
        <td style={{ padding: "9px 12px", borderBottom: "1px solid #1e2d45" }}>
          <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 9,
            color: "#475569", border: "1px solid #1e2d45", padding: "1px 5px", borderRadius: 3 }}>
            {f.category}
          </span>
        </td>
        <td style={{ padding: "9px 12px", borderBottom: "1px solid #1e2d45", maxWidth: 340 }}>
          <div style={{ fontFamily: "IBM Plex Sans, sans-serif", fontSize: 12,
            color: "#f1f5f9", fontWeight: 500 }}>{f.title}</div>
          {f.cve_id && <div style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 9,
            color: "#f43f5e", marginTop: 2 }}>{f.cve_id}</div>}
        </td>
        <td style={{ padding: "9px 12px", borderBottom: "1px solid #1e2d45" }}>
          <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 10, color: "#475569" }}>
            {f.asset}
          </span>
        </td>
        <td style={{ padding: "9px 12px", borderBottom: "1px solid #1e2d45", textAlign: "right" }}>
          {f.cvss_score > 0 ? (
            <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 11, fontWeight: 700,
              color: f.cvss_score >= 9 ? "#f43f5e" : f.cvss_score >= 7 ? "#f97316" : "#eab308" }}>
              {f.cvss_score.toFixed(1)}
            </span>
          ) : <span style={{ color: "#273548" }}>—</span>}
        </td>
        <td style={{ padding: "9px 12px", borderBottom: "1px solid #1e2d45" }}>
          {f.cisa_kev && (
            <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 9, fontWeight: 700,
              color: "#f43f5e", background: "#1c081020", border: "1px solid #7f1d1d",
              padding: "1px 5px", borderRadius: 2 }}>KEV</span>
          )}
        </td>
        <td style={{ padding: "9px 12px", borderBottom: "1px solid #1e2d45" }}>
          <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 9, color: "#22c55e" }}>
            {f.tool}
          </span>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={7} style={{
            padding: "12px 16px 16px 28px", borderBottom: "1px solid #1e2d45",
            background: "#0d1221",
          }}>
            <div style={{ fontFamily: "IBM Plex Sans, sans-serif", fontSize: 12,
              color: "#94a3b8", lineHeight: 1.6, marginBottom: 10 }}>
              {f.description}
            </div>
            <div style={{ background: "#0f3d2015", border: "1px solid #14532d",
              borderRadius: 4, padding: "8px 12px" }}>
              <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 9,
                color: "#22c55e", display: "block", marginBottom: 4 }}>REMEDIATION</span>
              <span style={{ fontFamily: "IBM Plex Sans, sans-serif", fontSize: 11, color: "#94a3b8" }}>
                {f.remediation}
              </span>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function AssetRow({ a }) {
  const col = SEV_COLOR[a.risk_level] || "#94a3b8";
  return (
    <tr style={{ cursor: "default", borderLeft: `2px solid ${col}` }}
      onMouseEnter={e => e.currentTarget.style.background = "#172131"}
      onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
      <td style={{ padding: "9px 12px", borderBottom: "1px solid #1e2d45" }}>
        <SevBadge s={a.risk_level} />
      </td>
      <td style={{ padding: "9px 12px", borderBottom: "1px solid #1e2d45" }}>
        <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 11, color: "#22c55e" }}>
          {a.fqdn}
        </span>
      </td>
      <td style={{ padding: "9px 12px", borderBottom: "1px solid #1e2d45" }}>
        <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 10, color: "#475569" }}>
          {a.ip || "—"}
        </span>
      </td>
      <td style={{ padding: "9px 12px", borderBottom: "1px solid #1e2d45" }}>
        <span style={{ fontFamily: "IBM Plex Sans, sans-serif", fontSize: 11, color: "#94a3b8" }}>
          {a.org}
        </span>
      </td>
      <td style={{ padding: "9px 12px", borderBottom: "1px solid #1e2d45" }}>
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
          {(a.ports || []).slice(0, 5).map(port => (
            <span key={port} style={{
              fontFamily: "JetBrains Mono, monospace", fontSize: 9,
              color: [6274, 6277, 3389].includes(port) ? "#f43f5e" : "#475569",
              border: `1px solid ${[6274, 6277, 3389].includes(port) ? "#7f1d1d" : "#1e2d45"}`,
              padding: "0 4px", borderRadius: 2,
            }}>{port}</span>
          ))}
        </div>
      </td>
    </tr>
  );
}

export default function SearchResults({ result, query, onClear, loading }) {
  const T = {
    bg2: "#0d1221", bg3: "#121929", border: "#1e2d45",
    text0: "#f1f5f9", text1: "#94a3b8", text2: "#475569", text3: "#273548",
    accent: "#22c55e", font: "JetBrains Mono, monospace", fontSans: "IBM Plex Sans, sans-serif",
  };

  const thStyle = {
    padding: "7px 12px", fontFamily: T.font, fontSize: 8, fontWeight: 700,
    letterSpacing: "0.08em", color: T.text2, background: "#121929",
    borderBottom: `1px solid ${T.border}`, textAlign: "left", whiteSpace: "nowrap",
  };

  if (loading) {
    return (
      <div style={{ padding: "48px", textAlign: "center" }}>
        <div style={{ fontFamily: T.font, fontSize: 12, color: T.text2,
          animation: "pulse 1.2s ease-in-out infinite" }}>
          SEARCHING...
        </div>
      </div>
    );
  }

  if (!result) return null;

  const findings = result.results?.findings || [];
  const assets   = result.results?.assets   || [];
  const total    = (result.total?.findings || 0) + (result.total?.assets || 0);

  return (
    <div style={{ animation: "fadeIn 0.2s ease" }}>
      {/* Header */}
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        padding: "12px 16px", background: T.bg2, borderBottom: `1px solid ${T.border}`,
        borderRadius: "6px 6px 0 0",
      }}>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <span style={{ fontFamily: T.font, fontSize: 10, fontWeight: 700,
            color: T.accent }}>SEARCH RESULTS</span>
          <span style={{ fontFamily: T.font, fontSize: 10, color: T.text2 }}>
            "{query}"
          </span>
          <span style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>
            {total} results · {result.took_ms}ms
          </span>
          {result.total?.findings > 0 && (
            <span style={{ fontFamily: T.font, fontSize: 9,
              color: T.text1, background: T.bg3,
              border: `1px solid ${T.border}`, padding: "1px 7px", borderRadius: 3 }}>
              {result.total.findings} findings
            </span>
          )}
          {result.total?.assets > 0 && (
            <span style={{ fontFamily: T.font, fontSize: 9,
              color: T.text1, background: T.bg3,
              border: `1px solid ${T.border}`, padding: "1px 7px", borderRadius: 3 }}>
              {result.total.assets} assets
            </span>
          )}
        </div>
        <button onClick={onClear} style={{
          background: "transparent", border: `1px solid ${T.border}`, borderRadius: 4,
          padding: "5px 12px", fontFamily: T.font, fontSize: 9, color: T.text2, cursor: "pointer",
        }}>← Zurück</button>
      </div>

      {/* Parsed query display */}
      {result.parsed && <ParsedQueryDisplay parsed={result.parsed} />}

      {/* Error */}
      {result.error && (
        <div style={{ padding: "16px", background: "#1c081020", border: "1px solid #7f1d1d",
          borderRadius: 4, margin: "12px" }}>
          <span style={{ fontFamily: T.font, fontSize: 11, color: "#f43f5e" }}>
            ⚠ {result.error}
          </span>
          {result.suggestion && (
            <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1, marginTop: 6 }}>
              {result.suggestion}
            </div>
          )}
        </div>
      )}

      {/* Empty */}
      {!result.error && total === 0 && (
        <div style={{ padding: "48px", textAlign: "center" }}>
          <div style={{ fontFamily: T.font, fontSize: 11, color: T.text3, marginBottom: 8 }}>
            Keine Ergebnisse für "{query}"
          </div>
          <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3 }}>
            Syntax-Referenz: <code style={{ color: T.accent }}>severity:critical has:kev</code>
          </div>
        </div>
      )}

      {/* Findings table */}
      {findings.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ padding: "8px 14px", background: "#121929",
            borderBottom: `1px solid ${T.border}`,
            fontFamily: T.font, fontSize: 9, color: T.text2, letterSpacing: "0.1em" }}>
            FINDINGS ({result.total?.findings})
          </div>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>
                {["SEVERITY","CATEGORY","FINDING","ASSET","CVSS","KEV","TOOL"].map(h => (
                  <th key={h} style={thStyle}>{h}</th>
                ))}
              </tr></thead>
              <tbody>
                {findings.map(f => <FindingRow key={f.id} f={f} />)}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Assets table */}
      {assets.length > 0 && (
        <div>
          <div style={{ padding: "8px 14px", background: "#121929",
            borderBottom: `1px solid ${T.border}`,
            fontFamily: T.font, fontSize: 9, color: T.text2, letterSpacing: "0.1em" }}>
            ASSETS ({result.total?.assets})
          </div>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>
                {["RISK","FQDN","IP","ORG","PORTS"].map(h => (
                  <th key={h} style={thStyle}>{h}</th>
                ))}
              </tr></thead>
              <tbody>
                {assets.map(a => <AssetRow key={a.id} a={a} />)}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
