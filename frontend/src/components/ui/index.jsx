import { useState, useEffect } from "react";
import { T, SEV, TOOL_COLOR } from "../../theme";
import QueryTokenBar from "../QueryTokenBar";

export const Skeleton = ({ width = "100%", height = 16, style = {} }) => (
  <div style={{
    width, height,
    background: `linear-gradient(90deg, ${T.bg3} 0%, ${T.bg4} 50%, ${T.bg3} 100%)`,
    backgroundSize: "200% 100%",
    animation: "shimmer 1.4s ease-in-out infinite",
    borderRadius: 4,
    ...style,
  }} />
);

export const Sev = ({ s, small }) => {
  const c = SEV[s] || SEV.INFO;
  return (
    <span style={{
      fontFamily: T.font, fontSize: small ? 9 : 10, fontWeight: 700,
      color: c.color, background: c.bg, border: `1px solid ${c.border}`,
      padding: small ? "1px 5px" : "2px 7px", borderRadius: 3,
      letterSpacing: "0.04em", whiteSpace: "nowrap",
    }}>{s}</span>
  );
};

export const Tag = ({ label, color = T.text2, bg = T.bg3, border = T.border, onClick }) => (
  <span onClick={onClick} style={{
    fontFamily: T.font,
    fontSize: 9,
    fontWeight: 600,
    letterSpacing: "0.05em",
    color,
    background: bg,
    border: `1px solid ${border}`,
    padding: "1px 7px",
    borderRadius: 3,
    whiteSpace: "nowrap",
    cursor: onClick ? "pointer" : "default",
  }}>{label}</span>
);

export const Btn = ({ children, onClick, variant = "primary", size = "md", disabled = false, style = {} }) => {
  const [hov, setHov] = useState(false);
  const base = {
    fontFamily: T.font, fontWeight: 700, letterSpacing: "0.06em",
    border: "none", borderRadius: 4, cursor: disabled ? "not-allowed" : "pointer",
    transition: "all 0.15s", outline: "none", display: "inline-flex",
    alignItems: "center", gap: 6, opacity: disabled ? 0.5 : 1,
    fontSize: size === "sm" ? 9 : size === "lg" ? 12 : 10,
    padding: size === "sm" ? "4px 10px" : size === "lg" ? "10px 24px" : "7px 16px",
  };
  const variants = {
    primary:   { background: hov ? T.accent2   : T.accent,   color: "#052e16", border: "none" },
    secondary: { background: hov ? T.bg4       : T.bg3,      color: T.text1,   border: `1px solid ${hov ? T.border2 : T.border}` },
    danger:    { background: hov ? T.criticalBorder : T.criticalBg, color: T.critical, border: `1px solid ${T.criticalBorder}` },
    ghost:     { background: "transparent",                   color: hov ? T.text0 : T.text1, border: `1px solid ${hov ? T.border2 : T.border}` },
  };
  return (
    <button onClick={!disabled ? onClick : undefined}
      onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}
      style={{ ...base, ...variants[variant], ...style }}>
      {children}
    </button>
  );
};

export const Input = ({ value, onChange, placeholder = "", style = {}, onKeyDown }) => {
  const [focused, setFocused] = useState(false);
  return (
    <input value={value} onChange={onChange} placeholder={placeholder} onKeyDown={onKeyDown}
      onFocus={() => setFocused(true)} onBlur={() => setFocused(false)}
      style={{
        background: T.bg2, color: T.text0,
        border: `1px solid ${focused ? T.borderFocus : T.border}`,
        borderRadius: 4, outline: "none",
        fontFamily: T.font, fontSize: 11,
        padding: "7px 11px", transition: "border-color 0.15s",
        boxShadow: focused ? `0 0 0 3px ${T.accent}18` : "none",
        ...style,
      }} />
  );
};

export const Select = ({ value, onChange, children, style = {} }) => (
  <select value={value} onChange={onChange} style={{
    background: T.bg2, color: T.text1,
    border: `1px solid ${T.border}`, borderRadius: 4,
    outline: "none", fontFamily: T.font, fontSize: 10,
    padding: "6px 8px", cursor: "pointer", ...style,
  }}>{children}</select>
);

export const Card = ({ children, style = {}, noPad = false }) => (
  <div style={{
    background: T.bg2, border: `1px solid ${T.border}`,
    borderRadius: 6, padding: noPad ? 0 : 20,
    overflow: noPad ? "hidden" : "visible", ...style,
  }}>{children}</div>
);

export const CardHeader = ({ children, sub, action }) => (
  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
    <div>
      <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0 }}>{children}</div>
      {sub && <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, marginTop: 3, letterSpacing: "0.04em" }}>{sub}</div>}
    </div>
    {action}
  </div>
);

export const Pill = ({ label, color = T.text1 }) => (
  <span style={{
    fontFamily: T.font, fontSize: 9, fontWeight: 600, letterSpacing: "0.04em",
    color, background: `${color}15`, border: `1px solid ${color}35`,
    padding: "1px 8px", borderRadius: 999,
  }}>{label}</span>
);

export const ScoreBar = ({ score }) => {
  const color = score >= 75 ? T.accent : score >= 50 ? T.medium : score >= 25 ? T.high : T.critical;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ flex: 1, height: 4, background: T.bg4, borderRadius: 2, overflow: "hidden" }}>
        <div style={{ width: `${score}%`, height: "100%", background: color,
          borderRadius: 2, transition: "width 1s ease" }} />
      </div>
      <span style={{ fontFamily: T.font, fontSize: 11, color, fontWeight: 700, minWidth: 28 }}>{score}</span>
    </div>
  );
};

export const TH = ({ children, onClick, sorted, dir, right }) => (
  <th onClick={onClick} style={{
    padding: "8px 12px", fontSize: 9, fontFamily: T.font, fontWeight: 700,
    color: sorted ? T.accent : T.text2, letterSpacing: "0.08em", textTransform: "uppercase",
    borderBottom: `1px solid ${T.border}`, background: T.bg2,
    textAlign: right ? "right" : "left", cursor: onClick ? "pointer" : "default",
    whiteSpace: "nowrap", userSelect: "none",
  }}>
    {children}{sorted ? (dir === "asc" ? " ↑" : " ↓") : ""}
  </th>
);

export const TD = ({ children, mono, right, muted }) => (
  <td style={{
    padding: "9px 12px", fontSize: 11,
    fontFamily: mono ? T.font : T.fontSans,
    color: muted ? T.text2 : T.text1,
    borderBottom: `1px solid ${T.border}`,
    textAlign: right ? "right" : "left",
    whiteSpace: "nowrap",
  }}>{children}</td>
);

export const KPI = ({ label, value, sub, color = T.accent, onClick }) => (
  <div onClick={onClick} style={{
    background: T.bg2, border: `1px solid ${T.border}`,
    borderRadius: 6, padding: "16px 20px", cursor: onClick ? "pointer" : "default",
    transition: "border-color 0.15s",
    ...(onClick ? { ":hover": { borderColor: color } } : {}),
  }}
  onMouseEnter={e => onClick && (e.currentTarget.style.borderColor = color)}
  onMouseLeave={e => onClick && (e.currentTarget.style.borderColor = T.border)}>
    <div style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text2, marginBottom: 6, letterSpacing: "0.05em", textTransform: "uppercase" }}>{label}</div>
    <div style={{ fontFamily: T.font, fontSize: 26, fontWeight: 700, color, lineHeight: 1 }}>{value}</div>
    {sub && <div style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text3, marginTop: 4 }}>{sub}</div>}
  </div>
);

export const SectionHeader = CardHeader;

export const SearchBar = ({ onSearch, liveQuery = "", onInputChange }) => {
  const [q, setQ] = useState(liveQuery);
  const [focused, setFocused] = useState(false);
  const examples = [
    "tag:mcp-exposure severity:critical",
    "subdomain:*.mueller-gmbh.de",
    "tool:nuclei has:cve",
    "port:6274 OR port:6277",
    "age:<7 has:no-ticket",
    "cvss:>=9 status:open",
  ];
  const [ex, setEx] = useState(0);

  useEffect(() => {
    const t = setInterval(() => setEx(i => (i+1)%examples.length), 3000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => { if (liveQuery === "") setQ(""); }, [liveQuery]);

  const handleChange = (val) => {
    setQ(val);
    if (onInputChange) onInputChange(val);
  };

  const handleSearch = () => { if (q.trim()) onSearch(q.trim()); };

  return (
    <div>
      <div style={{
        display: "flex", alignItems: "center", gap: 0,
        background: T.bg2, border: `1px solid ${focused ? T.borderFocus : T.border2}`,
        borderRadius: 6, overflow: "hidden",
        boxShadow: focused ? `0 0 0 3px ${T.accent}18` : "none",
        transition: "border-color 0.15s, box-shadow 0.15s",
      }}>
        <div style={{ padding: "0 12px", color: T.text3, fontSize: 13 }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <circle cx="11" cy="11" r="7"/><path d="M16.5 16.5L21 21"/>
          </svg>
        </div>
        <input
          value={q}
          onChange={e => handleChange(e.target.value)}
          onKeyDown={e => {
            if (e.key === "Enter") handleSearch();
            if (e.key === "Escape") { handleChange(""); onSearch(""); }
          }}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          placeholder={q ? "" : examples[ex]}
          style={{
            flex: 1, background: "transparent", border: "none", outline: "none",
            fontFamily: T.font, fontSize: 12, color: T.text0,
            padding: "11px 0", letterSpacing: "0.02em",
          }} />
        {q && (
          <button onClick={() => { handleChange(""); onSearch(""); }} style={{
            background: "transparent", border: "none", padding: "0 10px",
            color: T.text3, cursor: "pointer", fontSize: 18, lineHeight: "1",
          }}>×</button>
        )}
        <button onClick={handleSearch} style={{
          background: q.trim() ? T.accent : T.bg4,
          border: "none", padding: "11px 20px",
          fontFamily: T.font, fontSize: 11, fontWeight: 700,
          color: q.trim() ? "#052e16" : T.text3,
          cursor: q.trim() ? "pointer" : "default",
          letterSpacing: "0.06em", transition: "all 0.15s",
        }}>SEARCH</button>
      </div>
      <QueryTokenBar query={q} />
    </div>
  );
};
