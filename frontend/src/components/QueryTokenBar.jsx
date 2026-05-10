/**
 * QueryTokenBar.jsx — Zeigt erkannte Query-Tokens farbig in der Suchleiste an.
 * Wird unter dem Suchfeld angezeigt sobald der Nutzer eintippt.
 */

const TOKEN_RE = /(-?)(\w+):((?:"[^"]*"|[^\s]+))/g;

const FIELD_COLORS = {
  severity: "#f43f5e", sev: "#f43f5e",
  status: "#60a5fa",
  cat: "#a78bfa", tag: "#a78bfa", category: "#a78bfa",
  tool: "#22c55e",
  has: "#eab308",
  cvss: "#f97316", epss: "#f97316",
  age: "#94a3b8",
  port: "#f43f5e",
  subdomain: "#60a5fa", domain: "#60a5fa",
  ip: "#60a5fa",
  org: "#22c55e",
  cve: "#f43f5e",
  asset: "#94a3b8",
  title: "#94a3b8",
};

export function parseTokens(q) {
  const tokens = [];
  let lastIdx = 0;
  const regex = /(-?)(\w+):((?:"[^"]*"|[^\s]+))/g;
  let m;
  while ((m = regex.exec(q)) !== null) {
    if (m.index > lastIdx) {
      const text = q.slice(lastIdx, m.index).trim();
      if (text) tokens.push({ type: "text", value: text });
    }
    const negate = m[1] === "-";
    const key = m[2].toLowerCase();
    const val = m[3];
    const color = FIELD_COLORS[key] || "#94a3b8";
    tokens.push({ type: "token", key, val, negate, color, raw: m[0] });
    lastIdx = m.index + m[0].length;
  }
  const remainder = q.slice(lastIdx).trim();
  if (remainder) tokens.push({ type: "text", value: remainder });
  return tokens;
}

export default function QueryTokenBar({ query }) {
  if (!query || !query.trim()) return null;
  const tokens = parseTokens(query);
  const hasTokens = tokens.some(t => t.type === "token");
  if (!hasTokens) return null;

  return (
    <div style={{
      display: "flex", gap: 4, flexWrap: "wrap", alignItems: "center",
      padding: "6px 4px 2px",
    }}>
      {tokens.map((t, i) => {
        if (t.type === "text") {
          return (
            <span key={i} style={{
              fontFamily: "JetBrains Mono, monospace", fontSize: 10, color: "#475569",
              background: "#121929", border: "1px solid #1e2d45",
              padding: "1px 7px", borderRadius: 3,
            }}>"{t.value}"</span>
          );
        }
        return (
          <span key={i} title={`Filter: ${t.key} = ${t.val}`} style={{
            fontFamily: "JetBrains Mono, monospace", fontSize: 10,
            color: t.negate ? "#f43f5e" : t.color,
            background: `${t.color}12`,
            border: `1px solid ${t.negate ? "#7f1d1d" : t.color + "40"}`,
            padding: "1px 7px", borderRadius: 3, cursor: "default",
            textDecoration: t.negate ? "line-through" : "none",
          }}>
            {t.negate && <span style={{ opacity: 0.6 }}>NOT </span>}
            <span style={{ opacity: 0.6 }}>{t.key}:</span>
            <span style={{ fontWeight: 700 }}>{t.val}</span>
          </span>
        );
      })}
    </div>
  );
}
