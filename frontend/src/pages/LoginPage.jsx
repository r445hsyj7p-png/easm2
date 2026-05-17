import { useState, useEffect } from "react";
import { T } from "../theme";
import { saveToken } from "../api/client";
import { saveTenantId } from "../api/client";

export default function LoginPage({ onLogin }) {
  const [mode, setMode]           = useState(null);
  const [email, setEmail]         = useState("");
  const [password, setPassword]   = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [name, setName]           = useState("");
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState("");
  const [pwStrength, setPwStrength] = useState(0);

  useEffect(() => {
    fetch("/api/v1/auth/status")
      .then(r => r.json())
      .then(d => setMode(d.setup_required ? "setup" : "login"))
      .catch(() => setMode("login"));
  }, []);

  useEffect(() => {
    if (!password) { setPwStrength(0); return; }
    let s = 0;
    if (password.length >= 8)  s++;
    if (password.length >= 12) s++;
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) s++;
    if (/[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password)) s++;
    setPwStrength(s);
  }, [password]);

  const pwStrengthLabel = ["", "Schwach", "Mäßig", "Gut", "Stark"][pwStrength];
  const pwStrengthColor = ["", T.critical, T.high, T.medium, T.accent][pwStrength];

  const handleSetup = async () => {
    setError("");
    if (!name.trim())           return setError("Bitte Namen eingeben.");
    if (!email.trim())          return setError("Bitte E-Mail eingeben.");
    if (password.length < 8)    return setError("Passwort muss mindestens 8 Zeichen haben.");
    if (password !== confirmPw) return setError("Passwörter stimmen nicht überein.");
    setLoading(true);
    try {
      const res = await fetch("/api/v1/auth/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, name }),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        const msg = e.detail
          ? (Array.isArray(e.detail) ? e.detail.map(d => d.msg || JSON.stringify(d)).join(", ") : e.detail)
          : e.error || `Fehler ${res.status}: Einrichtung fehlgeschlagen.`;
        throw new Error(msg);
      }
      const { access_token, tenant_id } = await res.json();
      if (!tenant_id) throw new Error("Login-Antwort enthält keine tenant_id.");
      saveToken(access_token);
      saveTenantId(tenant_id);
      onLogin(tenant_id);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async () => {
    setError("");
    if (!email.trim() || !password) return setError("Bitte E-Mail und Passwort eingeben.");
    setLoading(true);
    try {
      const res = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        const msg = e.detail
          ? (Array.isArray(e.detail) ? e.detail.map(d => d.msg || JSON.stringify(d)).join(", ") : e.detail)
          : e.error || `Fehler ${res.status}: Login fehlgeschlagen.`;
        throw new Error(msg);
      }
      const { access_token, tenant_id } = await res.json();
      if (!tenant_id) throw new Error("Login-Antwort enthält keine tenant_id.");
      saveToken(access_token);
      saveTenantId(tenant_id);
      onLogin(tenant_id);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e) => {
    if (e.key === "Enter") mode === "setup" ? handleSetup() : handleLogin();
  };

  const inputStyle = {
    width: "100%", background: T.bg3, border: `1px solid ${T.border}`,
    borderRadius: 4, padding: "10px 12px", fontFamily: T.font, fontSize: 12,
    color: T.text0, outline: "none", boxSizing: "border-box",
    transition: "border-color 0.15s",
  };
  const labelStyle = {
    fontFamily: T.font, fontSize: 10, color: T.text2,
    letterSpacing: "0.06em", display: "block", marginBottom: 6,
  };

  return (
    <div style={{
      minHeight: "100vh", background: T.bg0, display: "flex",
      alignItems: "center", justifyContent: "center", fontFamily: T.fontSans,
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
        @keyframes fadeSlideIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:none} }
      `}</style>

      <div style={{
        background: T.bg2, border: `1px solid ${T.border}`,
        borderRadius: 8, padding: "40px 48px", width: 400,
        boxShadow: "0 24px 64px rgba(0,0,0,0.5)",
        animation: "fadeSlideIn 0.25s ease",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 28 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8,
            background: "linear-gradient(135deg, #22c55e, #15803d)",
            display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
          }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#050810" strokeWidth="2.5">
              <path d="M12 2L3 7v5c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V7L12 2z"/>
            </svg>
          </div>
          <div>
            <div style={{ fontFamily: T.font, fontSize: 16, fontWeight: 700, color: T.text0 }}>EASM Platform</div>
            <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, letterSpacing: "0.08em" }}>MSSP · EXTERNAL ATTACK SURFACE</div>
          </div>
        </div>

        {mode === null && (
          <div style={{ textAlign: "center", padding: "24px 0", color: T.text3, fontFamily: T.font, fontSize: 11 }}>Verbinde...</div>
        )}

        {mode === "setup" && (
          <>
            <div style={{
              display: "flex", alignItems: "center", gap: 8, marginBottom: 20,
              padding: "10px 14px", background: `${T.accent}10`,
              border: `1px solid ${T.accent}30`, borderRadius: 4,
            }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                stroke={T.accent} strokeWidth="2" strokeLinecap="round">
                <circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>
              </svg>
              <div>
                <div style={{ fontFamily: T.font, fontSize: 10, fontWeight: 700, color: T.accent, letterSpacing: "0.06em" }}>ERSTEINRICHTUNG</div>
                <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text2, marginTop: 2 }}>Lege deinen Admin-Account an.</div>
              </div>
            </div>

            <div style={{ marginBottom: 14 }}>
              <label style={labelStyle}>VOLLSTÄNDIGER NAME</label>
              <input value={name} onChange={e => setName(e.target.value)}
                onKeyDown={handleKey} placeholder="Max Mustermann" style={inputStyle} autoFocus />
            </div>
            <div style={{ marginBottom: 14 }}>
              <label style={labelStyle}>E-MAIL</label>
              <input value={email} onChange={e => setEmail(e.target.value)}
                onKeyDown={handleKey} placeholder="admin@beispiel.de" type="email" style={inputStyle} />
            </div>
            <div style={{ marginBottom: 6 }}>
              <label style={labelStyle}>PASSWORT</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                onKeyDown={handleKey} placeholder="Mindestens 8 Zeichen" style={inputStyle} />
            </div>
            {password.length > 0 && (
              <div style={{ marginBottom: 14 }}>
                <div style={{ height: 3, background: T.bg4, borderRadius: 2, overflow: "hidden", marginBottom: 4 }}>
                  <div style={{
                    height: "100%", borderRadius: 2, width: `${pwStrength * 25}%`,
                    background: pwStrengthColor, transition: "width 0.2s, background 0.2s",
                  }}/>
                </div>
                <div style={{ fontFamily: T.font, fontSize: 9, color: pwStrengthColor }}>{pwStrengthLabel}</div>
              </div>
            )}
            <div style={{ marginBottom: 20 }}>
              <label style={labelStyle}>PASSWORT BESTÄTIGEN</label>
              <input type="password" value={confirmPw} onChange={e => setConfirmPw(e.target.value)}
                onKeyDown={handleKey}
                style={{
                  ...inputStyle,
                  borderColor: confirmPw && confirmPw !== password ? T.critical
                    : confirmPw && confirmPw === password ? T.accent : T.border,
                }} />
              {confirmPw && confirmPw === password && (
                <div style={{ fontFamily: T.font, fontSize: 9, color: T.accent, marginTop: 4 }}>✓ Passwörter stimmen überein</div>
              )}
            </div>

            {error && (
              <div style={{ background: T.criticalBg, border: `1px solid ${T.criticalBorder}`,
                borderRadius: 4, padding: "8px 12px", marginBottom: 14,
                fontFamily: T.fontSans, fontSize: 12, color: T.critical }}>{error}</div>
            )}
            <button onClick={handleSetup} disabled={loading} style={{
              width: "100%", background: loading ? T.bg4 : T.accent, border: "none", borderRadius: 4, padding: "12px",
              fontFamily: T.font, fontSize: 12, fontWeight: 700, color: loading ? T.text3 : "#052e16",
              cursor: loading ? "default" : "pointer", letterSpacing: "0.06em", transition: "all 0.15s",
            }}>
              {loading ? "EINRICHTEN..." : "ACCOUNT ERSTELLEN"}
            </button>
          </>
        )}

        {mode === "login" && (
          <>
            <div style={{ marginBottom: 20 }}>
              <label style={labelStyle}>E-MAIL</label>
              <input value={email} onChange={e => setEmail(e.target.value)}
                onKeyDown={handleKey} type="email" style={inputStyle} autoFocus />
            </div>
            <div style={{ marginBottom: 24 }}>
              <label style={labelStyle}>PASSWORT</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                onKeyDown={handleKey} style={inputStyle} />
            </div>
            {error && (
              <div style={{ background: T.criticalBg, border: `1px solid ${T.criticalBorder}`,
                borderRadius: 4, padding: "8px 12px", marginBottom: 16,
                fontFamily: T.fontSans, fontSize: 12, color: T.critical }}>{error}</div>
            )}
            <button onClick={handleLogin} disabled={loading} style={{
              width: "100%", background: loading ? T.bg4 : T.accent, border: "none", borderRadius: 4, padding: "12px",
              fontFamily: T.font, fontSize: 12, fontWeight: 700, color: loading ? T.text3 : "#052e16",
              cursor: loading ? "default" : "pointer", letterSpacing: "0.06em", transition: "all 0.15s",
            }}>
              {loading ? "ANMELDEN..." : "ANMELDEN"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
