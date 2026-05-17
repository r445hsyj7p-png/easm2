import { useState, useEffect, useCallback } from "react";
import { toast } from "sonner";
import { T } from "../../theme";
import { Tag, TH, TD } from "../../components/ui/index";
import { useApp } from "../../context/AppContext";
import { apiFetch } from "../../api/client";

const DEFAULT_SCHEDULE = {
  full_scan:    { enabled: true,  interval: "daily",  time: "08:00", days: "mon-fri" },
  mcp_scan:     { enabled: true,  interval: "daily",  time: "04:00", days: "all" },
  hibp_check:   { enabled: true,  interval: "daily",  time: "06:00", days: "all" },
  nuclei_update:{ enabled: true,  interval: "daily",  time: "01:00", days: "all" },
  deep_scan:    { enabled: false, interval: "weekly", time: "02:00", days: "sun" },
};

const DEFAULT_NOTIF = {
  email:         { enabled: true,  value: "" },
  slack_webhook: { enabled: false, value: "" },
  critical_only: { enabled: false },
  report_weekly: { enabled: true },
};

const AdminTab = () => {
  const { tenantId } = useApp();
  const [section, setSection] = useState("domains");

  // ── Domains ────────────────────────────────────────────────────────────────
  const [domains, setDomains] = useState([]);
  const [domainsLoading, setDomainsLoading] = useState(true);
  const [showAddDomain, setShowAddDomain] = useState(false);
  const [editDomain, setEditDomain] = useState(null);
  const [newDomain, setNewDomain] = useState({ domain: "", ip_ranges: "", panos_version: "" });
  const [addError, setAddError] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(null);

  // ── Settings ───────────────────────────────────────────────────────────────
  const [schedule, setSchedule] = useState(DEFAULT_SCHEDULE);
  const [notif, setNotif] = useState(DEFAULT_NOTIF);
  const [settingsLoading, setSettingsLoading] = useState(true);

  const [saved, setSaved] = useState({});
  const showSaved = (key, msg = "Gespeichert") => {
    setSaved(s => ({ ...s, [key]: true }));
    setTimeout(() => setSaved(s => ({ ...s, [key]: false })), 2000);
    toast.success(msg);
  };

  // Load domains
  const loadDomains = useCallback(async () => {
    if (!tenantId) return;
    setDomainsLoading(true);
    try {
      const data = await apiFetch(`/tenants/${tenantId}/domains`);
      setDomains(data.domains || []);
    } catch (e) {
      toast.error("Domains konnten nicht geladen werden: " + e.message);
    } finally {
      setDomainsLoading(false);
    }
  }, [tenantId]);

  // Load settings
  const loadSettings = useCallback(async () => {
    if (!tenantId) return;
    setSettingsLoading(true);
    try {
      const data = await apiFetch(`/tenants/${tenantId}/settings`);
      if (data.schedule) setSchedule({ ...DEFAULT_SCHEDULE, ...data.schedule });
      if (data.notifications) setNotif({ ...DEFAULT_NOTIF, ...data.notifications });
    } catch {
      // settings not saved yet — defaults are fine
    } finally {
      setSettingsLoading(false);
    }
  }, [tenantId]);

  useEffect(() => { loadDomains(); loadSettings(); }, [loadDomains, loadSettings]);

  const validateDomain = (d) => {
    if (!d.domain.trim()) return "Domain darf nicht leer sein";
    if (!/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(d.domain.trim())) return "Ungültiges Domain-Format (z.B. example.de)";
    if (domains.find(x => x.domain === d.domain.trim() && x.id !== editDomain?.id)) return "Domain bereits vorhanden";
    return "";
  };

  const handleAddDomain = async () => {
    const err = validateDomain(newDomain);
    if (err) { setAddError(err); return; }
    const ranges = newDomain.ip_ranges.split(",").map(s => s.trim()).filter(Boolean);
    try {
      if (editDomain) {
        await apiFetch(`/tenants/${tenantId}/domains/${editDomain.id}`, {
          method: "PATCH",
          body: { ip_ranges: ranges, panos_version: newDomain.panos_version },
        });
        setDomains(prev => prev.map(d =>
          d.id === editDomain.id ? { ...d, ip_ranges: ranges, panos_version: newDomain.panos_version } : d
        ));
        toast.success("Domain aktualisiert");
      } else {
        const created = await apiFetch(`/tenants/${tenantId}/domains`, {
          method: "POST",
          body: { domain: newDomain.domain.trim(), ip_ranges: ranges, panos_version: newDomain.panos_version },
        });
        setDomains(prev => [...prev, created]);
        toast.success("Domain hinzugefügt");
      }
      setShowAddDomain(false); setEditDomain(null);
      setNewDomain({ domain: "", ip_ranges: "", panos_version: "" }); setAddError("");
    } catch (e) {
      setAddError(e.message || "Fehler beim Speichern");
    }
  };

  const handleDeleteDomain = async (id) => {
    try {
      await apiFetch(`/tenants/${tenantId}/domains/${id}`, { method: "DELETE" });
      setDomains(prev => prev.filter(d => d.id !== id));
      setConfirmDelete(null);
      toast.success("Domain gelöscht");
    } catch (e) {
      toast.error("Löschen fehlgeschlagen: " + e.message);
    }
  };

  const toggleDomainStatus = async (domain) => {
    const newStatus = domain.status === "active" ? "paused" : "active";
    try {
      await apiFetch(`/tenants/${tenantId}/domains/${domain.id}`, {
        method: "PATCH", body: { status: newStatus },
      });
      setDomains(prev => prev.map(d => d.id === domain.id ? { ...d, status: newStatus } : d));
    } catch (e) {
      toast.error("Status konnte nicht geändert werden");
    }
  };

  const saveSchedule = async () => {
    try {
      const current = await apiFetch(`/tenants/${tenantId}/settings`);
      await apiFetch(`/tenants/${tenantId}/settings`, {
        method: "PUT", body: { ...current, schedule },
      });
      showSaved("schedule", "Scan-Zeitplan gespeichert");
    } catch (e) {
      toast.error("Fehler beim Speichern: " + e.message);
    }
  };

  const saveNotifications = async () => {
    try {
      const current = await apiFetch(`/tenants/${tenantId}/settings`);
      await apiFetch(`/tenants/${tenantId}/settings`, {
        method: "PUT", body: { ...current, notifications: notif },
      });
      showSaved("notif", "Benachrichtigungen gespeichert");
    } catch (e) {
      toast.error("Fehler beim Speichern: " + e.message);
    }
  };

  const SECTIONS = [
    { id: "domains",       label: "Domains & Targets" },
    { id: "schedule",      label: "Scan Schedule" },
    { id: "notifications", label: "Notifications" },
    { id: "access",        label: "Access & RBAC" },
  ];

  // ── Render ─────────────────────────────────────────────────────────────────

  const STATUS_COLOR = { active: T.accent, paused: T.medium, pending: T.text3 };

  return (
    <div style={{ display: "flex", gap: 16, alignItems: "flex-start" }}>
      {/* Sidebar */}
      <div style={{ width: 180, flexShrink: 0, background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, overflow: "hidden" }}>
        {SECTIONS.map(s => (
          <button key={s.id} onClick={() => setSection(s.id)} style={{
            display: "block", width: "100%", textAlign: "left",
            padding: "11px 16px", background: section === s.id ? T.bg3 : "transparent",
            border: "none", borderLeft: `2px solid ${section === s.id ? T.accent : "transparent"}`,
            fontFamily: T.font, fontSize: 11, color: section === s.id ? T.accent : T.text2,
            cursor: "pointer", letterSpacing: "0.04em",
          }}>{s.label}</button>
        ))}
      </div>

      {/* Content */}
      <div style={{ flex: 1, minWidth: 0 }}>

        {/* ── Domains ── */}
        {section === "domains" && (
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, overflow: "hidden" }}>
            <div style={{ padding: "14px 16px", borderBottom: `1px solid ${T.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0 }}>Domains & Scan-Targets</div>
              <button onClick={() => { setShowAddDomain(true); setEditDomain(null); setNewDomain({ domain: "", ip_ranges: "", panos_version: "" }); setAddError(""); }} style={{
                background: T.accent, border: "none", borderRadius: 4, padding: "6px 14px",
                fontFamily: T.font, fontSize: 10, fontWeight: 700, color: T.bg0, cursor: "pointer",
              }}>+ Domain</button>
            </div>

            {showAddDomain && (
              <div style={{ padding: "14px 16px", borderBottom: `1px solid ${T.border}`, background: T.bg3 }}>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "flex-end" }}>
                  <div style={{ flex: 2, minWidth: 180 }}>
                    <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, marginBottom: 4 }}>DOMAIN</div>
                    <input value={editDomain ? editDomain.domain : newDomain.domain}
                      readOnly={!!editDomain}
                      onChange={e => setNewDomain(d => ({ ...d, domain: e.target.value }))}
                      placeholder="example.de"
                      style={{ width: "100%", background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 4, padding: "7px 10px", fontFamily: T.font, fontSize: 11, color: T.text0, outline: "none" }} />
                  </div>
                  <div style={{ flex: 2, minWidth: 160 }}>
                    <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, marginBottom: 4 }}>IP-RANGES (kommagetrennt)</div>
                    <input value={newDomain.ip_ranges}
                      onChange={e => setNewDomain(d => ({ ...d, ip_ranges: e.target.value }))}
                      placeholder="203.0.113.0/24"
                      style={{ width: "100%", background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 4, padding: "7px 10px", fontFamily: T.font, fontSize: 11, color: T.text0, outline: "none" }} />
                  </div>
                  <div style={{ flex: 1, minWidth: 100 }}>
                    <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, marginBottom: 4 }}>PANOS</div>
                    <input value={newDomain.panos_version}
                      onChange={e => setNewDomain(d => ({ ...d, panos_version: e.target.value }))}
                      placeholder="10.2.7"
                      style={{ width: "100%", background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 4, padding: "7px 10px", fontFamily: T.font, fontSize: 11, color: T.text0, outline: "none" }} />
                  </div>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button onClick={handleAddDomain} style={{ background: T.accent, border: "none", borderRadius: 4, padding: "7px 16px", fontFamily: T.font, fontSize: 10, fontWeight: 700, color: T.bg0, cursor: "pointer" }}>
                      {editDomain ? "Speichern" : "Hinzufügen"}
                    </button>
                    <button onClick={() => { setShowAddDomain(false); setEditDomain(null); setAddError(""); }} style={{ background: "transparent", border: `1px solid ${T.border}`, borderRadius: 4, padding: "7px 12px", fontFamily: T.font, fontSize: 10, color: T.text2, cursor: "pointer" }}>Abbrechen</button>
                  </div>
                </div>
                {addError && <div style={{ fontFamily: T.font, fontSize: 10, color: T.critical, marginTop: 8 }}>{addError}</div>}
              </div>
            )}

            {domainsLoading ? (
              <div style={{ padding: 24, textAlign: "center", fontFamily: T.font, fontSize: 11, color: T.text3 }}>Lade Domains…</div>
            ) : domains.length === 0 ? (
              <div style={{ padding: 24, textAlign: "center", fontFamily: T.font, fontSize: 11, color: T.text3 }}>Keine Domains konfiguriert. Füge eine Domain hinzu um Scans zu starten.</div>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    <TH>Domain</TH><TH>Status</TH><TH>Last Scan</TH>
                    <TH right>Findings</TH><TH right>Score</TH><TH>IP-Ranges</TH><TH>PAN-OS</TH><TH>Added</TH><TH></TH>
                  </tr>
                </thead>
                <tbody>
                  {domains.map(d => (
                    <tr key={d.id} style={{ borderTop: `1px solid ${T.border}` }}>
                      <TD mono>{d.domain}</TD>
                      <TD>
                        <span onClick={() => toggleDomainStatus(d)} title="Klicken zum Umschalten" style={{
                          fontFamily: T.font, fontSize: 9, fontWeight: 700,
                          color: STATUS_COLOR[d.status] || T.text3,
                          cursor: "pointer",
                        }}>{d.status}</span>
                      </TD>
                      <TD mono muted>{d.last_scan ? d.last_scan.slice(0, 16).replace("T", " ") : "—"}</TD>
                      <TD right><span style={{ fontFamily: T.font, fontSize: 11, color: d.findings_count > 0 ? T.high : T.text3 }}>{d.findings_count ?? 0}</span></TD>
                      <TD right><span style={{ fontFamily: T.font, fontSize: 11, color: T.text2 }}>{d.risk_score ?? "—"}</span></TD>
                      <TD mono muted>{(d.ip_ranges || []).join(", ") || "—"}</TD>
                      <TD mono muted>{d.panos_version || "—"}</TD>
                      <TD mono muted>{d.added || "—"}</TD>
                      <TD>
                        <div style={{ display: "flex", gap: 6 }}>
                          <button onClick={() => {
                            setEditDomain(d);
                            setNewDomain({ domain: d.domain, ip_ranges: (d.ip_ranges || []).join(", "), panos_version: d.panos_version || "" });
                            setShowAddDomain(true); setAddError("");
                          }} style={{ background: "transparent", border: `1px solid ${T.border}`, borderRadius: 3, padding: "3px 8px", fontFamily: T.font, fontSize: 9, color: T.text2, cursor: "pointer" }}>Edit</button>
                          {confirmDelete === d.id ? (
                            <>
                              <button onClick={() => handleDeleteDomain(d.id)} style={{ background: T.critical, border: "none", borderRadius: 3, padding: "3px 8px", fontFamily: T.font, fontSize: 9, color: "#fff", cursor: "pointer", fontWeight: 700 }}>Ja, löschen</button>
                              <button onClick={() => setConfirmDelete(null)} style={{ background: "transparent", border: `1px solid ${T.border}`, borderRadius: 3, padding: "3px 8px", fontFamily: T.font, fontSize: 9, color: T.text2, cursor: "pointer" }}>Abbrechen</button>
                            </>
                          ) : (
                            <button onClick={() => setConfirmDelete(d.id)} style={{ background: "transparent", border: `1px solid ${T.border}`, borderRadius: 3, padding: "3px 8px", fontFamily: T.font, fontSize: 9, color: T.text3, cursor: "pointer" }}>Löschen</button>
                          )}
                        </div>
                      </TD>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* ── Schedule ── */}
        {section === "schedule" && (
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, overflow: "hidden" }}>
            <div style={{ padding: "14px 16px", borderBottom: `1px solid ${T.border}` }}>
              <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0 }}>Automatische Scan-Zeitpläne</div>
            </div>
            {settingsLoading ? (
              <div style={{ padding: 24, textAlign: "center", fontFamily: T.font, fontSize: 11, color: T.text3 }}>Lade…</div>
            ) : (
              <div style={{ padding: 16 }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      <TH>Scan-Typ</TH><TH>Aktiv</TH><TH>Intervall</TH><TH>Uhrzeit</TH><TH>Tage</TH>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(schedule).map(([key, val]) => (
                      <tr key={key} style={{ borderTop: `1px solid ${T.border}` }}>
                        <TD><span style={{ fontFamily: T.font, fontSize: 11, color: T.text0 }}>{key.replace(/_/g, " ")}</span></TD>
                        <TD>
                          <input type="checkbox" checked={val.enabled}
                            onChange={e => setSchedule(s => ({ ...s, [key]: { ...s[key], enabled: e.target.checked } }))} />
                        </TD>
                        <TD>
                          <select value={val.interval} onChange={e => setSchedule(s => ({ ...s, [key]: { ...s[key], interval: e.target.value } }))}
                            style={{ background: T.bg3, border: `1px solid ${T.border}`, borderRadius: 3, padding: "4px 8px", fontFamily: T.font, fontSize: 10, color: T.text0 }}>
                            <option value="daily">täglich</option>
                            <option value="weekly">wöchentlich</option>
                            <option value="monthly">monatlich</option>
                          </select>
                        </TD>
                        <TD>
                          <input type="time" value={val.time}
                            onChange={e => setSchedule(s => ({ ...s, [key]: { ...s[key], time: e.target.value } }))}
                            style={{ background: T.bg3, border: `1px solid ${T.border}`, borderRadius: 3, padding: "4px 8px", fontFamily: T.font, fontSize: 10, color: T.text0 }} />
                        </TD>
                        <TD mono muted>{val.days}</TD>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <button onClick={saveSchedule} style={{
                  marginTop: 16, background: T.accent, border: "none", borderRadius: 4,
                  padding: "8px 20px", fontFamily: T.font, fontSize: 10, fontWeight: 700,
                  color: T.bg0, cursor: "pointer",
                }}>{saved.schedule ? "✓ Gespeichert" : "Zeitplan speichern"}</button>
              </div>
            )}
          </div>
        )}

        {/* ── Notifications ── */}
        {section === "notifications" && (
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, overflow: "hidden" }}>
            <div style={{ padding: "14px 16px", borderBottom: `1px solid ${T.border}` }}>
              <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0 }}>Benachrichtigungen</div>
            </div>
            {settingsLoading ? (
              <div style={{ padding: 24, textAlign: "center", fontFamily: T.font, fontSize: 11, color: T.text3 }}>Lade…</div>
            ) : (
              <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 14 }}>
                {[
                  { key: "email",         label: "E-Mail",             placeholder: "security@example.de", hasValue: true },
                  { key: "slack_webhook", label: "Slack Webhook-URL",  placeholder: "https://hooks.slack.com/...", hasValue: true },
                ].map(({ key, label, placeholder, hasValue }) => (
                  <div key={key} style={{ display: "flex", gap: 12, alignItems: "center" }}>
                    <input type="checkbox" checked={notif[key]?.enabled}
                      onChange={e => setNotif(n => ({ ...n, [key]: { ...n[key], enabled: e.target.checked } }))} />
                    <div style={{ fontFamily: T.font, fontSize: 11, color: T.text1, width: 140 }}>{label}</div>
                    {hasValue && (
                      <input value={notif[key]?.value || ""}
                        onChange={e => setNotif(n => ({ ...n, [key]: { ...n[key], value: e.target.value } }))}
                        placeholder={placeholder}
                        disabled={!notif[key]?.enabled}
                        style={{ flex: 1, background: T.bg3, border: `1px solid ${T.border}`, borderRadius: 4, padding: "7px 10px", fontFamily: T.font, fontSize: 11, color: T.text0, outline: "none", opacity: notif[key]?.enabled ? 1 : 0.4 }} />
                    )}
                  </div>
                ))}
                <div style={{ height: 1, background: T.border }} />
                {[
                  { key: "critical_only", label: "Nur CRITICAL-Findings benachrichtigen" },
                  { key: "report_weekly", label: "Wöchentlichen Report senden" },
                ].map(({ key, label }) => (
                  <div key={key} style={{ display: "flex", gap: 12, alignItems: "center" }}>
                    <input type="checkbox" checked={notif[key]?.enabled}
                      onChange={e => setNotif(n => ({ ...n, [key]: { ...n[key], enabled: e.target.checked } }))} />
                    <div style={{ fontFamily: T.font, fontSize: 11, color: T.text1 }}>{label}</div>
                  </div>
                ))}
                <button onClick={saveNotifications} style={{
                  alignSelf: "flex-start", marginTop: 4,
                  background: T.accent, border: "none", borderRadius: 4,
                  padding: "8px 20px", fontFamily: T.font, fontSize: 10, fontWeight: 700,
                  color: T.bg0, cursor: "pointer",
                }}>{saved.notif ? "✓ Gespeichert" : "Benachrichtigungen speichern"}</button>
              </div>
            )}
          </div>
        )}

        {/* ── Access & RBAC ── */}
        {section === "access" && (
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, padding: 24, textAlign: "center" }}>
            <div style={{ fontFamily: T.font, fontSize: 11, color: T.text3 }}>User-Management folgt in einer nächsten Version.</div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AdminTab;
