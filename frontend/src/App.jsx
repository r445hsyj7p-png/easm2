import { useState } from "react";
import { getToken, clearToken, clearTenantId, getTenantId, saveTenantId } from "./api/client";
import { AppProvider } from "./context/AppContext";
import LoginPage from "./pages/LoginPage";
import AppShell from "./pages/AppShell";

export default function App() {
  const [authed,   setAuthed]   = useState(!!getToken());
  const [tenantId, setTenantId] = useState(() => getTenantId());

  if (authed && !tenantId) {
    clearToken();
    clearTenantId();
    window.location.reload();
    return null;
  }

  if (!authed) {
    return (
      <LoginPage onLogin={(tid) => { saveTenantId(tid); setTenantId(tid); setAuthed(true); }} />
    );
  }

  return (
    <AppProvider tenantId={tenantId}>
      <AppShell />
    </AppProvider>
  );
}
