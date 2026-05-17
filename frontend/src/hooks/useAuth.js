import { useState } from "react";
import { getToken, clearToken, clearTenantId, getTenantId, saveTenantId } from "../api/client";

export function useAuth() {
  const [authed,   setAuthed]   = useState(!!getToken());
  const [tenantId, setTenantId] = useState(() => getTenantId());

  function handleLogin(tid) {
    saveTenantId(tid);
    setTenantId(tid);
    setAuthed(true);
  }

  function handleLogout() {
    clearToken();
    clearTenantId();
    window.location.reload();
  }

  return { authed, tenantId, handleLogin, handleLogout };
}
