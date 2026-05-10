import { useState, useEffect, useCallback, createContext, useContext } from "react";
import { apiFetch } from "../api/client";

export const AppCtx = createContext(null);
export function useApp() { return useContext(AppCtx); }

const EMPTY_TENANT = {
  domain:"—", score:0, grade:"?", active:false, last_scan:null, next_scan:null,
  assets:{subdomains:0,ips:0,ports:0,services:0},
  findings_summary:{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0},
  tool_stats:{},
};

export function AppProvider({ tenantId, children }) {
  const [tenant,  setTenant]   = useState(EMPTY_TENANT);
  const [findings,setFindings] = useState([]);
  const [assets,  setAssets]   = useState([]);
  const [mcp,     setMcp]      = useState([]);
  const [intel,   setIntel]    = useState(null);
  const [scans,   setScans]    = useState([]);
  const [loading, setLoading]  = useState(true);
  const [error,   setError]    = useState(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [t,f,a,m,i,s] = await Promise.all([
        apiFetch(`/tenants/${tenantId}`),
        apiFetch(`/tenants/${tenantId}/findings?limit=200`),
        apiFetch(`/tenants/${tenantId}/assets`),
        apiFetch(`/tenants/${tenantId}/mcp`),
        apiFetch(`/tenants/${tenantId}/intel`),
        apiFetch(`/tenants/${tenantId}/scans?limit=20`),
      ]);
      setTenant(t); setFindings(f.findings??f); setAssets(a.assets??a);
      setMcp(m.servers??m); setIntel(i); setScans(s.scans??s);
    } catch(e) { setError(e.message); }
    finally    { setLoading(false); }
  }, [tenantId]);

  useEffect(() => { load(); }, [load]);

  const updateFinding = useCallback(async (id, patch) => {
    setFindings(prev => prev.map(f => f.id===id ? {...f,...patch} : f));
    try { await apiFetch(`/tenants/${tenantId}/findings/${id}`, {method:"PATCH",body:patch}); }
    catch { load(); }
  }, [tenantId, load]);

  const triggerScan = useCallback(async (type="full") => {
    const job = await apiFetch(`/tenants/${tenantId}/scans`, {method:"POST",body:{scan_type:type}});
    setScans(prev => [job,...prev]); return job;
  }, [tenantId]);

  return (
    <AppCtx.Provider value={{tenant,findings,assets,mcp,intel,scans,loading,error,reload:load,updateFinding,triggerScan,tenantId}}>
      {children}
    </AppCtx.Provider>
  );
}
