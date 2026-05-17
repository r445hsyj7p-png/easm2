import { Toaster } from "sonner";
import { AppProvider } from "./context/AppContext";
import LoginPage from "./pages/LoginPage";
import AppShell from "./pages/AppShell";
import { useAuth } from "./hooks/useAuth";

export default function App() {
  const { authed, tenantId, handleLogin, handleLogout } = useAuth();

  // Corrupted auth state: token present but no tenant — force a clean slate.
  if (authed && !tenantId) {
    handleLogout();
    return null;
  }

  if (!authed) {
    return <LoginPage onLogin={handleLogin} />;
  }

  return (
    <AppProvider tenantId={tenantId}>
      <Toaster
        position="bottom-right"
        theme="dark"
        toastOptions={{ style: { fontFamily: "'JetBrains Mono', monospace", fontSize: 11 } }}
      />
      <AppShell />
    </AppProvider>
  );
}
