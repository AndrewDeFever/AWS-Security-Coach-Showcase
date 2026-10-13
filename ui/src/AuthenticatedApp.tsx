import { useEffect, useRef, useState } from "react";
import { CircleUserRound, Loader2, LogIn, LogOut, Plus, ShieldCheck } from "lucide-react";
import App from "./App";
import { useOidcAuth } from "./auth";
import { API_BASE_URL } from "./config";
import { LegalPage, SiteFooter, legalPageFromHash, type LegalPageName } from "./legalPages";
import OperatorConnectorManagement from "./operatorConnectorManagement";
import OperatorConnectorOnboarding from "./operatorConnectorOnboarding";
import OperatorManagedAssessment from "./operatorManagedAssessment";

const CONNECTOR_ONBOARDING_INTENT_KEY = "aws-security-coach-connector-onboarding-intent";
const TARGET_REFRESH_INTERVAL_MS = 5_000;
const TARGET_REFRESH_WINDOW_MS = 5 * 60_000;

function targetSignature(payload: unknown): string {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return "";
  const root = payload as Record<string, unknown>;
  const targets = Array.isArray(root.targets) ? root.targets : [];
  return targets
    .map(value => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {})
    .filter(item => String(item.targetType ?? "") === "connector")
    .map(item => String(item.connectorId ?? "").trim())
    .filter(Boolean)
    .sort()
    .join("|");
}

export default function AuthenticatedApp() {
  const auth = useOidcAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [resumeConnectorOnboarding, setResumeConnectorOnboarding] = useState(false);
  const [targetRefreshEpoch, setTargetRefreshEpoch] = useState(0);
  const [hasConnector, setHasConnector] = useState(false);
  const [legalPage, setLegalPage] = useState<LegalPageName | null>(() => legalPageFromHash(window.location.hash));
  const menuRef = useRef<HTMLDivElement | null>(null);
  const targetSignatureRef = useRef<string | null>(null);

  useEffect(() => {
    function syncLegalPage() {
      setLegalPage(legalPageFromHash(window.location.hash));
      window.scrollTo({ top: 0, behavior: "auto" });
    }
    window.addEventListener("hashchange", syncLegalPage);
    return () => window.removeEventListener("hashchange", syncLegalPage);
  }, []);

  useEffect(() => {
    function closeOnOutsideClick(event: MouseEvent) {
      if (!menuRef.current?.contains(event.target as Node)) setMenuOpen(false);
    }

    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") setMenuOpen(false);
    }

    document.addEventListener("mousedown", closeOnOutsideClick);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("mousedown", closeOnOutsideClick);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, []);

  useEffect(() => {
    if (!auth.isAuthenticated) return;
    if (sessionStorage.getItem(CONNECTOR_ONBOARDING_INTENT_KEY) !== "1") return;
    sessionStorage.removeItem(CONNECTOR_ONBOARDING_INTENT_KEY);
    setResumeConnectorOnboarding(true);
  }, [auth.isAuthenticated]);

  useEffect(() => {
    if (!auth.isAuthenticated || !auth.accessToken) {
      targetSignatureRef.current = null;
      setHasConnector(false);
      return;
    }

    let disposed = false;
    let intervalId: number | null = null;
    let stopTimerId: number | null = null;
    const accessToken = auth.accessToken;

    async function refreshTargetInventory() {
      try {
        const response = await fetch(`${API_BASE_URL}/auth/targets`, {
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        if (!response.ok || disposed) return;
        const payload = await response.json();
        if (disposed) return;
        const nextSignature = targetSignature(payload);
        const previousSignature = targetSignatureRef.current;
        targetSignatureRef.current = nextSignature;
        setHasConnector(Boolean(nextSignature));
        if (previousSignature !== null && previousSignature !== nextSignature) {
          setTargetRefreshEpoch(value => value + 1);
        }
      } catch {
        // This is a best-effort view refresh. App remains the authority for user-visible target errors.
      }
    }

    function refreshOnFocus() {
      void refreshTargetInventory();
    }

    function refreshOnVisibility() {
      if (document.visibilityState === "visible") void refreshTargetInventory();
    }

    targetSignatureRef.current = null;
    void refreshTargetInventory();
    intervalId = window.setInterval(() => void refreshTargetInventory(), TARGET_REFRESH_INTERVAL_MS);
    stopTimerId = window.setTimeout(() => {
      if (intervalId !== null) {
        window.clearInterval(intervalId);
        intervalId = null;
      }
    }, TARGET_REFRESH_WINDOW_MS);
    window.addEventListener("focus", refreshOnFocus);
    document.addEventListener("visibilitychange", refreshOnVisibility);

    return () => {
      disposed = true;
      if (intervalId !== null) window.clearInterval(intervalId);
      if (stopTimerId !== null) window.clearTimeout(stopTimerId);
      window.removeEventListener("focus", refreshOnFocus);
      document.removeEventListener("visibilitychange", refreshOnVisibility);
    };
  }, [auth.isAuthenticated, auth.accessToken]);

  async function beginConnectorOnboarding() {
    sessionStorage.setItem(CONNECTOR_ONBOARDING_INTENT_KEY, "1");
    await auth.signIn();
  }

  const profileControl = (
    <div ref={menuRef} style={{ position: "relative" }}>
      <button
        type="button"
        className="button-secondary"
        aria-label={auth.isAuthenticated ? "Open profile menu" : "Sign in"}
        aria-haspopup="menu"
        aria-expanded={menuOpen}
        disabled={auth.isLoading}
        onClick={() => {
          if (auth.isAuthenticated) setMenuOpen(value => !value);
          else void auth.signIn();
        }}
        style={{ width: 42, height: 42, padding: 0, borderRadius: "50%" }}
      >
        {auth.isLoading ? (
          <Loader2 size={19} className="spin" />
        ) : auth.isAuthenticated ? (
          <ShieldCheck size={20} aria-hidden="true" />
        ) : (
          <CircleUserRound size={21} aria-hidden="true" />
        )}
      </button>

      {auth.isAuthenticated && menuOpen && (
        <div
          role="menu"
          aria-label="Security Coach profile"
          style={{
            position: "absolute",
            zIndex: 30,
            top: "calc(100% + 10px)",
            right: 0,
            width: 230,
            padding: 12,
            border: "1px solid rgba(148, 163, 184, 0.3)",
            borderRadius: 12,
            background: "rgba(15, 23, 42, 0.98)",
            boxShadow: "0 16px 34px rgba(0, 0, 0, 0.32)",
            color: "#e2e8f0",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 12 }}>
            <ShieldCheck size={17} aria-hidden="true" />
            <div>
              <div style={{ fontSize: 12, color: "#94a3b8" }}>Security Coach profile</div>
              <div style={{ marginTop: 2, fontSize: 14, fontWeight: 700 }}>Signed in</div>
            </div>
          </div>
          {auth.accessToken && <div className="profile-menu-connector"><OperatorManagedAssessment accessToken={auth.accessToken} /></div>}
          {auth.accessToken && <div className="profile-menu-connector"><OperatorConnectorManagement accessToken={auth.accessToken} /></div>}
          <button
            type="button"
            role="menuitem"
            className="button-secondary profile-menu-signout"
            onClick={auth.signOut}
          >
            <span className="button-inline"><LogOut size={15} /> Sign out</span>
          </button>
        </div>
      )}

      {!auth.isAuthenticated && auth.error && (
        <div
          role="status"
          style={{
            position: "absolute",
            zIndex: 30,
            top: "calc(100% + 10px)",
            right: 0,
            width: 250,
            padding: 12,
            border: "1px solid rgba(248, 113, 113, 0.35)",
            borderRadius: 12,
            background: "rgba(15, 23, 42, 0.98)",
            color: "#fecaca",
            fontSize: 13,
          }}
        >
          {auth.error}
          <button
            type="button"
            className="button-secondary"
            onClick={() => void auth.signIn()}
            style={{ width: "100%", justifyContent: "center", marginTop: 10 }}
          >
            <span className="button-inline"><LogIn size={15} /> Try again</span>
          </button>
        </div>
      )}
    </div>
  );

  const identityControl = (
    <div className="identity-controls">
      {!auth.isAuthenticated && !auth.isLoading && (
        <button type="button" className="button-primary" onClick={() => void beginConnectorOnboarding()}>
          <span className="button-inline"><Plus size={16} /> Connect AWS Account</span>
        </button>
      )}
      {auth.isAuthenticated && auth.accessToken && (
        <OperatorConnectorOnboarding
          accessToken={auth.accessToken}
          hasConnector={hasConnector}
          autoOpen={resumeConnectorOnboarding}
          onAutoOpenHandled={() => setResumeConnectorOnboarding(false)}
        />
      )}
      {profileControl}
    </div>
  );

  return <>
    {legalPage ? (
      <LegalPage page={legalPage} />
    ) : (
      <App
        key={targetRefreshEpoch}
        identityControl={identityControl}
        accessToken={auth.accessToken}
        isAuthenticated={auth.isAuthenticated}
        isAuthLoading={auth.isLoading}
      />
    )}
    <SiteFooter />
  </>;
}
