import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, Clipboard, ExternalLink, Loader2, Plus, RefreshCw, ShieldCheck, X } from "lucide-react";
import { API_BASE_URL } from "./config";

const DISCLOSURE_VERSION = "1.0";
const HOME_REGION = "us-east-1";
const DRAFT_KEY = "aws-security-coach-managed-assessment-draft";

const STYLES = `
.managed-assessment-trigger{width:100%;justify-content:center}
.managed-assessment-backdrop{position:fixed;inset:0;z-index:90;display:flex;align-items:center;justify-content:center;padding:16px 22px;overflow:hidden;background:rgba(2,6,23,.8);backdrop-filter:blur(5px)}
.managed-assessment{display:flex;flex-direction:column;width:min(920px,96vw);max-height:calc(100vh - 32px);overflow:hidden;border:1px solid rgba(148,163,184,.28);border-radius:18px;background:#0f172a;box-shadow:0 28px 70px rgba(0,0,0,.5);color:#e2e8f0}
.managed-assessment-header{flex:0 0 auto;display:flex;align-items:flex-start;justify-content:space-between;gap:18px;padding:18px 22px;border-bottom:1px solid rgba(148,163,184,.18);background:rgba(15,23,42,.98)}
.managed-assessment-header h2{margin:3px 0 5px;font-size:23px}.managed-assessment-header p{margin:0;color:#94a3b8;font-size:13px}.managed-assessment-kicker{color:#38bdf8;font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase}
.managed-assessment-close{display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;border:1px solid rgba(148,163,184,.26);border-radius:10px;background:transparent;color:#cbd5e1;cursor:pointer}
.managed-assessment-body{min-height:0;padding:18px 22px 20px;overflow:hidden}.managed-assessment-step{margin-bottom:14px;color:#64748b;font-size:12px;font-weight:800;letter-spacing:.07em;text-transform:uppercase}
.managed-assessment-card{padding:18px;border:1px solid rgba(148,163,184,.18);border-radius:14px;background:rgba(2,6,23,.32)}.managed-assessment-card h3{margin:0 0 8px;font-size:19px}.managed-assessment-card p{margin:0 0 11px;color:#cbd5e1;line-height:1.52}
.managed-assessment-label{display:block;margin-top:11px;color:#cbd5e1;font-size:13px;font-weight:700}.managed-assessment-input{width:100%;box-sizing:border-box;margin-top:7px;padding:11px 12px;border:1px solid rgba(148,163,184,.34);border-radius:9px;background:#020617;color:#f8fafc;font:inherit}.managed-assessment-input:focus{outline:2px solid rgba(56,189,248,.35);border-color:#38bdf8}
.managed-assessment-actions{display:flex;align-items:center;justify-content:flex-end;flex-wrap:wrap;gap:10px;margin-top:14px}.managed-assessment-error{margin-bottom:14px;padding:12px 14px;border:1px solid rgba(248,113,113,.35);border-radius:10px;background:rgba(127,29,29,.18);color:#fecaca}.managed-assessment-note{margin:12px 0;padding:12px 14px;border:1px solid rgba(56,189,248,.2);border-radius:10px;background:rgba(14,116,144,.08);color:#bae6fd;font-size:13px;line-height:1.5}
.managed-assessment-resume{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-top:14px;padding:12px 14px;border:1px solid rgba(148,163,184,.2);border-radius:10px;background:rgba(15,23,42,.72)}.managed-assessment-resume-copy{min-width:0}.managed-assessment-resume-copy span{display:block;color:#64748b;font-size:10px;font-weight:800;letter-spacing:.05em;text-transform:uppercase}.managed-assessment-resume-copy strong{display:block;margin-top:4px;color:#e2e8f0;font-size:13px;overflow-wrap:anywhere}
.managed-assessment-secret{display:flex;gap:8px;align-items:stretch;margin-top:7px}.managed-assessment-secret code{flex:1;min-width:0;padding:10px 12px;border:1px solid rgba(148,163,184,.28);border-radius:9px;background:#020617;color:#f8fafc;overflow-wrap:anywhere;font-size:12px}.managed-assessment-copy{display:inline-flex;align-items:center;justify-content:center;min-width:42px;border:1px solid rgba(148,163,184,.28);border-radius:9px;background:#111827;color:#cbd5e1;cursor:pointer}
.managed-assessment-meta{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}.managed-assessment-meta>div{padding:10px 12px;border:1px solid rgba(148,163,184,.15);border-radius:9px;background:rgba(15,23,42,.7)}.managed-assessment-meta span{display:block;color:#64748b;font-size:10px;font-weight:800;text-transform:uppercase}.managed-assessment-meta strong{display:block;margin-top:4px;color:#e2e8f0;font-size:13px;overflow-wrap:anywhere}
.managed-assessment-packet{width:100%;height:170px;min-height:140px;box-sizing:border-box;margin-top:8px;padding:12px 14px;overflow:auto;border:1px solid rgba(148,163,184,.22);border-radius:10px;background:#020617;color:#cbd5e1;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;resize:none}
.managed-assessment-success{display:flex;align-items:flex-start;gap:12px;color:#86efac}.managed-assessment-success-icon{display:inline-flex;align-items:center;justify-content:center;width:42px;height:42px;flex:0 0 42px;border-radius:50%;background:rgba(34,197,94,.14)}
@media(max-width:620px){.managed-assessment-backdrop{align-items:stretch;padding:0}.managed-assessment{width:100vw;height:100vh;max-height:100vh;border-radius:0}.managed-assessment-header{padding:19px}.managed-assessment-body{padding:19px;overflow:auto}.managed-assessment-actions{justify-content:stretch}.managed-assessment-actions button{flex:1}.managed-assessment-meta{grid-template-columns:1fr}.managed-assessment-packet{height:220px;min-height:180px;resize:vertical}.managed-assessment-resume{align-items:stretch;flex-direction:column}.managed-assessment-resume button{width:100%;justify-content:center}}
`;

type Stage = "details" | "handoff" | "role" | "approval" | "complete";
type ManagedConnector = {
  connectorId: string;
  displayName: string;
  customerOrganization?: string;
  status: string;
  expectedAccountId?: string;
  homeRegion?: string;
  templateVersion?: string;
  disclosureAcknowledged?: boolean;
  externalId?: string;
  quickCreateUrl?: string;
  stackName?: string;
};
type Draft = { connectorId: string; displayName: string; customerOrganization: string };

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function normalizeConnector(value: unknown): ManagedConnector | null {
  const item = record(value);
  const connectorId = String(item.connectorId ?? "").trim();
  const displayName = String(item.displayName ?? "").trim();
  if (!connectorId || !displayName) return null;
  return {
    connectorId,
    displayName,
    customerOrganization: typeof item.customerOrganization === "string" ? item.customerOrganization : undefined,
    status: String(item.status ?? "").trim(),
    expectedAccountId: typeof item.expectedAccountId === "string" ? item.expectedAccountId : undefined,
    homeRegion: typeof item.homeRegion === "string" ? item.homeRegion : undefined,
    templateVersion: typeof item.templateVersion === "string" ? item.templateVersion : undefined,
    disclosureAcknowledged: item.disclosureAcknowledged === true,
    externalId: typeof item.externalId === "string" ? item.externalId : undefined,
    quickCreateUrl: typeof item.quickCreateUrl === "string" ? item.quickCreateUrl : undefined,
    stackName: typeof item.stackName === "string" ? item.stackName : undefined,
  };
}

function readDraft(): Draft | null {
  try {
    const parsed = record(JSON.parse(localStorage.getItem(DRAFT_KEY) || "{}"));
    const connectorId = String(parsed.connectorId ?? "").trim();
    const displayName = String(parsed.displayName ?? "").trim();
    const customerOrganization = String(parsed.customerOrganization ?? "").trim();
    return connectorId && displayName && customerOrganization ? { connectorId, displayName, customerOrganization } : null;
  } catch {
    return null;
  }
}

function writeDraft(connector: ManagedConnector) {
  localStorage.setItem(DRAFT_KEY, JSON.stringify({
    connectorId: connector.connectorId,
    displayName: connector.displayName,
    customerOrganization: connector.customerOrganization || "",
  }));
}

function clearDraft() {
  localStorage.removeItem(DRAFT_KEY);
}

async function responsePayload(response: Response) {
  return record(await response.json().catch(() => ({})));
}

function hasHandoff(connector: ManagedConnector) {
  return connector.disclosureAcknowledged === true && Boolean(connector.externalId && connector.quickCreateUrl && connector.stackName);
}

export default function OperatorManagedAssessment({ accessToken }: { accessToken: string }) {
  const [operatorAvailable, setOperatorAvailable] = useState(false);
  const [inventory, setInventory] = useState<ManagedConnector[]>([]);
  const [open, setOpen] = useState(false);
  const [stage, setStage] = useState<Stage>("details");
  const [displayName, setDisplayName] = useState("");
  const [customerOrganization, setCustomerOrganization] = useState("");
  const [connector, setConnector] = useState<ManagedConnector | null>(null);
  const [resumableDraft, setResumableDraft] = useState<Draft | null>(null);
  const [connectorRoleArn, setConnectorRoleArn] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState("");

  const canRegister = useMemo(() => /^arn:aws:iam::\d{12}:role\/aws-security-coach\/.+/.test(connectorRoleArn.trim()), [connectorRoleArn]);

  async function loadInventory(signal?: AbortSignal) {
    if (!accessToken) return;
    try {
      const response = await fetch(`${API_BASE_URL}/auth/connectors`, {
        headers: { Authorization: `Bearer ${accessToken}` },
        signal,
      });
      if (response.status === 403) {
        setOperatorAvailable(false);
        setInventory([]);
        return;
      }
      if (!response.ok) return;
      const payload = await responsePayload(response);
      const items = Array.isArray(payload.connectors) ? payload.connectors : [];
      setInventory(items.map(normalizeConnector).filter((item): item is ManagedConnector => item !== null));
      setOperatorAvailable(true);
    } catch (caught: unknown) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
    }
  }

  useEffect(() => {
    const controller = new AbortController();
    void loadInventory(controller.signal);
    return () => controller.abort();
  }, [accessToken]);

  useEffect(() => {
    if (!open) return;
    function closeOnEscape(event: KeyboardEvent) { if (event.key === "Escape" && !busy) close(); }
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [open, busy]);

  function resetNew() {
    setStage("details");
    setDisplayName("");
    setCustomerOrganization("");
    setConnector(null);
    setConnectorRoleArn("");
    setError("");
    setCopied("");
  }

  function close() {
    if (busy) return;
    setOpen(false);
    setError("");
    setCopied("");
  }

  async function loadSetup(connectorId: string): Promise<ManagedConnector> {
    const response = await fetch(`${API_BASE_URL}/auth/connectors/${encodeURIComponent(connectorId)}/setup`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const payload = await responsePayload(response);
    if (!response.ok) throw new Error(`Managed setup could not be loaded: ${String(payload.code ?? "CONNECTOR_SETUP_FAILED")}`);
    const setup = normalizeConnector(payload.connector);
    if (!setup) throw new Error("Managed setup response was incomplete.");
    return setup;
  }

  async function ensureCustomerHandoff(connectorId: string): Promise<ManagedConnector> {
    const current = await loadSetup(connectorId);
    if (hasHandoff(current)) return current;

    const response = await fetch(`${API_BASE_URL}/auth/connectors/${encodeURIComponent(connectorId)}/setup`, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ acknowledged: true, disclosureVersion: DISCLOSURE_VERSION }),
    });
    const payload = await responsePayload(response);
    if (!response.ok) throw new Error(`Customer handoff could not be prepared: ${String(payload.code ?? "CONNECTOR_SETUP_FAILED")}`);
    const setup = normalizeConnector(payload.connector);
    if (!setup || !hasHandoff(setup)) throw new Error("Protected customer handoff material was incomplete.");
    return setup;
  }

  function openWorkflow() {
    const draft = readDraft();
    resetNew();
    setResumableDraft(draft);
    setOpen(true);
  }

  async function resumePreviousAssessment() {
    const draft = resumableDraft ?? readDraft();
    if (!draft) return;

    setError("");
    setCopied("");
    setDisplayName(draft.displayName);
    setCustomerOrganization(draft.customerOrganization);
    const existing = inventory.find(item => item.connectorId === draft.connectorId);

    if (existing?.status === "APPROVAL_PENDING" || existing?.status === "VALIDATING") {
      setConnector(existing);
      setStage("approval");
      return;
    }
    if (existing?.status === "ENABLED") {
      setConnector(existing);
      setStage("complete");
      clearDraft();
      setResumableDraft(null);
      return;
    }
    if (existing?.status === "REVOKED") {
      clearDraft();
      setResumableDraft(null);
      resetNew();
      return;
    }

    setBusy(true);
    try {
      const setup = await ensureCustomerHandoff(draft.connectorId);
      const restored = { ...setup, customerOrganization: setup.customerOrganization || draft.customerOrganization };
      setConnector(restored);
      writeDraft(restored);
      setResumableDraft({ connectorId: restored.connectorId, displayName: restored.displayName, customerOrganization: restored.customerOrganization || draft.customerOrganization });
      setStage("handoff");
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : "Managed customer handoff could not be restored.");
      if (!existing) {
        clearDraft();
        setResumableDraft(null);
      }
    } finally {
      setBusy(false);
    }
  }

  async function createManagedConnector() {
    const name = displayName.trim();
    const organization = customerOrganization.trim();
    if (!organization) {
      setError("Enter the customer or organization name that should appear on the managed reports.");
      return;
    }
    if (!name) {
      setError("Give this AWS account an internal connector name before continuing.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const response = await fetch(`${API_BASE_URL}/auth/connectors`, {
        method: "POST",
        headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ displayName: name, customerOrganization: organization, homeRegion: HOME_REGION }),
      });
      const payload = await responsePayload(response);
      if (!response.ok) throw new Error(`Managed connector could not be created: ${String(payload.code ?? "CONNECTOR_CREATE_FAILED")}`);
      const created = normalizeConnector(payload.connector);
      if (!created) throw new Error("Managed connector creation returned no connector reference.");
      writeDraft(created);

      const setup = await ensureCustomerHandoff(created.connectorId);
      const prepared = { ...created, ...setup, customerOrganization: setup.customerOrganization || created.customerOrganization || organization };
      setConnector(prepared);
      writeDraft(prepared);
      setResumableDraft({ connectorId: prepared.connectorId, displayName: prepared.displayName, customerOrganization: prepared.customerOrganization || organization });
      setStage("handoff");
      await loadInventory();
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : "Managed connector could not be created.");
    } finally {
      setBusy(false);
    }
  }

  async function refreshHandoffLink() {
    if (!connector) return;
    setBusy(true);
    setError("");
    try {
      const setup = await ensureCustomerHandoff(connector.connectorId);
      const refreshed = { ...connector, ...setup, customerOrganization: setup.customerOrganization || connector.customerOrganization };
      setConnector(refreshed);
      writeDraft(refreshed);
      setResumableDraft({ connectorId: refreshed.connectorId, displayName: refreshed.displayName, customerOrganization: refreshed.customerOrganization || customerOrganization.trim() });
      setCopied("");
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : "Fresh AWS setup link could not be generated.");
    } finally {
      setBusy(false);
    }
  }

  function customerPacket() {
    if (!connector?.externalId || !connector.quickCreateUrl || !connector.stackName) return "";
    const stackRegion = connector.homeRegion || HOME_REGION;
    return [
      "AWS Security Posture Review — Secure Connection Instructions",
      "",
      "No AWS credentials are required for this assessment. Please do NOT send an AWS password, access key, secret access key, or console credentials.",
      "",
      "1. Open the AWS CloudFormation setup link below while signed in to the AWS account you want assessed.",
      "2. In Parameters, paste the External ID shown below.",
      "3. Review the dedicated read-only IAM role and permissions, continue to the bottom, acknowledge the IAM capability, and choose Create stack.",
      "4. Wait for the CloudFormation deployment to reach CREATE_COMPLETE. AWS may show this in Table view or Timeline view.",
      "5. Open the Outputs tab and send me ONLY the ConnectorRoleArn value.",
      "",
      `External ID: ${connector.externalId}`,
      "",
      `AWS CloudFormation setup link: ${connector.quickCreateUrl}`,
      "",
      `CloudFormation stack Region: ${stackRegion}`,
      "This Region is only the connector stack setup/lifecycle location; it is not the assessment coverage boundary.",
      "",
      `Expected stack name: ${connector.stackName}`,
      ...(connector.templateVersion ? ["", `Connector template version: ${connector.templateVersion}`] : []),
      "",
      "The AWS launch link is short-lived. If AWS reports that it expired, I can generate a fresh link without changing your External ID.",
      "",
      `To remove assessment access later, delete the CloudFormation stack named ${connector.stackName} from your AWS account.`,
    ].join("\n");
  }

  async function copyText(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
      window.setTimeout(() => setCopied(""), 1800);
    } catch {
      setError("Copy failed. Select the value manually.");
    }
  }

  async function registerThenEnable() {
    if (!connector || !canRegister) return;
    setBusy(true);
    setError("");
    try {
      const registerResponse = await fetch(`${API_BASE_URL}/auth/connectors/${encodeURIComponent(connector.connectorId)}/register`, {
        method: "POST",
        headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ connectorRoleArn: connectorRoleArn.trim() }),
      });
      const registerPayload = await responsePayload(registerResponse);
      if (!registerResponse.ok) throw new Error(`Connection verification failed: ${String(registerPayload.code ?? "CONNECTOR_REGISTRATION_FAILED")}`);
      const registered = normalizeConnector(registerPayload.connector);
      if (!registered || registered.status !== "APPROVAL_PENDING") throw new Error("Connection verification did not reach the expected approval state.");
      const pending = { ...connector, ...registered, customerOrganization: registered.customerOrganization || connector.customerOrganization };
      setConnector(pending);
      writeDraft(pending);
      setResumableDraft({ connectorId: pending.connectorId, displayName: pending.displayName, customerOrganization: pending.customerOrganization || customerOrganization.trim() });
      setStage("approval");

      const enableResponse = await fetch(`${API_BASE_URL}/auth/connectors/${encodeURIComponent(connector.connectorId)}/enable`, {
        method: "POST",
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const enablePayload = await responsePayload(enableResponse);
      if (!enableResponse.ok) throw new Error(`Fresh approval validation failed: ${String(enablePayload.code ?? "CONNECTOR_ENABLE_FAILED")}`);
      const enabled = normalizeConnector({ ...pending, ...record(enablePayload.connector) });
      if (!enabled || enabled.status !== "ENABLED") throw new Error("Managed connector did not reach ENABLED after approval validation.");
      setConnector({ ...pending, ...enabled, customerOrganization: enabled.customerOrganization || pending.customerOrganization });
      clearDraft();
      setResumableDraft(null);
      setStage("complete");
      await loadInventory();
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : "Managed connection could not be enabled.");
    } finally {
      setBusy(false);
    }
  }

  async function enablePendingConnector() {
    if (!connector) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch(`${API_BASE_URL}/auth/connectors/${encodeURIComponent(connector.connectorId)}/enable`, {
        method: "POST",
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const payload = await responsePayload(response);
      if (!response.ok) throw new Error(`Fresh approval validation failed: ${String(payload.code ?? "CONNECTOR_ENABLE_FAILED")}`);
      const enabled = normalizeConnector({ ...connector, ...record(payload.connector) });
      if (!enabled || enabled.status !== "ENABLED") throw new Error("Managed connector did not reach ENABLED after approval validation.");
      setConnector({ ...connector, ...enabled, customerOrganization: enabled.customerOrganization || connector.customerOrganization });
      clearDraft();
      setResumableDraft(null);
      setStage("complete");
      await loadInventory();
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : "Managed connection could not be enabled.");
    } finally {
      setBusy(false);
    }
  }

  if (!operatorAvailable) return null;

  return <>
    <style>{STYLES}</style>
    <button type="button" className="button-primary managed-assessment-trigger" onClick={openWorkflow}>
      <span className="button-inline"><Plus size={16}/> New Managed Assessment</span>
    </button>

    {open && <div className="managed-assessment-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) close(); }}>
      <section className="managed-assessment" role="dialog" aria-modal="true" aria-label="New managed assessment">
        <header className="managed-assessment-header">
          <div>
            <div className="managed-assessment-kicker">Operator workflow</div>
            <h2>New Managed Assessment</h2>
            <p>Prepare a customer-controlled read-only AWS connection without requiring the customer to use Security Coach.</p>
          </div>
          <button type="button" className="managed-assessment-close" aria-label="Close managed assessment" disabled={busy} onClick={close}><X size={20}/></button>
        </header>

        <div className="managed-assessment-body">
          {error && <div className="managed-assessment-error">{error}</div>}

          {stage === "details" && <>
            <div className="managed-assessment-step">Step 1 of 4 · Identify customer and AWS account</div>
            <div className="managed-assessment-card">
              <h3>Set the customer-facing and operator identifiers</h3>
              <p>The customer or organization name is printed on the managed reports. The internal connector name remains operator-only and is used for inventory and scan targeting.</p>
              <label className="managed-assessment-label">Customer / Organization
                <input className="managed-assessment-input" value={customerOrganization} maxLength={120} onChange={event => setCustomerOrganization(event.target.value)} placeholder="Acme Corporation" autoFocus />
              </label>
              <label className="managed-assessment-label">Internal account / connector name
                <input className="managed-assessment-input" value={displayName} maxLength={80} onChange={event => setDisplayName(event.target.value)} placeholder="Acme - Production" />
              </label>
              <div className="managed-assessment-note">The AWS account ID is not typed here. It is captured from the validated ConnectorRoleArn/account match and printed on the managed reports only after verification.</div>

              {resumableDraft && <div className="managed-assessment-resume">
                <div className="managed-assessment-resume-copy"><span>Unfinished managed assessment</span><strong>{resumableDraft.customerOrganization} · {resumableDraft.displayName}</strong></div>
                <button type="button" className="button-secondary" disabled={busy} onClick={() => void resumePreviousAssessment()}>Resume Previous Assessment</button>
              </div>}

              <div className="managed-assessment-actions">
                <button type="button" className="button-primary" disabled={busy || !displayName.trim() || !customerOrganization.trim()} onClick={() => void createManagedConnector()}>
                  <span className="button-inline">{busy && <Loader2 size={16} className="spin"/>} Create Assessment Connector</span>
                </button>
              </div>
            </div>
          </>}

          {stage === "handoff" && connector?.externalId && connector.quickCreateUrl && connector.stackName && <>
            <div className="managed-assessment-step">Step 2 of 4 · Send customer handoff</div>
            <div className="managed-assessment-card">
              <h3>Customer handoff is ready</h3>
              <p>Send the customer the instructions below. The AWS launch link is intentionally refreshable because the underlying template URL is short-lived.</p>
              <div className="managed-assessment-meta">
                <div><span>CloudFormation stack Region</span><strong>{connector.homeRegion || HOME_REGION}</strong></div>
                <div><span>Connector template</span><strong>{connector.templateVersion || "Current released template"}</strong></div>
              </div>
              <div className="managed-assessment-note">The CloudFormation stack Region is the connector setup/lifecycle location only. It does not limit the assessment's AWS Region coverage.</div>
              <label className="managed-assessment-label">External ID</label>
              <div className="managed-assessment-secret"><code>{connector.externalId}</code><button type="button" className="managed-assessment-copy" aria-label="Copy External ID" onClick={() => void copyText(connector.externalId || "", "external")}>{copied === "external" ? <CheckCircle2 size={17}/> : <Clipboard size={17}/>}</button></div>
              <label className="managed-assessment-label">Customer instructions</label>
              <textarea className="managed-assessment-packet" readOnly value={customerPacket()} />
              <div className="managed-assessment-actions">
                <button type="button" className="button-secondary" disabled={busy} onClick={() => void refreshHandoffLink()}><span className="button-inline">{busy ? <Loader2 size={16} className="spin"/> : <RefreshCw size={16}/>} Refresh AWS Link</span></button>
                <button type="button" className="button-secondary" onClick={() => window.open(connector.quickCreateUrl, "_blank", "noopener,noreferrer")}><span className="button-inline"><ExternalLink size={16}/> Open AWS CloudFormation</span></button>
                <button type="button" className="button-secondary" onClick={() => void copyText(connector.quickCreateUrl || "", "aws-link")}><span className="button-inline">{copied === "aws-link" ? <CheckCircle2 size={16}/> : <Clipboard size={16}/>} {copied === "aws-link" ? "AWS Link Copied" : "Copy AWS Link"}</span></button>
                <button type="button" className="button-primary" onClick={() => void copyText(customerPacket(), "packet")}><span className="button-inline">{copied === "packet" ? <CheckCircle2 size={16}/> : <Clipboard size={16}/>} {copied === "packet" ? "Copied" : "Copy Customer Instructions"}</span></button>
                <button type="button" className="button-primary" onClick={() => { setError(""); setStage("role"); }}>Customer Created Stack</button>
              </div>
            </div>
          </>}

          {stage === "role" && connector && <>
            <div className="managed-assessment-step">Step 3 of 4 · Verify and enable</div>
            <div className="managed-assessment-card">
              <h3>Enter the customer’s ConnectorRoleArn</h3>
              <p>Paste only the <strong>ConnectorRoleArn</strong> from the customer’s CloudFormation Outputs tab. Security Coach will validate the connector, then perform the existing fresh operator approval validation before enabling it.</p>
              <label className="managed-assessment-label">ConnectorRoleArn
                <input className="managed-assessment-input" value={connectorRoleArn} onChange={event => setConnectorRoleArn(event.target.value)} placeholder="arn:aws:iam::<AWS_ACCOUNT_ID>:role/aws-security-coach/..." />
              </label>
              <div className="managed-assessment-note">One operator action performs the existing registration validation followed by the existing fresh approval/revalidation. The trust boundary is unchanged.</div>
              <div className="managed-assessment-actions">
                <button type="button" className="button-secondary" disabled={busy} onClick={() => setStage("handoff")}>Back to Handoff</button>
                <button type="button" className="button-primary" disabled={busy || !canRegister} onClick={() => void registerThenEnable()}>
                  <span className="button-inline">{busy && <Loader2 size={16} className="spin"/>} Verify & Enable</span>
                </button>
              </div>
            </div>
          </>}

          {stage === "approval" && connector && <>
            <div className="managed-assessment-step">Step 3 of 4 · Approval validation</div>
            <div className="managed-assessment-card">
              <h3>Connection is awaiting fresh approval validation</h3>
              <p>Registration completed successfully. If the automatic approval pass was interrupted or failed transiently, retry the existing operator enable/revalidation action here.</p>
              <div className="managed-assessment-meta">
                <div><span>Customer / Organization</span><strong>{connector.customerOrganization || customerOrganization}</strong></div>
                <div><span>Connection</span><strong>{connector.displayName}</strong></div>
                <div><span>Status</span><strong>{connector.status || "APPROVAL_PENDING"}</strong></div>
              </div>
              <div className="managed-assessment-actions">
                <button type="button" className="button-primary" disabled={busy} onClick={() => void enablePendingConnector()}>
                  <span className="button-inline">{busy && <Loader2 size={16} className="spin"/>} Approve & Revalidate</span>
                </button>
              </div>
            </div>
          </>}

          {stage === "complete" && connector && <>
            <div className="managed-assessment-step">Step 4 of 4 · Ready to assess</div>
            <div className="managed-assessment-card">
              <div className="managed-assessment-success"><span className="managed-assessment-success-icon"><ShieldCheck size={22}/></span><div><h3>Managed connection enabled</h3><p>The customer’s read-only connector is enabled and can now be selected as a scan target by the operator.</p></div></div>
              <div className="managed-assessment-meta">
                <div><span>Customer / Organization</span><strong>{connector.customerOrganization || customerOrganization}</strong></div>
                <div><span>AWS account</span><strong>{connector.expectedAccountId || "Verified during validation"}</strong></div>
                <div><span>Connection</span><strong>{connector.displayName}</strong></div>
                <div><span>Status</span><strong>{connector.status || "ENABLED"}</strong></div>
              </div>
              <div className="managed-assessment-note">Customer-controlled disconnect remains unchanged: deleting the connector CloudFormation stack removes the dedicated AWS-side assessment role. Platform disable/revoke remains an operator control.</div>
              <div className="managed-assessment-actions">
                <button type="button" className="button-secondary" onClick={() => { clearDraft(); setResumableDraft(null); resetNew(); }}>Start Another</button>
                <button type="button" className="button-primary" onClick={close}>Done</button>
              </div>
            </div>
          </>}
        </div>
      </section>
    </div>}
  </>;
}
