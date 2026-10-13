import { useEffect, useMemo, useState } from "react";
import { Check, ChevronDown, ChevronUp, Clipboard, ExternalLink, Loader2, Plus, ShieldCheck, X } from "lucide-react";
import { API_BASE_URL } from "./config";

const DISCLOSURE_VERSION = "1.0";
const HOME_REGION = "us-east-1";
const CONNECTOR_PERMISSIONS = [
  "iam:GenerateCredentialReport",
  "iam:GetCredentialReport",
  "iam:GetAccountSummary",
  "iam:ListUsers",
  "iam:ListMFADevices",
  "iam:GetAccountPasswordPolicy",
  "cloudtrail:DescribeTrails",
  "s3:GetAccountPublicAccessBlock",
  "ec2:DescribeSecurityGroups (us-east-1)",
];

const STYLES = `
.connector-onboarding-trigger{white-space:nowrap}.connector-onboarding-backdrop{position:fixed;inset:0;z-index:70;display:flex;align-items:flex-start;justify-content:center;padding:5vh 22px 22px;background:rgba(2,6,23,.78);backdrop-filter:blur(5px)}.connector-onboarding{width:min(900px,96vw);max-height:90vh;overflow:auto;border:1px solid rgba(148,163,184,.28);border-radius:18px;background:#0f172a;box-shadow:0 28px 70px rgba(0,0,0,.5);color:#e2e8f0}.connector-onboarding-header{position:sticky;top:0;z-index:2;display:flex;align-items:flex-start;justify-content:space-between;gap:18px;padding:22px 24px;border-bottom:1px solid rgba(148,163,184,.18);background:rgba(15,23,42,.98)}.connector-onboarding-header h2{margin:3px 0 5px;font-size:23px}.connector-onboarding-header p{margin:0;color:#94a3b8;font-size:13px}.connector-onboarding-kicker{color:#38bdf8;font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase}.connector-onboarding-close{display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;border:1px solid rgba(148,163,184,.26);border-radius:10px;background:transparent;color:#cbd5e1;cursor:pointer}.connector-onboarding-body{padding:24px}.connector-onboarding-step{margin-bottom:18px;color:#64748b;font-size:12px;font-weight:800;letter-spacing:.07em;text-transform:uppercase}.connector-onboarding-card{padding:20px;border:1px solid rgba(148,163,184,.18);border-radius:14px;background:rgba(2,6,23,.32)}.connector-onboarding-card h3{margin:0 0 9px;font-size:19px}.connector-onboarding-card p{margin:0 0 13px;color:#cbd5e1;line-height:1.58}.connector-onboarding-label{display:block;margin-top:14px;color:#cbd5e1;font-size:13px;font-weight:700}.connector-onboarding-input{width:100%;box-sizing:border-box;margin-top:7px;padding:11px 12px;border:1px solid rgba(148,163,184,.34);border-radius:9px;background:#020617;color:#f8fafc;font:inherit}.connector-onboarding-input:focus{outline:2px solid rgba(56,189,248,.35);border-color:#38bdf8}.connector-onboarding-actions{display:flex;align-items:center;justify-content:flex-end;flex-wrap:wrap;gap:10px;margin-top:20px}.connector-onboarding-error{margin-bottom:18px;padding:12px 14px;border:1px solid rgba(248,113,113,.35);border-radius:10px;background:rgba(127,29,29,.18);color:#fecaca}.connector-onboarding-note{margin:14px 0;padding:13px 14px;border:1px solid rgba(56,189,248,.2);border-radius:10px;background:rgba(14,116,144,.08);color:#bae6fd;font-size:13px;line-height:1.55}.connector-onboarding-note ol{margin:7px 0 0;padding-left:22px}.connector-onboarding-note li{margin:6px 0}.connector-onboarding-disclosure{margin-top:15px;padding:16px;border:1px solid rgba(148,163,184,.18);border-radius:11px;background:rgba(15,23,42,.7)}.connector-onboarding-disclosure p:last-child{margin-bottom:0}.connector-onboarding-permissions{margin-top:14px}.connector-onboarding-toggle{display:inline-flex;align-items:center;gap:7px;padding:0;border:0;background:transparent;color:#7dd3fc;font:inherit;font-size:13px;font-weight:700;cursor:pointer}.connector-onboarding-permissions ul{margin:12px 0 0;padding:13px 14px 13px 34px;border:1px solid rgba(148,163,184,.16);border-radius:10px;background:#020617;color:#cbd5e1}.connector-onboarding-permissions li{margin:6px 0;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12px}.connector-onboarding-check{display:flex;align-items:flex-start;gap:10px;margin-top:18px;padding:14px;border:1px solid rgba(148,163,184,.2);border-radius:10px;background:rgba(2,6,23,.4);color:#e2e8f0;font-size:13px;line-height:1.5}.connector-onboarding-check input{margin-top:3px}.connector-onboarding-secret{display:flex;gap:8px;align-items:stretch;margin-top:8px}.connector-onboarding-secret code{flex:1;min-width:0;padding:11px 12px;border:1px solid rgba(148,163,184,.28);border-radius:9px;background:#020617;color:#f8fafc;overflow-wrap:anywhere;font-size:12px}.connector-onboarding-copy{display:inline-flex;align-items:center;justify-content:center;min-width:42px;border:1px solid rgba(148,163,184,.28);border-radius:9px;background:#111827;color:#cbd5e1;cursor:pointer}.connector-onboarding-success{display:flex;align-items:center;gap:12px;margin-bottom:15px;color:#86efac}.connector-onboarding-success-icon{display:inline-flex;align-items:center;justify-content:center;width:42px;height:42px;border-radius:50%;background:rgba(34,197,94,.14)}.connector-onboarding-meta{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:14px}.connector-onboarding-meta>div{padding:11px 12px;border:1px solid rgba(148,163,184,.15);border-radius:9px;background:rgba(15,23,42,.7)}.connector-onboarding-meta span{display:block;color:#64748b;font-size:10px;font-weight:800;text-transform:uppercase}.connector-onboarding-meta strong{display:block;margin-top:4px;color:#e2e8f0;font-size:13px;overflow-wrap:anywhere}.connector-onboarding-meta small{display:block;margin-top:4px;color:#94a3b8;font-size:11px;line-height:1.4}@media(max-width:620px){.connector-onboarding-backdrop{padding:0}.connector-onboarding{width:100vw;max-height:100vh;min-height:100vh;border-radius:0}.connector-onboarding-header,.connector-onboarding-body{padding:19px}.connector-onboarding-actions{justify-content:stretch}.connector-onboarding-actions button{flex:1}.connector-onboarding-meta{grid-template-columns:1fr}}
`;

type Stage = "name" | "disclosure" | "handoff" | "wait" | "register" | "approval";
type SetupConnector = {
  connectorId: string;
  displayName: string;
  status: string;
  homeRegion: string;
  templateVersion: string;
  disclosureVersion: string;
  disclosureAcknowledged: boolean;
  externalId?: string;
  quickCreateUrl?: string;
  stackName?: string;
};

type Props = {
  accessToken: string;
  autoOpen?: boolean;
  hasConnector?: boolean;
  onAutoOpenHandled?: () => void;
};

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function normalizeSetup(value: unknown): SetupConnector | null {
  const item = record(value);
  const connectorId = String(item.connectorId ?? "").trim();
  const displayName = String(item.displayName ?? "").trim();
  if (!connectorId || !displayName) return null;
  return {
    connectorId,
    displayName,
    status: String(item.status ?? "").trim(),
    homeRegion: String(item.homeRegion ?? "").trim(),
    templateVersion: String(item.templateVersion ?? "").trim(),
    disclosureVersion: String(item.disclosureVersion ?? "").trim(),
    disclosureAcknowledged: item.disclosureAcknowledged === true,
    externalId: typeof item.externalId === "string" ? item.externalId : undefined,
    quickCreateUrl: typeof item.quickCreateUrl === "string" ? item.quickCreateUrl : undefined,
    stackName: typeof item.stackName === "string" ? item.stackName : undefined,
  };
}

async function responsePayload(response: Response) {
  return record(await response.json().catch(() => ({})));
}

export default function OperatorConnectorOnboarding({ accessToken, autoOpen = false, hasConnector = false, onAutoOpenHandled }: Props) {
  const [open, setOpen] = useState(false);
  const [stage, setStage] = useState<Stage>("name");
  const [displayName, setDisplayName] = useState("");
  const [connector, setConnector] = useState<SetupConnector | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [showPermissions, setShowPermissions] = useState(false);
  const [connectorRoleArn, setConnectorRoleArn] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  const canRegister = useMemo(() => /^arn:aws:iam::\d{12}:role\/aws-security-coach\/.+/.test(connectorRoleArn.trim()), [connectorRoleArn]);

  function reset() {
    setStage("name");
    setDisplayName("");
    setConnector(null);
    setAcknowledged(false);
    setShowPermissions(false);
    setConnectorRoleArn("");
    setError("");
    setCopied(false);
  }

  function openOnboarding() {
    reset();
    setOpen(true);
  }

  function close() {
    if (busy) return;
    setOpen(false);
    reset();
  }

  useEffect(() => {
    if (!autoOpen || !accessToken) return;
    openOnboarding();
    onAutoOpenHandled?.();
  }, [autoOpen, accessToken, onAutoOpenHandled]);

  useEffect(() => {
    if (!open) return;
    function closeOnEscape(event: KeyboardEvent) { if (event.key === "Escape" && !busy) setOpen(false); }
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [open, busy]);

  async function createConnector() {
    const name = displayName.trim();
    if (!name) { setError("Give this connection a name before continuing."); return; }
    setBusy(true); setError("");
    try {
      const response = await fetch(`${API_BASE_URL}/auth/connectors`, {
        method: "POST",
        headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ displayName: name, homeRegion: HOME_REGION }),
      });
      const payload = await responsePayload(response);
      if (!response.ok) throw new Error(`Connector could not be created: ${String(payload.code ?? "CONNECTOR_CREATE_FAILED")}`);
      const created = record(payload.connector);
      const connectorId = String(created.connectorId ?? "").trim();
      if (!connectorId) throw new Error("Connector creation returned no connector reference.");

      const setupResponse = await fetch(`${API_BASE_URL}/auth/connectors/${encodeURIComponent(connectorId)}/setup`, { headers: { Authorization: `Bearer ${accessToken}` } });
      const setupPayload = await responsePayload(setupResponse);
      if (!setupResponse.ok) throw new Error(`Connector setup could not be loaded: ${String(setupPayload.code ?? "CONNECTOR_SETUP_FAILED")}`);
      const setup = normalizeSetup(setupPayload.connector);
      if (!setup) throw new Error("Connector setup response was incomplete.");
      setConnector(setup);
      setStage(setup.disclosureAcknowledged ? "handoff" : "disclosure");
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : "Connector could not be created.");
    } finally { setBusy(false); }
  }

  async function acknowledgeDisclosure() {
    if (!connector || !acknowledged) return;
    setBusy(true); setError("");
    try {
      const response = await fetch(`${API_BASE_URL}/auth/connectors/${encodeURIComponent(connector.connectorId)}/setup`, {
        method: "POST",
        headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ acknowledged: true, disclosureVersion: DISCLOSURE_VERSION }),
      });
      const payload = await responsePayload(response);
      if (!response.ok) throw new Error(`Disclosure acknowledgment failed: ${String(payload.code ?? "CONNECTOR_SETUP_FAILED")}`);
      const setup = normalizeSetup(payload.connector);
      if (!setup?.disclosureAcknowledged || !setup.externalId || !setup.quickCreateUrl) throw new Error("Protected setup material was not returned after acknowledgment.");
      setConnector(setup);
      setStage("handoff");
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : "Disclosure acknowledgment failed.");
    } finally { setBusy(false); }
  }

  async function copyExternalId() {
    if (!connector?.externalId) return;
    try { await navigator.clipboard.writeText(connector.externalId); setCopied(true); window.setTimeout(() => setCopied(false), 1600); }
    catch { setError("Copy failed. Select the ExternalId manually."); }
  }

  function launchCustomerStack() {
    if (!connector?.quickCreateUrl) return;
    window.open(connector.quickCreateUrl, "_blank", "noopener,noreferrer");
    setStage("wait");
  }

  async function registerConnector() {
    if (!connector || !canRegister) return;
    setBusy(true); setError("");
    try {
      const response = await fetch(`${API_BASE_URL}/auth/connectors/${encodeURIComponent(connector.connectorId)}/register`, {
        method: "POST",
        headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ connectorRoleArn: connectorRoleArn.trim() }),
      });
      const payload = await responsePayload(response);
      if (!response.ok) throw new Error(`Connection verification failed: ${String(payload.code ?? "CONNECTOR_REGISTRATION_FAILED")}`);
      const updated = record(payload.connector);
      const status = String(updated.status ?? "").trim();
      if (status !== "APPROVAL_PENDING") throw new Error("Connection verification did not reach the expected approval state. Try again or contact support.");
      setConnector(current => current ? { ...current, status } : current);
      setStage("approval");
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : "Connection verification failed.");
    } finally { setBusy(false); }
  }

  return <>
    <style>{STYLES}</style>
    <button type="button" className={hasConnector ? "button-secondary connector-onboarding-trigger" : "button-primary connector-onboarding-trigger"} onClick={openOnboarding}>
      <span className="button-inline"><Plus size={16}/> {hasConnector ? "Add AWS Account" : "Connect AWS Account"}</span>
    </button>

    {open && <div className="connector-onboarding-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) close(); }}>
      <section className="connector-onboarding" role="dialog" aria-modal="true" aria-label="Connect AWS account">
        <header className="connector-onboarding-header">
          <div><div className="connector-onboarding-kicker">AWS account connector</div><h2>Connect an AWS Account</h2><p>Create one bounded read-only CloudFormation connector, verify it, then submit it for Security Coach approval.</p></div>
          <button type="button" className="connector-onboarding-close" aria-label="Close onboarding" onClick={close}><X size={20}/></button>
        </header>
        <div className="connector-onboarding-body">
          {error && <div className="connector-onboarding-error" role="alert">{error}</div>}

          {stage === "name" && <>
            <div className="connector-onboarding-step">Step 1 of 6 · Name this connection</div>
            <div className="connector-onboarding-card">
              <h3>Name this AWS connection</h3>
              <p>Choose a name that will help you recognize this AWS account in Security Coach later. It does not need to match anything in AWS; Security Coach verifies the actual AWS account automatically during setup.</p>
              <label className="connector-onboarding-label">Connection name
                <input className="connector-onboarding-input" value={displayName} maxLength={80} autoFocus onChange={event => setDisplayName(event.target.value)} placeholder="Acme Corp - Production" />
              </label>
              <div className="connector-onboarding-meta"><div><span>Region</span><strong>{HOME_REGION}</strong><small>Currently supported region for Security Coach scans.</small></div><div><span>Access</span><strong>Cross-account read-only</strong></div></div>
              <div className="connector-onboarding-actions"><button type="button" className="button-secondary" onClick={close}>Cancel</button><button type="button" className="button-primary" disabled={busy || !displayName.trim()} onClick={() => void createConnector()}>{busy ? <span className="button-inline"><Loader2 size={16} className="spin"/> Creating…</span> : "Continue"}</button></div>
            </div>
          </>}

          {stage === "disclosure" && connector && <>
            <div className="connector-onboarding-step">Step 2 of 6 · Review access</div>
            <div className="connector-onboarding-card">
              <h3>Review what Security Coach will access</h3>
              <div className="connector-onboarding-disclosure">
                <p>Security Coach connects to your AWS account using a dedicated read-only IAM role created by AWS CloudFormation. The connector allows Security Coach to perform only the supported posture checks shown below.</p>
                <p>Security Coach does not receive your AWS password, access keys, or console credentials. Cross-account access uses temporary AWS STS sessions and a connector-specific ExternalId.</p>
                <p>You remain in control. To remove Security Coach’s AWS access, delete the connector CloudFormation stack from your AWS account.</p>
                <p><strong>Security Coach evaluates a bounded set of security checks. A successful scan does not guarantee that an AWS account is secure or free of vulnerabilities.</strong></p>
              </div>
              <div className="connector-onboarding-permissions">
                <button type="button" className="connector-onboarding-toggle" onClick={() => setShowPermissions(value => !value)}>{showPermissions ? <ChevronUp size={15}/> : <ChevronDown size={15}/>} View exact AWS permissions</button>
                {showPermissions && <ul>{CONNECTOR_PERMISSIONS.map(permission => <li key={permission}>{permission}</li>)}</ul>}
              </div>
              <label className="connector-onboarding-check"><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} /><span>I understand the access model, the permissions Security Coach will receive, the limits of the assessment, and that I can remove access by deleting the connector CloudFormation stack from my AWS account.</span></label>
              <div className="connector-onboarding-actions"><button type="button" className="button-secondary" onClick={close}>Exit setup</button><button type="button" className="button-primary" disabled={busy || !acknowledged} onClick={() => void acknowledgeDisclosure()}>{busy ? <span className="button-inline"><Loader2 size={16} className="spin"/> Recording…</span> : "Acknowledge & continue"}</button></div>
            </div>
          </>}

          {stage === "handoff" && connector && <>
            <div className="connector-onboarding-step">Step 3 of 6 · Create the connector in AWS</div>
            <div className="connector-onboarding-card">
              <h3>Create the connector in AWS</h3>
              <p>Security Coach will open AWS CloudFormation in a new tab with the connector template and required settings already prepared. Before you continue, copy the ExternalId below. You will paste it into CloudFormation.</p>
              <label className="connector-onboarding-label">ExternalId
                <div className="connector-onboarding-secret"><code>{connector.externalId}</code><button type="button" className="connector-onboarding-copy" aria-label="Copy ExternalId" onClick={() => void copyExternalId()}>{copied ? <Check size={17}/> : <Clipboard size={17}/>}</button></div>
              </label>
              <div className="connector-onboarding-note"><strong>In AWS CloudFormation:</strong><ol><li>Make sure you are signed in to the AWS account you want Security Coach to scan.</li><li>Scroll down to the <strong>Parameters</strong> section.</li><li>Find the <strong>ExternalId</strong> field and paste the value shown above.</li><li>Scroll to the bottom of the page.</li><li>Under <strong>Capabilities</strong>, select <strong>“I acknowledge that AWS CloudFormation might create IAM resources.”</strong></li><li>Click <strong>Create stack</strong>.</li></ol></div>
              <div className="connector-onboarding-actions"><button type="button" className="button-secondary" onClick={close}>Exit setup</button><button type="button" className="button-primary" disabled={!connector.quickCreateUrl} onClick={launchCustomerStack}><span className="button-inline"><ExternalLink size={16}/> Open AWS CloudFormation</span></button></div>
            </div>
          </>}

          {stage === "wait" && connector && <>
            <div className="connector-onboarding-step">Step 4 of 6 · Wait for AWS to finish</div>
            <div className="connector-onboarding-card">
              <h3>Wait for the connector to finish deploying</h3>
              <p>After you click <strong>Create stack</strong>, AWS opens the new stack and shows its deployment progress. Keep the AWS page open while CloudFormation creates the connector.</p>
              <div className="connector-onboarding-note"><strong>In the AWS stack page:</strong><ol><li>Open the <strong>Events</strong> tab if it is not already selected.</li><li>Use the view toggle in the <strong>upper-right</strong> of the Events area to choose the view you prefer.</li><li><strong>Table view:</strong> wait until the stack and <strong>AWSSecurityCoachReadOnlyRole</strong> show <strong>CREATE_COMPLETE</strong>.<br/><strong>Timeline view:</strong> wait until the connector role finishes and the deployment shows <strong>Complete</strong>.</li><li>Once the deployment is complete, select the <strong>Outputs</strong> tab near the top of the stack page.</li><li>Find <strong>ConnectorRoleArn</strong> and copy the value in the <strong>Value</strong> column.</li></ol></div>
              <p>Keep that value handy. You will paste it into Security Coach in the next step.</p>
              <div className="connector-onboarding-actions"><button type="button" className="button-secondary" onClick={() => setStage("handoff")}>Back</button><button type="button" className="button-primary" onClick={() => setStage("register")}>I have the ConnectorRoleArn</button></div>
            </div>
          </>}

          {stage === "register" && connector && <>
            <div className="connector-onboarding-step">Step 5 of 6 · Verify the connection</div>
            <div className="connector-onboarding-card">
              <h3>Verify your AWS connection</h3>
              <p>Paste the <strong>ConnectorRoleArn</strong> you copied from the CloudFormation <strong>Outputs</strong> tab.</p>
              <label className="connector-onboarding-label">ConnectorRoleArn
                <input className="connector-onboarding-input" value={connectorRoleArn} onChange={event => setConnectorRoleArn(event.target.value)} placeholder="arn:aws:iam::<AWS_ACCOUNT_ID>:role/aws-security-coach/..." />
              </label>
              <div className="connector-onboarding-note">Security Coach will verify the AWS account, connector trust, ExternalId protection, supported read-only permissions, and connector compatibility. Successful verification sends the connection for Security Coach approval before scans are allowed.</div>
              <div className="connector-onboarding-actions"><button type="button" className="button-secondary" onClick={() => setStage("wait")}>Back</button><button type="button" className="button-primary" disabled={busy || !canRegister} onClick={() => void registerConnector()}>{busy ? <span className="button-inline"><Loader2 size={16} className="spin"/> Verifying…</span> : "Verify connection"}</button></div>
            </div>
          </>}

          {stage === "approval" && connector && <>
            <div className="connector-onboarding-step">Step 6 of 6 · Setup complete</div>
            <div className="connector-onboarding-card">
              <div className="connector-onboarding-success"><span className="connector-onboarding-success-icon"><ShieldCheck size={22}/></span><div><h3 style={{margin:0}}>Connector setup complete</h3><div style={{color:"#cbd5e1",fontSize:13,marginTop:4}}>{connector.displayName}</div></div></div>
              <p><strong>Your AWS connector was verified successfully.</strong></p>
              <div className="connector-onboarding-note"><strong>Current status: Waiting for approval</strong><br/>Security Coach has verified the AWS account, connector trust, ExternalId protection, read-only permissions, and compatibility. Scans remain unavailable while this approval is pending.</div>
              <p><strong>No further setup is required from you.</strong> After Security Coach approves the connection, this AWS account will appear automatically as an available scan target.</p>
              <p>You can close this window now. You remain in control of AWS access, and you can disconnect Security Coach later by deleting the connector CloudFormation stack from your AWS account.</p>
              <div className="connector-onboarding-actions"><button type="button" className="button-primary" onClick={close}>Finish setup</button></div>
            </div>
          </>}
        </div>
      </section>
    </div>}
  </>;
}
