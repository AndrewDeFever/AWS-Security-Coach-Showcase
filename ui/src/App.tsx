import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, Download, FileText, Loader2, Play, Wrench } from "lucide-react";
import "./app.css";
import { API_BASE_URL, IDEMPOTENCY_KEY_HEADER } from "./config";
import "./reportLinks.css";
import { reportRoute } from "./reportDelivery";
import ScanReportPage, { scanReportRouteFromHash, type ScanReportRoute } from "./ScanReportPage";
import { normalizeReport, type Finding } from "./reportAdapter";
import { downloadManagedPdf } from "./managedPdf";

type ScanStatus = "IDLE" | "QUEUED" | "RUNNING" | "COMPLETE" | "FAILED";
type Group = "All" | "Identity & Access" | "Detection & Visibility" | "Data Exposure" | "Network Exposure";
type ScanTarget = { targetType: "tool-account" | "connector"; targetId?: string; connectorId?: string; displayName: string; };
type AppProps = { identityControl?: ReactNode; accessToken: string; isAuthenticated: boolean; isAuthLoading: boolean; };

const GROUPS: Group[] = ["All", "Identity & Access", "Detection & Visibility", "Data Exposure", "Network Exposure"];
const TERMINAL = new Set(["COMPLETE", "FAILED"]);
const KNOWN = new Set(["QUEUED", "RUNNING", "COMPLETE", "FAILED"]);

class RequestError extends Error {
  readonly retryAfter: number;
  constructor(message: string, retryAfter = 0) { super(message); this.retryAfter = retryAfter; }
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function findingGroup(finding: Finding): Group {
  if (finding.id.startsWith("iam-")) return "Identity & Access";
  if (finding.id.startsWith("cloudtrail-")) return "Detection & Visibility";
  if (finding.id.startsWith("s3-")) return "Data Exposure";
  if (finding.id.startsWith("ec2-")) return "Network Exposure";
  return "All";
}

function buildHeaders(accessToken: string, idempotencyKey?: string): HeadersInit {
  return { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}`, ...(idempotencyKey ? { [IDEMPOTENCY_KEY_HEADER]: idempotencyKey } : {}) };
}

async function request(path: string, options: RequestInit) {
  const response = await fetch(`${API_BASE_URL}${path}`, options);
  if (response.ok) return response.json();
  const retryAfter = Number.parseInt(response.headers.get("retry-after") ?? "0", 10) || 0;
  if (response.status === 401) throw new RequestError("Your sign-in session is no longer valid. Sign in again.");
  if (response.status === 403) throw new RequestError("You are not authorized to access this scan target.");
  if (response.status === 409) throw new RequestError("A scan is already queued or running.", retryAfter);
  if (response.status === 429) throw new RequestError("Scan cooldown is active.", retryAfter);
  if (response.status >= 500) throw new RequestError("The scan service could not complete the request.");
  throw new RequestError("The request could not be completed.");
}

function normalizeTarget(value: unknown): ScanTarget | null {
  const item = record(value);
  const targetType = String(item.targetType ?? "");
  const displayName = String(item.displayName ?? "").trim();
  if (!displayName) return null;
  if (targetType === "tool-account" && String(item.targetId ?? "") === "tool-account") return { targetType: "tool-account", targetId: "tool-account", displayName };
  if (targetType === "connector") {
    const connectorId = String(item.connectorId ?? "").trim();
    if (connectorId) return { targetType: "connector", connectorId, displayName };
  }
  return null;
}

function targetKey(target: ScanTarget) { return target.targetType === "connector" ? `connector:${target.connectorId}` : "tool-account"; }
function sleep(ms: number, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(resolve, ms);
    signal.addEventListener("abort", () => { window.clearTimeout(timer); reject(new DOMException("Aborted", "AbortError")); }, { once: true });
  });
}
function statusClass(status: string) { return `status-pill status-${status.toLowerCase()}`; }
function findingStatusClass(status: string) { return `finding-status finding-status-${status.toLowerCase()}`; }
function severityClass(severity: string) {
  const value = ["critical", "high", "medium", "low", "info"].includes(severity.toLowerCase()) ? severity.toLowerCase() : "low";
  return `sev sev-${value}`;
}

export default function App({ identityControl, accessToken, isAuthenticated, isAuthLoading }: AppProps) {
  const [scanStatus, setScanStatus] = useState<ScanStatus>("IDLE");
  const [scanId, setScanId] = useState("");
  const [reportPayload, setReportPayload] = useState<unknown>(null);
  const [activeGroup, setActiveGroup] = useState<Group>("All");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [cooldown, setCooldown] = useState(0);
  const [targets, setTargets] = useState<ScanTarget[]>([]);
  const [selectedTargetKey, setSelectedTargetKey] = useState("");
  const [targetsLoading, setTargetsLoading] = useState(false);
  const [targetError, setTargetError] = useState("");
  const [scanTargetName, setScanTargetName] = useState("");
  const [reportRouteState, setReportRouteState] = useState<ScanReportRoute | null>(() => scanReportRouteFromHash(window.location.hash));
  const abortRef = useRef<AbortController | null>(null);
  const runRef = useRef(0);

  const report = useMemo(() => {
    if (!reportPayload) return null;
    try { return normalizeReport(reportPayload); }
    catch (caught: unknown) { setError(caught instanceof Error ? caught.message : "The report could not be read."); return null; }
  }, [reportPayload]);

  const selectedTarget = targets.find(target => targetKey(target) === selectedTargetKey) ?? null;

  useEffect(() => () => abortRef.current?.abort(), []);
  useEffect(() => {
    function syncReportRoute() { setReportRouteState(scanReportRouteFromHash(window.location.hash)); window.scrollTo({ top: 0, behavior: "auto" }); }
    window.addEventListener("hashchange", syncReportRoute);
    return () => window.removeEventListener("hashchange", syncReportRoute);
  }, []);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = window.setInterval(() => setCooldown(value => Math.max(0, value - 1)), 1000);
    return () => window.clearInterval(timer);
  }, [cooldown]);

  useEffect(() => {
    if (isAuthenticated) return;
    abortRef.current?.abort(); setBusy(false); setTargets([]); setSelectedTargetKey(""); setTargetError("");
  }, [isAuthenticated]);

  useEffect(() => {
    if (!isAuthenticated || !accessToken) return;
    const controller = new AbortController();
    setTargetsLoading(true); setTargetError("");
    void request("/auth/targets", { headers: buildHeaders(accessToken), signal: controller.signal }).then(payload => {
      const root = record(payload);
      const rawTargets = Array.isArray(root.targets) ? root.targets : [];
      const nextTargets = rawTargets.map(normalizeTarget).filter((target): target is ScanTarget => target !== null);
      setTargets(nextTargets);
      setSelectedTargetKey(current => nextTargets.some(target => targetKey(target) === current) ? current : nextTargets[0] ? targetKey(nextTargets[0]) : "");
      if (nextTargets.length === 0) setTargetError("No scan targets are assigned to this account.");
    }).catch((caught: unknown) => {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      setTargets([]); setSelectedTargetKey(""); setTargetError(caught instanceof Error ? caught.message : "Authorized scan targets could not be loaded.");
    }).finally(() => setTargetsLoading(false));
    return () => controller.abort();
  }, [isAuthenticated, accessToken]);

  async function runScan() {
    if (!isAuthenticated || !accessToken) { setError("Sign in before starting a scan."); return; }
    if (!selectedTarget) { setError("Select an authorized scan target before starting a scan."); return; }
    abortRef.current?.abort();
    const controller = new AbortController(); abortRef.current = controller;
    const runId = ++runRef.current;
    setBusy(true); setError(""); setReportPayload(null); setScanId(""); setScanStatus("QUEUED"); setScanTargetName(selectedTarget.displayName);
    const requestBody = selectedTarget.targetType === "connector" ? { targetType: "connector", connectorId: selectedTarget.connectorId } : { targetType: "tool-account" };
    try {
      const started = await request("/auth/scan", { method: "POST", headers: buildHeaders(accessToken, crypto.randomUUID()), body: JSON.stringify(requestBody), signal: controller.signal });
      if (runRef.current !== runId) return;
      const startedRecord = record(started);
      const id = String(startedRecord.scanId ?? startedRecord.id ?? "");
      if (!id) throw new Error("The service did not return a scan reference.");
      setScanId(id);
      for (let attempt = 0; attempt < 40; attempt++) {
        const statusPayload = await request(`/auth/scan/${encodeURIComponent(id)}`, { headers: buildHeaders(accessToken), signal: controller.signal });
        if (runRef.current !== runId) return;
        const statusRoot = record(statusPayload);
        const scanRecord = record(statusRoot.scan ?? statusRoot.item ?? statusRoot);
        const current = String(scanRecord.status ?? statusRoot.scanStatus ?? "UNKNOWN").toUpperCase();
        if (!KNOWN.has(current)) throw new Error("The service returned an unsupported scan status.");
        setScanStatus(current as ScanStatus);
        if (TERMINAL.has(current)) {
          if (current === "FAILED") throw new Error("The scan failed. Use the displayed scan reference when reviewing service logs.");
          const reportResponse = await request(`/auth/report/${encodeURIComponent(id)}`, { headers: buildHeaders(accessToken), signal: controller.signal });
          if (runRef.current === runId) setReportPayload(reportResponse);
          return;
        }
        await sleep(3000, controller.signal);
      }
      throw new Error("The scan did not finish within the expected polling window.");
    } catch (caught: unknown) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      if (runRef.current !== runId) return;
      if (caught instanceof RequestError && caught.retryAfter > 0) setCooldown(caught.retryAfter);
      setScanStatus("FAILED"); setError(caught instanceof Error ? caught.message : "The scan request failed.");
    } finally {
      if (runRef.current === runId) { setBusy(false); abortRef.current = null; }
    }
  }

  const visibleFindings = report?.findings.filter(finding => activeGroup === "All" || findingGroup(finding) === activeGroup) ?? [];
  const passed = report?.findings.filter(finding => finding.status === "PASS").length ?? 0;
  const failed = report?.findings.filter(finding => finding.status === "FAIL").length ?? 0;
  const warnings = report?.findings.filter(finding => finding.status === "WARN").length ?? 0;
  const errors = report?.findings.filter(finding => finding.status === "ERROR").length ?? 0;
  const notApplicable = report?.findings.filter(finding => finding.status === "NOT_APPLICABLE").length ?? 0;
  const evaluated = (report?.findings.length ?? 0) - notApplicable;
  const clean = failed + warnings + errors === 0;
  const summaryMetrics = [
    { label: "Total", value: report?.findings.length ?? 0, style: "", visible: true },
    { label: "Evaluated", value: evaluated, style: "", visible: notApplicable > 0 },
    { label: "Passed", value: passed, style: "metric-success", visible: true },
    { label: "Needs Attention", value: failed, style: "metric-critical", visible: failed > 0 },
    { label: "Warnings", value: warnings, style: "metric-medium", visible: warnings > 0 },
    { label: "Errors", value: errors, style: "metric-error", visible: errors > 0 },
    { label: "N/A", value: notApplicable, style: "", visible: notApplicable > 0 },
  ].filter(metric => metric.visible);
  const managementReady = Boolean(report?.assessment) && (report?.findings.every(finding => Boolean(finding.guidance)) ?? false);
  const engineeringReady = managementReady && (report?.findings.every(finding => Boolean(finding.guidance?.engineeringRemediation)) ?? false);
  const displayedTargetName = scanTargetName || selectedTarget?.displayName || "Authorized AWS account";
  const reportScanId = report?.scanId || scanId;
  const disabled = isAuthLoading || !isAuthenticated || !accessToken || targetsLoading || !selectedTarget || busy || cooldown > 0;
  const deliveryModel = report?.deliveryModel ?? "managed";
  const reportSectionTitle = deliveryModel === "managed" ? "Customer Reports" : "Your Reports";
  const reportSectionCopy = deliveryModel === "managed"
    ? "Open or download the consulting deliverables for this managed assessment. These documents do not assume the customer has access to this application."
    : "Open the self-service reports for this assessment. These documents include in-app reassessment guidance.";

  function downloadBothManagedReports() {
    if (!report || deliveryModel !== "managed" || !engineeringReady) return;
    try {
      downloadManagedPdf(report, "management");
      downloadManagedPdf(report, "engineering");
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : "The customer PDFs could not be downloaded.");
    }
  }

  if (reportRouteState) return <ScanReportPage route={reportRouteState} accessToken={accessToken} isAuthenticated={isAuthenticated} isAuthLoading={isAuthLoading} />;

  return <div className="app"><main className="shell">
    <header className="topbar"><a className="topbar-brand" href="#/" aria-label="AWS Security Coach home"><div className="topbar-kicker">AWS Security Coach</div><h1 className="topbar-title">AWS Posture Review</h1><p className="topbar-copy">An authenticated, read-only AWS control-plane review with bounded scan execution.</p></a><div className="topbar-actions"><button className="button-primary topbar-scan-action" disabled={disabled} onClick={runScan}><span className="button-inline">{busy ? <Loader2 size={16} className="spin" /> : <Play size={16} />}{isAuthLoading || targetsLoading ? "Loading access..." : !isAuthenticated ? "Sign in to scan" : busy ? "Running..." : cooldown > 0 ? `Available in ${cooldown}s` : report ? "Run Another Scan" : "Run Security Scan"}</span></button>{identityControl}</div></header>

    <section className="card"><div className="card-header"><h2 className="card-title">Scan Scope</h2><p className="card-subtitle">Only targets authorized for the signed-in account are available. Public-facing AWS account identifiers are intentionally omitted.</p></div><div className="scope-grid"><div className="scope-item"><div className="scope-label">Target</div><select aria-label="Scan target" className="button-secondary" disabled={!isAuthenticated || targetsLoading || busy || targets.length === 0} value={selectedTargetKey} onChange={event => setSelectedTargetKey(event.target.value)} style={{ width: "100%", marginTop: 8, padding: "9px 10px", background: "var(--surface-alt)", color: "var(--text-strong)" }}>{targets.length === 0 && <option value="">{targetsLoading ? "Loading targets…" : "No targets available"}</option>}{targets.map(target => <option key={targetKey(target)} value={targetKey(target)}>{target.displayName}</option>)}</select></div>{[["Authorization", isAuthenticated ? "Cognito authenticated session" : "Sign-in required"], ["Access", "Read-only checks"], ["Execution", "One active scan"], ["Region", "us-east-1"]].map(([label, value]) => <div className="scope-item" key={label}><div className="scope-label">{label}</div><div className="scope-value">{value}</div></div>)}</div>{targetError && <div className="error-text">{targetError}</div>}{error && <div className="error-text">{error}</div>}</section>

    <section className="card"><div className="card-header"><h2 className="card-title">Status</h2></div><div className="status-row"><span className={statusClass(scanStatus)}>{scanStatus}</span>{scanId && <span className="meta-line">Scan reference: <strong>{scanId.slice(0, 8)}…{scanId.slice(-4)}</strong></span>}{busy && <span className="meta-line"><Loader2 size={16} className="spin" /> Polling live scan status</span>}</div></section>

    {report && <>
      <section className="card"><div className="card-header"><h2 className="card-title">Report Summary</h2><p className="card-subtitle">Failed checks need attention. Errors indicate evaluation issues. Not-applicable controls are excluded from the pass calculation.</p></div><div className="metrics">{summaryMetrics.map(metric => <div className="metric" key={metric.label}><div className="metric-label">{metric.label}</div><div className={`metric-value ${metric.style}`}>{metric.value}</div></div>)}</div><div className="report-meta"><div>Status: <strong>{report.status}</strong></div>{report.generatedAt && <div>Generated: {report.generatedAt}</div>}<div>Target: {displayedTargetName}</div><div>Delivery: <strong>{deliveryModel === "managed" ? "Managed assessment" : "Self-service"}</strong></div></div></section>

      <section className="card"><div className="card-header"><h2 className="card-title">What this means</h2></div><div className="meaning-wrap"><div className={clean ? "meaning-pill clean" : "meaning-pill alert"}>{clean ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}{clean ? "All applicable checks passed" : `${failed + warnings + errors} items need attention`}</div><div className="meaning-main">{clean ? `${passed} of ${evaluated} evaluated checks passed for ${displayedTargetName}.${notApplicable ? ` ${notApplicable} control${notApplicable === 1 ? " was" : "s were"} not applicable.` : ""}` : "Review the findings before treating this result as a clean baseline."}</div><div className="meaning-sub">This is a point-in-time result for the active ruleset, not proof of continuous security.</div></div></section>

      {managementReady && reportScanId && <section className="card customer-report-card"><div className="card-header"><h2 className="card-title">{reportSectionTitle}</h2><p className="card-subtitle">{reportSectionCopy}</p></div><div className="customer-report-actions"><a className="button-primary customer-report-link" href={reportRoute(reportScanId, deliveryModel, "management")}><FileText size={16} /> Management Report</a>{engineeringReady && <a className="button-secondary customer-report-link" href={reportRoute(reportScanId, deliveryModel, "engineering")}><Wrench size={16} /> Engineering Report</a>}{deliveryModel === "managed" && engineeringReady && <button type="button" className="button-secondary customer-report-link" onClick={downloadBothManagedReports}><Download size={16} /> Download both PDFs</button>}<span className="customer-report-note">These links are tied to scan {reportScanId.slice(0, 8)}…{reportScanId.slice(-4)}.</span></div></section>}

      <section className="card"><div className="card-header"><h2 className="card-title">Findings</h2><p className="card-subtitle">Raw backend responses are not exposed in this view.</p></div><div className="tabs">{GROUPS.map(group => <button type="button" key={group} className={group === activeGroup ? "tab active" : "tab"} onClick={() => setActiveGroup(group)}>{group}<span className="tab-count">{report.findings.filter(finding => group === "All" || findingGroup(finding) === group).length}</span></button>)}</div><div className="tab-panel"><div className="finding-table">{visibleFindings.map(finding => <div className="finding-row" key={finding.id}><div className="finding-row-badges"><span className={findingStatusClass(finding.status)}>{finding.status}</span><span className={severityClass(finding.severity)}>{finding.severity}</span></div><div className="finding-row-content"><div className="finding-row-title">{finding.title}</div>{finding.details && <div className="finding-row-description">{finding.details}</div>}{finding.resource && <div className="finding-row-resource">Resource: {finding.resource}</div>}</div></div>)}</div></div></section>
    </>}
  </main></div>;
}
