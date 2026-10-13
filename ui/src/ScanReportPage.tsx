import { ArrowLeft, Download, FileWarning, Loader2, LogIn } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { API_BASE_URL } from "./config";
import ManagedEngineeringReport, { managedEngineeringReportReady } from "./ManagedEngineeringReport";
import ManagedManagementReport from "./ManagedManagementReport";
import SubscriberEngineeringReport, { subscriberEngineeringReportReady } from "./SubscriberEngineeringReport";
import SubscriberManagementReport from "./SubscriberManagementReport";
import { downloadManagedPdf } from "./managedPdf";
import { prepareManagedReport } from "./managedReportPolicy";
import { parseReportRoute, type ReportDocumentRoute } from "./reportDelivery";
import { normalizeReport, type Report } from "./reportAdapter";
import { downloadSubscriberPdf } from "./subscriberPdf";
import "./scanReportPage.css";

export type ScanReportRoute = ReportDocumentRoute;

export function scanReportRouteFromHash(hash: string): ScanReportRoute | null {
  return parseReportRoute(hash);
}

function managementReportReady(report: Report): boolean {
  return Boolean(report.assessment) && report.findings.every(finding => Boolean(finding.guidance));
}

type ScanReportPageProps = {
  route: ScanReportRoute;
  accessToken: string;
  isAuthenticated: boolean;
  isAuthLoading: boolean;
  onSignIn?: () => Promise<void>;
};

export default function ScanReportPage({ route, accessToken, isAuthenticated, isAuthLoading, onSignIn }: ScanReportPageProps) {
  const [payload, setPayload] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [downloadError, setDownloadError] = useState("");

  useEffect(() => {
    setPayload(null);
    setError("");
    setDownloadError("");
    if (!isAuthenticated || !accessToken) return;

    const controller = new AbortController();
    setLoading(true);
    void fetch(`${API_BASE_URL}/auth/report/${encodeURIComponent(route.scanId)}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: controller.signal,
    }).then(async response => {
      if (response.status === 401) throw new Error("Your sign-in session is no longer valid. Sign in again.");
      if (response.status === 403) throw new Error("You are not authorized to view this report.");
      if (response.status === 404) throw new Error("This scan report is not available.");
      if (!response.ok) throw new Error("The report could not be loaded.");
      return response.json();
    }).then(setPayload).catch((caught: unknown) => {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      setError(caught instanceof Error ? caught.message : "The report could not be loaded.");
    }).finally(() => setLoading(false));

    return () => controller.abort();
  }, [route.scanId, accessToken, isAuthenticated]);

  const report = useMemo(() => {
    if (!payload) return null;
    try {
      const normalized = normalizeReport(payload);
      return route.deliveryModel === "managed" ? prepareManagedReport(normalized) : normalized;
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : "The report could not be read.");
      return null;
    }
  }, [payload, route.deliveryModel]);

  const ready = report
    ? route.documentType === "engineering"
      ? route.deliveryModel === "managed" ? managedEngineeringReportReady(report) : subscriberEngineeringReportReady(report)
      : managementReportReady(report)
    : false;

  const label = `${route.deliveryModel === "managed" ? "managed" : "subscriber"} ${route.documentType}`;

  function renderReport(current: Report) {
    if (route.deliveryModel === "managed") {
      return route.documentType === "engineering"
        ? <ManagedEngineeringReport report={current} />
        : <ManagedManagementReport report={current} />;
    }
    return route.documentType === "engineering"
      ? <SubscriberEngineeringReport report={current} />
      : <SubscriberManagementReport report={current} />;
  }

  function downloadCurrentReport(current: Report): void {
    setDownloadError("");
    try {
      if (route.deliveryModel === "managed") downloadManagedPdf(current, route.documentType);
      else downloadSubscriberPdf(current, route.documentType);
    } catch (caught: unknown) {
      setDownloadError(caught instanceof Error ? caught.message : "The PDF could not be generated.");
    }
  }

  return <div className="scan-report-page">
    <div className="scan-report-toolbar">
      <a className="scan-report-back" href="#/"><ArrowLeft size={16} /> Back to scans</a>
      <div className="scan-report-toolbar-actions">
        <div className="scan-report-route-id">Scan {route.scanId.slice(0, 8)}…{route.scanId.slice(-4)} · {route.deliveryModel}</div>
        {report && ready && <button className="scan-report-download" type="button" onClick={() => downloadCurrentReport(report)}><Download size={16} /> Download PDF</button>}
      </div>
    </div>
    {downloadError && <div className="scan-report-download-error" role="alert">{downloadError}</div>}

    {isAuthLoading ? (
      <div className="scan-report-state"><Loader2 className="spin" size={24} /><strong>Checking report access…</strong></div>
    ) : !isAuthenticated ? (
      <div className="scan-report-state"><LogIn size={24} /><strong>Sign in to view this report</strong><span>Report access remains protected by the same authenticated authorization used for scan results.</span>{onSignIn ? <button className="button-primary" type="button" onClick={() => void onSignIn()}>Sign in</button> : <a className="button-primary" href="#/">Return to scans and sign in</a>}</div>
    ) : loading ? (
      <div className="scan-report-state"><Loader2 className="spin" size={24} /><strong>Loading {label} report…</strong></div>
    ) : error ? (
      <div className="scan-report-state scan-report-error"><FileWarning size={24} /><strong>Report unavailable</strong><span>{error}</span></div>
    ) : report && ready ? (
      renderReport(report)
    ) : report ? (
      <div className="scan-report-state scan-report-error"><FileWarning size={24} /><strong>{route.documentType === "engineering" ? "Engineering runbook metadata is not available for this scan" : "Customer report metadata is not available for this scan"}</strong><span>{route.documentType === "engineering" ? "This scan predates the complete engineering-runbook release and cannot be rendered as the current engineering remediation document." : "This historical scan predates the customer-report guidance required by the current document."}</span></div>
    ) : null}
  </div>;
}
