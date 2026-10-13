import { AlertTriangle, CheckCircle2, ExternalLink, ShieldCheck } from "lucide-react";
import type { Finding, Report } from "./reportAdapter";
import "./managementReport.css";
import "./managementReportEnhancements.css";

const SEVERITY_WEIGHT: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
const AREA_ORDER = ["Identity and access management", "Detection", "Infrastructure protection", "Data protection"];

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((left, right) => {
    const severity = (SEVERITY_WEIGHT[right.severity] ?? 0) - (SEVERITY_WEIGHT[left.severity] ?? 0);
    return severity || left.title.localeCompare(right.title);
  });
}

function formattedDate(value?: string): string {
  if (!value) return "Not available";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return new Intl.DateTimeFormat("en-US", { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" }).format(parsed);
}

function assessmentId(report: Report): string {
  const year = report.generatedAt && !Number.isNaN(new Date(report.generatedAt).getTime()) ? new Date(report.generatedAt).getUTCFullYear() : new Date().getUTCFullYear();
  const shortId = report.scanId?.replace(/[^A-Za-z0-9]/g, "").slice(0, 8).toUpperCase() || "PENDING";
  return `ASC-${year}-${shortId}`;
}

function severityClass(severity: string): string {
  return `management-badge management-severity management-severity-${severity.toLowerCase()}`;
}

function Disclaimer({ text }: { text: string }) {
  const marker = "NOT";
  const index = text.indexOf(marker);
  if (index === -1) return <>{text}</>;
  return <>{text.slice(0, index)}<strong>{marker}</strong>{text.slice(index + marker.length)}</>;
}

function areaSummary(report: Report) {
  const areas = new Map<string, { total: number; evaluated: number; passed: number; attention: number; notApplicable: number }>();
  for (const finding of report.findings) {
    const area = finding.guidance?.awsSecurityArea;
    if (!area) continue;
    const current = areas.get(area) ?? { total: 0, evaluated: 0, passed: 0, attention: 0, notApplicable: 0 };
    current.total += 1;
    if (finding.status === "NOT_APPLICABLE") current.notApplicable += 1;
    else {
      current.evaluated += 1;
      if (finding.status === "PASS") current.passed += 1;
      else current.attention += 1;
    }
    areas.set(area, current);
  }
  return [...areas.entries()].sort(([left], [right]) => {
    const l = AREA_ORDER.indexOf(left); const r = AREA_ORDER.indexOf(right);
    if (l === -1 && r === -1) return left.localeCompare(right);
    if (l === -1) return 1; if (r === -1) return -1; return l - r;
  });
}

function disposition(confirmed: Finding[], evaluationIssues: Finding[]) {
  if (evaluationIssues.length) return { title: "Assessment follow-up required", copy: "One or more controls could not be evaluated reliably. Resolve the evaluation condition before relying on those controls as part of the assessed baseline." };
  if (confirmed.some(finding => ["CRITICAL", "HIGH"].includes(finding.severity))) return { title: "Immediate remediation recommended", copy: "Prioritize the highest-severity confirmed findings first. After remediation is complete, request follow-up verification of the affected controls." };
  if (confirmed.some(finding => finding.severity === "MEDIUM")) return { title: "Remediation recommended", copy: "Address the confirmed gaps during the next appropriate security maintenance window, then request follow-up verification." };
  if (confirmed.length) return { title: "Review recommended", copy: "Review the confirmed items and determine the appropriate remediation based on workload and organizational requirements." };
  return { title: "No immediate action identified within assessed scope", copy: "All successfully evaluated controls passed at the time of review. Controls marked not applicable were excluded from the pass calculation." };
}

export default function ManagedManagementReport({ report }: { report: Report }) {
  const assessment = report.assessment;
  if (!assessment) return null;

  const passed = report.findings.filter(finding => finding.status === "PASS");
  const notApplicable = report.findings.filter(finding => finding.status === "NOT_APPLICABLE");
  const confirmed = sortFindings(report.findings.filter(finding => finding.status === "FAIL" || finding.status === "WARN"));
  const evaluationIssues = report.findings.filter(finding => finding.status === "ERROR");
  const evaluated = report.findings.length - notApplicable.length;
  const topActions = confirmed.slice(0, 3);
  const recommendation = disposition(confirmed, evaluationIssues);
  const areas = areaSummary(report);
  const connectorAssessment = report.target?.type === "connector";

  return <article className="management-report managed-management-report" aria-label="Managed AWS Security Posture Review management summary">
    <header className="management-report-header">
      <div><div className="management-eyebrow">Management Summary</div><h2>{assessment.title}</h2><p className="management-target">Point-in-time review of selected foundational AWS security controls.</p></div>
      <div className="management-identity">
        {report.customer && <><span>Customer / Organization</span><strong>{report.customer.organization}</strong><span>AWS Account ID</span><strong>{report.customer.awsAccountId}</strong></>}
        <span>Assessment ID</span><strong>{assessmentId(report)}</strong><span>Prepared</span><strong>{formattedDate(report.generatedAt)}</strong>
      </div>
    </header>

    <section className="management-overview">
      <div className="management-overview-main"><span className="management-overview-number">{passed.length} of {evaluated}</span><span className="management-overview-label">evaluated controls passed</span>{notApplicable.length > 0 && <span className="management-section-note">{notApplicable.length} not applicable</span>}</div>
      <div className={confirmed.length || evaluationIssues.length ? "management-overview-state attention" : "management-overview-state clean"}>
        {confirmed.length || evaluationIssues.length ? <AlertTriangle size={20} /> : <CheckCircle2 size={20} />}
        <div><strong>{confirmed.length ? `${confirmed.length} confirmed ${confirmed.length === 1 ? "finding" : "findings"}` : evaluationIssues.length ? `${evaluationIssues.length} evaluation ${evaluationIssues.length === 1 ? "issue" : "issues"}` : "All applicable checks passed"}</strong><span>{confirmed.length ? "Remediation priorities are ordered by severity." : evaluationIssues.length ? "Evaluation issues require assessment follow-up, not automatic AWS changes." : "No immediate remediation is identified within the evaluated scope."}</span></div>
      </div>
    </section>

    <section className="management-section">
      <div className="management-section-heading"><div><span className="management-section-kicker">Priority</span><h3>Top Actions</h3></div><span className="management-section-note">Confirmed findings · highest severity first</span></div>
      {topActions.length ? <div className="management-actions">{topActions.map((finding, index) => <div className="management-action" key={finding.id}>
        <div className="management-action-index">{index + 1}</div><div className="management-action-body">
          <div className="management-action-meta"><span className={severityClass(finding.severity)}>{finding.severity}</span>{finding.guidance?.remediationEffort && <span className="management-badge management-effort">{finding.guidance.remediationEffort} effort</span>}{finding.guidance?.awsSecurityArea && <span className="management-area-label">{finding.guidance.awsSecurityArea}</span>}</div>
          <h4>{finding.title}</h4>{finding.details && <div className="management-observed"><strong>What we observed:</strong> {finding.details}</div>}
          {finding.guidance?.customerRisk && <div className="management-impact"><strong>Why this matters</strong><p>{finding.guidance.customerRisk}</p></div>}
          {finding.guidance?.remediation && <div className="management-recommendation"><strong>Recommended action:</strong> {finding.guidance.remediation}</div>}
          {finding.guidance?.awsReference && <a className="management-action-reference" href={finding.guidance.awsReference.url} target="_blank" rel="noreferrer">AWS reference: {finding.guidance.awsReference.title} <ExternalLink size={13} /></a>}
        </div>
      </div>)}</div> : <div className="management-clean-callout"><CheckCircle2 size={20} /><span>No confirmed remediation findings were identified.</span></div>}
    </section>

    {evaluationIssues.length > 0 && <section className="management-section">
      <div className="management-section-heading"><div><span className="management-section-kicker">Assessment follow-up</span><h3>Controls not fully evaluated</h3></div><span className="management-section-note">Not confirmed misconfigurations</span></div>
      <div className="management-actions">{evaluationIssues.map(finding => <div className="management-action" key={finding.id}><div className="management-action-body"><h4>{finding.title}</h4><div className="management-observed"><strong>Evaluation result:</strong> {finding.details}</div><div className="management-recommendation"><strong>Next step:</strong> Resolve the assessment access or evaluation condition before making an AWS configuration change based solely on this result.</div></div></div>)}</div>
    </section>}

    <section className="management-section"><div className="management-section-heading"><div><span className="management-section-kicker">AWS context</span><h3>Security Pillar Areas</h3></div></div><div className="management-area-grid">{areas.map(([area, counts]) => <div className="management-area-card" key={area}><div className="management-area-title"><ShieldCheck size={18} /><span>{area}</span></div><div className="management-area-count"><strong>{counts.passed} of {counts.evaluated}</strong> evaluated checks passed</div><div className={counts.attention ? "management-area-state attention" : "management-area-state clean"}>{counts.attention ? `${counts.attention} ${counts.attention === 1 ? "item" : "items"} need attention` : counts.evaluated ? "All applicable checks passed in this area" : "No applicable checks in this area"}</div>{counts.notApplicable > 0 && <div className="management-section-note">{counts.notApplicable} not applicable</div>}</div>)}</div></section>

    <section className="management-section"><div className="management-section-heading"><div><span className="management-section-kicker">Evidence of good state</span><h3>Controls Confirmed</h3></div><span className="management-section-note">{passed.length} passed</span></div><div className="management-confirmed-grid">{passed.map(finding => <div className="management-confirmed-item" key={finding.id}><CheckCircle2 size={17} /><span>{finding.title}</span></div>)}</div></section>

    {notApplicable.length > 0 && <section className="management-section"><div className="management-section-heading"><div><span className="management-section-kicker">Scope applicability</span><h3>Controls Not Applicable</h3></div><span className="management-section-note">{notApplicable.length} excluded from pass calculation</span></div><div className="management-actions">{notApplicable.map(finding => <div className="management-action" key={finding.id}><div className="management-action-body"><h4>{finding.title}</h4>{finding.details && <div className="management-observed">{finding.details}</div>}</div></div>)}</div></section>}

    <section className="management-section management-methodology">
      <div className="management-section-heading"><div><span className="management-section-kicker">Bounded assessment</span><h3>Scope & Next Step</h3></div></div>
      <div className="management-scope-grid"><div><span>Assessment type</span><strong>Point-in-time</strong></div><div><span>Access model</span><strong>Read-only</strong></div><div><span>Resource changes</span><strong>None</strong></div></div>
      <p>{assessment.scopeStatement} Account-global controls were evaluated at the account level. The SSH/RDP security-group control covered all AWS Regions enabled for the account at assessment time. <Disclaimer text={assessment.frameworkDisclaimer} /></p>
      <p>{connectorAssessment ? "The review used temporary read-only access through a customer-deployed AWS role and did not modify AWS resources." : "The review used read-only AWS permissions and did not modify AWS resources."}</p>
    </section>

    <section className="management-disposition"><div><span className="management-section-kicker">Recommended disposition</span><h3>{recommendation.title}</h3></div><p>{recommendation.copy}</p><p className="management-reassessment">When remediation or assessment follow-up is complete, contact your assessment provider to arrange point-in-time verification of the affected controls.</p></section>

    {assessment.frameworkContext?.referenceUrl && <a className="management-framework-link" href={assessment.frameworkContext.referenceUrl} target="_blank" rel="noreferrer">AWS Well-Architected Security Pillar reference <ExternalLink size={14} /></a>}
  </article>;
}