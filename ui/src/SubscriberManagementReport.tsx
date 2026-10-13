import { AlertTriangle, CheckCircle2, ExternalLink, FileText, RefreshCw, ShieldCheck } from "lucide-react";
import type { Finding, Report } from "./reportAdapter";
import { reportRoute } from "./reportDelivery";
import "./subscriberReports.css";

const SEVERITY_WEIGHT: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((left, right) => {
    const severity = (SEVERITY_WEIGHT[right.severity] ?? 0) - (SEVERITY_WEIGHT[left.severity] ?? 0);
    return severity || left.title.localeCompare(right.title);
  });
}

function assessmentId(report: Report): string {
  const year = report.generatedAt && !Number.isNaN(new Date(report.generatedAt).getTime())
    ? new Date(report.generatedAt).getUTCFullYear()
    : new Date().getUTCFullYear();
  const shortId = report.scanId?.replace(/[^A-Za-z0-9]/g, "").slice(0, 8).toUpperCase() || "PENDING";
  return `ASC-${year}-${shortId}`;
}

function formattedDate(value?: string): string {
  if (!value) return "Not available";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-US", { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" }).format(date);
}

function Disclaimer({ text }: { text: string }) {
  const marker = "NOT";
  const index = text.indexOf(marker);
  if (index === -1) return <>{text}</>;
  return <>{text.slice(0, index)}<strong>{marker}</strong>{text.slice(index + marker.length)}</>;
}

export default function SubscriberManagementReport({ report }: { report: Report }) {
  const assessment = report.assessment;
  if (!assessment) return null;

  const passed = report.findings.filter(finding => finding.status === "PASS");
  const notApplicable = report.findings.filter(finding => finding.status === "NOT_APPLICABLE");
  const evaluated = report.findings.length - notApplicable.length;
  const confirmed = sortFindings(report.findings.filter(finding => finding.status === "FAIL" || finding.status === "WARN"));
  const evaluationIssues = report.findings.filter(finding => finding.status === "ERROR");
  const topActions = confirmed.slice(0, 3);
  const regionScope = report.target?.regionScope.join(", ") || "Not available";
  const engineeringHref = report.scanId ? reportRoute(report.scanId, "self-service", "engineering") : "#/";

  return <article className="subscriber-report subscriber-management-report" aria-label="AWS Security Coach subscriber management report">
    <header className="subscriber-header">
      <div>
        <div className="subscriber-brand"><ShieldCheck size={18} /> AWS Security Coach</div>
        <div className="subscriber-eyebrow">Management Report</div>
        <h1>AWS Security Posture Review</h1>
        <p>Point-in-time visibility into the foundational AWS controls assessed for this connected account.</p>
      </div>
      <div className="subscriber-id-card">
        <span>Assessment ID</span><strong>{assessmentId(report)}</strong>
        <span>Completed</span><strong>{formattedDate(report.generatedAt)}</strong>
      </div>
    </header>

    <section className="subscriber-scoreboard">
      <div><span>Passed</span><strong>{passed.length} of {evaluated}</strong></div>
      <div className={confirmed.length ? "needs-attention" : "clean"}><span>Needs attention</span><strong>{confirmed.length}</strong></div>
      <div className={evaluationIssues.length ? "evaluation" : "clean"}><span>Evaluation issues</span><strong>{evaluationIssues.length}</strong></div>
      <div><span>Not applicable</span><strong>{notApplicable.length}</strong></div>
      <div><span>Region scope</span><strong>{regionScope}</strong></div>
    </section>

    <section className="subscriber-next-step">
      <RefreshCw size={21} />
      <div>
        <strong>Your assessment is a point-in-time result</strong>
        <p>Make AWS changes using the engineering remediation report, then run a new assessment in AWS Security Coach to confirm the affected controls now pass.</p>
      </div>
      <a href={engineeringHref}><FileText size={16} /> Open Engineering Report</a>
    </section>

    <section className="subscriber-section">
      <div className="subscriber-section-heading"><div><span>Priority</span><h2>What to address first</h2></div><small>Confirmed findings only · highest severity first</small></div>
      {topActions.length ? <div className="subscriber-action-grid">
        {topActions.map((finding, index) => <article className="subscriber-action-card" key={finding.id}>
          <div className="subscriber-action-top"><span className="subscriber-action-index">{index + 1}</span><span className={`subscriber-severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span></div>
          <h3>{finding.title}</h3>
          {finding.details && <p><strong>Observed:</strong> {finding.details}</p>}
          {finding.guidance?.customerRisk && <div className="subscriber-risk"><strong>Why it matters</strong><p>{finding.guidance.customerRisk}</p></div>}
          {finding.guidance?.remediation && <p><strong>Recommended action:</strong> {finding.guidance.remediation}</p>}
        </article>)}
      </div> : <div className="subscriber-clean"><CheckCircle2 size={20} /><span>All applicable, successfully evaluated controls passed. No confirmed remediation is required within this assessed baseline.</span></div>}
    </section>

    {evaluationIssues.length > 0 && <section className="subscriber-section subscriber-evaluation-section">
      <div className="subscriber-section-heading"><div><span>Assessment follow-up</span><h2>Controls that could not be evaluated</h2></div></div>
      <p className="subscriber-section-copy">These are not confirmed AWS misconfigurations. Resolve the access or evaluation condition and run a new assessment before treating the control as passed or failed.</p>
      <div className="subscriber-evaluation-list">{evaluationIssues.map(finding => <div key={finding.id}><AlertTriangle size={17} /><div><strong>{finding.title}</strong><span>{finding.details}</span></div></div>)}</div>
    </section>}

    <section className="subscriber-section">
      <div className="subscriber-section-heading"><div><span>Workflow</span><h2>Close the loop</h2></div></div>
      <div className="subscriber-workflow">
        <div><strong>1</strong><span>Review the Engineering Report for exact AWS remediation steps and cautions.</span></div>
        <div><strong>2</strong><span>Make the approved AWS changes and verify the target state directly in AWS.</span></div>
        <div><strong>3</strong><span>Return to AWS Security Coach and run a new assessment for the connected account.</span></div>
        <div><strong>4</strong><span>Confirm remediated controls report PASS and investigate any new or remaining findings.</span></div>
      </div>
    </section>

    <section className="subscriber-section">
      <div className="subscriber-section-heading"><div><span>Evidence of good state</span><h2>Passed controls</h2></div><small>{passed.length} passed</small></div>
      <div className="subscriber-pass-grid">{passed.map(finding => <div key={finding.id}><CheckCircle2 size={16} /><span>{finding.title}</span></div>)}</div>
    </section>

    {notApplicable.length > 0 && <section className="subscriber-section">
      <div className="subscriber-section-heading"><div><span>Scope applicability</span><h2>Not applicable controls</h2></div><small>{notApplicable.length} excluded from pass calculation</small></div>
      <div className="subscriber-evaluation-list">{notApplicable.map(finding => <div key={finding.id}><ShieldCheck size={17} /><div><strong>{finding.title}</strong><span>{finding.details}</span></div></div>)}</div>
    </section>}

    <section className="subscriber-scope">
      <div><span>Assessment type</span><strong>Point-in-time</strong></div>
      <div><span>Access model</span><strong>Read-only</strong></div>
      <div><span>Ruleset</span><strong>{report.ruleset?.version || "Not available"}</strong></div>
      <div><span>Controls in ruleset</span><strong>{report.findings.length}</strong></div>
      <div><span>Controls evaluated</span><strong>{evaluated}</strong></div>
      <div><span>Not applicable</span><strong>{notApplicable.length}</strong></div>
      <p>{assessment.scopeStatement}</p>
      <div className="subscriber-disclaimer"><Disclaimer text={assessment.frameworkDisclaimer} /></div>
    </section>

    {assessment.frameworkContext?.referenceUrl && <a className="subscriber-reference" href={assessment.frameworkContext.referenceUrl} target="_blank" rel="noreferrer">AWS Well-Architected Security Pillar <ExternalLink size={14} /></a>}
  </article>;
}
