import {
  AlertTriangle,
  CheckCircle2,
  CircleAlert,
  ExternalLink,
  ShieldCheck,
  TerminalSquare,
  Wrench,
} from "lucide-react";
import type { Finding, Report } from "./reportAdapter";
import "./engineeringReport.css";

type EngineeringReportProps = {
  report: Report;
};

const SEVERITY_WEIGHT: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

function sortedActionFindings(report: Report): Finding[] {
  return report.findings
    .filter(finding => finding.status !== "PASS")
    .sort((left, right) => {
      const severityDifference = (SEVERITY_WEIGHT[right.severity] ?? 0) - (SEVERITY_WEIGHT[left.severity] ?? 0);
      if (severityDifference !== 0) return severityDifference;
      return left.title.localeCompare(right.title);
    });
}

function formattedDate(value?: string): string {
  if (!value) return "Not available";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    timeZone: "UTC",
  }).format(parsed);
}

function assessmentId(report: Report): string {
  const year = report.generatedAt && !Number.isNaN(new Date(report.generatedAt).getTime())
    ? new Date(report.generatedAt).getUTCFullYear()
    : new Date().getUTCFullYear();
  const shortId = report.scanId?.replace(/[^A-Za-z0-9]/g, "").slice(0, 8).toUpperCase() || "PENDING";
  return `ASC-${year}-${shortId}`;
}

function severityClass(severity: string): string {
  return `engineering-badge engineering-severity engineering-severity-${severity.toLowerCase()}`;
}

function Disclaimer({ text }: { text: string }) {
  const marker = "NOT";
  const markerIndex = text.indexOf(marker);
  if (markerIndex === -1) return <>{text}</>;
  return <>
    {text.slice(0, markerIndex)}<strong>{marker}</strong>{text.slice(markerIndex + marker.length)}
  </>;
}

export function engineeringReportReady(report: Report): boolean {
  return Boolean(report.assessment)
    && report.findings.every(finding => Boolean(finding.guidance?.engineeringRemediation));
}

function FindingRunbook({ finding, index }: { finding: Finding; index: number }) {
  const guidance = finding.guidance;
  const runbook = guidance?.engineeringRemediation;
  if (!guidance || !runbook) return null;
  const evaluationError = finding.status === "ERROR";

  return <section className="engineering-finding" id={`finding-${finding.id}`}>
    <div className="engineering-finding-header">
      <div className="engineering-finding-number">{index + 1}</div>
      <div className="engineering-finding-title-wrap">
        <div className="engineering-finding-meta">
          <span className={severityClass(finding.severity)}>{finding.severity}</span>
          <span className={`engineering-badge engineering-status engineering-status-${finding.status.toLowerCase()}`}>{finding.status}</span>
          <span className="engineering-badge engineering-effort">{guidance.remediationEffort} effort</span>
          <span className="engineering-area">{guidance.awsSecurityArea}</span>
        </div>
        <h3>{finding.title}</h3>
      </div>
    </div>

    {evaluationError && <div className="engineering-evaluation-warning">
      <CircleAlert size={19} />
      <div><strong>Evaluation issue — do not treat this as a confirmed misconfiguration.</strong>
        <span>Resolve the assessment or permission error and rerun this control before making an AWS change based solely on this result. The remediation procedure below is reference guidance if the control is later confirmed to fail.</span>
      </div>
    </div>}

    <div className="engineering-context-grid">
      <div className="engineering-context-card">
        <span className="engineering-label">What we observed</span>
        <p>{finding.details || "No additional observation detail was returned."}</p>
        {finding.resource && <div className="engineering-resource"><strong>Resource:</strong> {finding.resource}</div>}
      </div>
      <div className="engineering-context-card engineering-risk-card">
        <span className="engineering-label">Why this matters</span>
        <p>{guidance.customerRisk}</p>
      </div>
    </div>

    <div className="engineering-target">
      <div><Wrench size={18} /><span>Target state</span></div>
      <strong>{runbook.objective}</strong>
    </div>

    <div className="engineering-runbook-section">
      <span className="engineering-label">Where to go in AWS</span>
      <div className="engineering-console-path">{runbook.consolePath}</div>
    </div>

    <div className="engineering-runbook-section">
      <span className="engineering-label">Before you change anything</span>
      <ul className="engineering-list">
        {runbook.prerequisites.map((item, itemIndex) => <li key={`${finding.id}-prereq-${itemIndex}`}>{item}</li>)}
      </ul>
    </div>

    <div className="engineering-runbook-section">
      <span className="engineering-label">Step-by-step remediation</span>
      <ol className="engineering-steps">
        {runbook.steps.map((step, stepIndex) => <li key={`${finding.id}-step-${stepIndex}`}>
          <span className="engineering-step-number">{stepIndex + 1}</span><span>{step}</span>
        </li>)}
      </ol>
    </div>

    {runbook.cliCommands.length > 0 && <div className="engineering-runbook-section">
      <div className="engineering-cli-heading"><TerminalSquare size={17} /><span className="engineering-label">AWS CLI alternative</span></div>
      <p className="engineering-cli-note">Replace every value in angle brackets with an environment-specific value and review the command before execution.</p>
      <div className="engineering-cli-list">
        {runbook.cliCommands.map((command, commandIndex) => <div className="engineering-cli" key={`${finding.id}-cli-${commandIndex}`}>
          <strong>{command.label}</strong>
          <code>{command.command}</code>
        </div>)}
      </div>
    </div>}

    <div className="engineering-caution">
      <div className="engineering-caution-title"><AlertTriangle size={18} /><strong>Change cautions</strong></div>
      <ul className="engineering-list">
        {runbook.cautions.map((caution, cautionIndex) => <li key={`${finding.id}-caution-${cautionIndex}`}>{caution}</li>)}
      </ul>
    </div>

    <div className="engineering-verify">
      <div className="engineering-verify-title"><CheckCircle2 size={18} /><strong>Verify the fix</strong></div>
      <ol className="engineering-verification-list">
        {runbook.verificationSteps.map((step, stepIndex) => <li key={`${finding.id}-verify-${stepIndex}`}>{step}</li>)}
      </ol>
    </div>

    <div className="engineering-aws-context">
      <div><span>AWS Security Pillar area</span><strong>{guidance.awsSecurityArea}</strong></div>
      <div><span>Design principle</span><strong>{guidance.awsDesignPrinciple}</strong></div>
      <p>{guidance.awsBestPracticeContext}</p>
      <a href={guidance.awsReference.url} target="_blank" rel="noreferrer">
        {guidance.awsReference.title} <ExternalLink size={14} />
      </a>
    </div>
  </section>;
}

export default function EngineeringReport({ report }: EngineeringReportProps) {
  const assessment = report.assessment;
  if (!assessment) return null;

  const actionFindings = sortedActionFindings(report);
  const passedFindings = report.findings.filter(finding => finding.status === "PASS");
  const regionScope = report.target?.regionScope.join(", ") || "Not available";
  const rulesetVersion = report.ruleset?.version || "Not available";

  return <article className="engineering-report" aria-label="AWS Security Posture Review engineering remediation report">
    <header className="engineering-report-header">
      <div>
        <div className="engineering-eyebrow">Engineering Remediation Report</div>
        <h2>{assessment.title}</h2>
        <p>Actionable remediation procedures for the controls evaluated in this point-in-time AWS security assessment.</p>
      </div>
      <div className="engineering-identity">
        <span>Assessment ID</span><strong>{assessmentId(report)}</strong>
        <span>Prepared</span><strong>{formattedDate(report.generatedAt)}</strong>
      </div>
    </header>

    <section className="engineering-summary">
      <div className="engineering-summary-card"><span>Controls assessed</span><strong>{report.findings.length}</strong></div>
      <div className="engineering-summary-card attention"><span>Need attention</span><strong>{actionFindings.length}</strong></div>
      <div className="engineering-summary-card clean"><span>Passed</span><strong>{passedFindings.length}</strong></div>
      <div className="engineering-summary-card"><span>Region scope</span><strong>{regionScope}</strong></div>
    </section>

    <section className="engineering-intro">
      <ShieldCheck size={22} />
      <div><strong>How to use this report</strong>
        <p>Work findings from highest severity downward. Each runbook shows the observed state, customer impact, AWS console path, prerequisites, ordered remediation steps, change cautions, verification steps, and first-party AWS reference. Commands are optional examples with placeholders; review them for the environment before execution.</p>
      </div>
    </section>

    <section className="engineering-section-heading">
      <div><span className="engineering-eyebrow">Remediation runbooks</span><h2>{actionFindings.length > 0 ? `${actionFindings.length} controls need attention` : "No remediation runbooks required"}</h2></div>
      <span>Highest severity first</span>
    </section>

    {actionFindings.length > 0 ? (
      <div className="engineering-findings">
        {actionFindings.map((finding, index) => <FindingRunbook finding={finding} index={index} key={finding.id} />)}
      </div>
    ) : (
      <div className="engineering-clean-callout"><CheckCircle2 size={20} /><span>All assessed controls passed at the time of review. No remediation steps are required for this assessed baseline.</span></div>
    )}

    <section className="engineering-passed-section">
      <div className="engineering-section-heading">
        <div><span className="engineering-eyebrow">Evidence of good state</span><h2>Passed controls appendix</h2></div>
        <span>{passedFindings.length} passed</span>
      </div>
      <div className="engineering-passed-grid">
        {passedFindings.map(finding => <div className="engineering-passed-item" key={finding.id}>
          <CheckCircle2 size={17} />
          <div><strong>{finding.title}</strong><span>{finding.details}</span></div>
        </div>)}
      </div>
    </section>

    <section className="engineering-methodology">
      <div><span>Assessment type</span><strong>Point-in-time</strong></div>
      <div><span>Access model</span><strong>Read-only</strong></div>
      <div><span>Ruleset</span><strong>{rulesetVersion}</strong></div>
      <div><span>Region scope</span><strong>{regionScope}</strong></div>
      <p>{assessment.scopeStatement}</p>
      <div className="engineering-disclaimer"><Disclaimer text={assessment.frameworkDisclaimer} /></div>
    </section>
  </article>;
}
