import { AlertTriangle, CheckCircle2, CircleAlert, ExternalLink, ShieldCheck, TerminalSquare, Wrench } from "lucide-react";
import type { Finding, Report } from "./reportAdapter";
import "./engineeringReport.css";

const SEVERITY_WEIGHT: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
const ADVANCED_CLI_NOTE = "Optional for users comfortable with AWS CLI or CloudShell. The AWS Console procedure above remains the recommended default. Confirm the active AWS account and Region, replace every value in angle brackets with an environment-specific value, and review the expected configuration impact before execution.";

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
  return `engineering-badge engineering-severity engineering-severity-${severity.toLowerCase()}`;
}

function managedText(value: string): string {
  return value
    .replace("The current scanner requires", "The assessment baseline requires")
    .replace("The scan classifies", "This assessment classifies")
    .replace(
      "Permission to create or update CloudTrail trails and the associated log destination.",
      "Confirm you have permission to create or update CloudTrail trails and manage the log destination.",
    )
    .replace(
      "A decision on the S3 log bucket, encryption, retention, and organization-specific log centralization requirements.",
      "Confirm where CloudTrail logs should go: which S3 bucket to use, whether encryption is required, how long logs must be retained, and whether your organization centralizes CloudTrail logs.",
    )
    .replace(
      "The home Region of any existing single-Region trail that may be converted.",
      "If you plan to convert an existing single-Region trail, identify that trail's home Region before using the CLI conversion command.",
    );
}

function awsVerificationSteps(finding: Finding): string[] {
  return (finding.guidance?.engineeringRemediation?.verificationSteps ?? [])
    .filter(step => !/^Rerun\b/i.test(step))
    .map(managedText);
}

function Disclaimer({ text }: { text: string }) {
  const marker = "NOT";
  const index = text.indexOf(marker);
  if (index === -1) return <>{text}</>;
  return <>{text.slice(0, index)}<strong>{marker}</strong>{text.slice(index + marker.length)}</>;
}

function ManagedRunbook({ finding, index }: { finding: Finding; index: number }) {
  const guidance = finding.guidance;
  const runbook = guidance?.engineeringRemediation;
  if (!guidance || !runbook) return null;
  const verificationSteps = awsVerificationSteps(finding);

  return <section className="engineering-finding managed-engineering-finding engineering-print-page-start" id={`finding-${finding.id}`}>
    <div className="engineering-finding-header"><div className="engineering-finding-number">{index + 1}</div><div className="engineering-finding-title-wrap"><div className="engineering-finding-meta"><span className={severityClass(finding.severity)}>{finding.severity}</span><span className={`engineering-badge engineering-status engineering-status-${finding.status.toLowerCase()}`}>{finding.status}</span><span className="engineering-badge engineering-effort">{guidance.remediationEffort} effort</span><span className="engineering-area">{guidance.awsSecurityArea}</span></div><h3>{finding.title}</h3></div></div>

    <div className="engineering-context-grid">
      <div className="engineering-context-card"><span className="engineering-label">What we observed</span><p>{finding.details || "No additional observation detail was returned."}</p>{finding.resource && <div className="engineering-resource"><strong>Resource:</strong> {finding.resource}</div>}</div>
      <div className="engineering-context-card engineering-risk-card"><span className="engineering-label">Why this matters</span><p>{guidance.customerRisk}</p></div>
    </div>

    <div className="engineering-target"><div><Wrench size={18} /><span>Target state</span></div><strong>{managedText(runbook.objective)}</strong></div>
    <div className="engineering-runbook-section"><span className="engineering-label">Where to go in AWS</span><div className="engineering-console-path">{managedText(runbook.consolePath)}</div></div>
    <div className="engineering-runbook-section"><span className="engineering-label">Before you start</span><ul className="engineering-list">{runbook.prerequisites.map((item, itemIndex) => <li key={`${finding.id}-pre-${itemIndex}`}>{managedText(item)}</li>)}</ul></div>
    <div className="engineering-runbook-section"><span className="engineering-label">Step-by-step remediation</span><ol className="engineering-steps">{runbook.steps.map((step, stepIndex) => <li key={`${finding.id}-step-${stepIndex}`}><span className="engineering-step-number">{stepIndex + 1}</span><span>{managedText(step)}</span></li>)}</ol></div>

    {runbook.cliCommands.length > 0 && <div className="engineering-runbook-section engineering-keep-together"><div className="engineering-cli-heading"><TerminalSquare size={17} /><span className="engineering-label">Advanced / Optional CLI</span></div><p className="engineering-cli-note">{ADVANCED_CLI_NOTE}</p><div className="engineering-cli-list">{runbook.cliCommands.map((command, commandIndex) => <div className="engineering-cli" key={`${finding.id}-cli-${commandIndex}`}><strong>{command.label}</strong><code>{command.command}</code></div>)}</div></div>}

    <div className="engineering-caution engineering-keep-together"><div className="engineering-caution-title"><AlertTriangle size={18} /><strong>Important considerations</strong></div><ul className="engineering-list" style={{ marginTop: 14 }}>{runbook.cautions.map((caution, cautionIndex) => <li style={{ marginTop: cautionIndex ? 8 : 0 }} key={`${finding.id}-caution-${cautionIndex}`}>{managedText(caution)}</li>)}</ul></div>
    <div className="engineering-verify engineering-keep-together"><div className="engineering-verify-title"><CheckCircle2 size={18} /><strong>Verify in AWS</strong></div><ol className="engineering-verification-list">{verificationSteps.map((step, stepIndex) => <li key={`${finding.id}-verify-${stepIndex}`}>{step}</li>)}</ol></div>
    <div className="engineering-evaluation-warning engineering-keep-together"><CheckCircle2 size={19} /><div><strong>Follow-up verification</strong><span>After the AWS-side checks are complete, notify your assessment contact that remediation is ready for verification. A follow-up point-in-time review can confirm whether this control now passes.</span></div></div>

    <div className="engineering-aws-context"><div><span>AWS Security Pillar area</span><strong>{guidance.awsSecurityArea}</strong></div><div><span>Design principle</span><strong>{guidance.awsDesignPrinciple}</strong></div><p>{guidance.awsBestPracticeContext}</p><a href={guidance.awsReference.url} target="_blank" rel="noreferrer">{guidance.awsReference.title} <ExternalLink size={14} /></a></div>
  </section>;
}

export function managedEngineeringReportReady(report: Report): boolean {
  return Boolean(report.assessment) && report.findings.every(finding => Boolean(finding.guidance?.engineeringRemediation));
}

export default function ManagedEngineeringReport({ report }: { report: Report }) {
  const assessment = report.assessment;
  if (!assessment) return null;

  const confirmed = sortFindings(report.findings.filter(finding => finding.status === "FAIL" || finding.status === "WARN"));
  const evaluationIssues = report.findings.filter(finding => finding.status === "ERROR");
  const notApplicable = report.findings.filter(finding => finding.status === "NOT_APPLICABLE");
  const passed = report.findings.filter(finding => finding.status === "PASS");
  const evaluated = report.findings.length - notApplicable.length;
  const regionScope = report.target?.regionScope.join(", ") || "Not available";

  return <article className="engineering-report managed-engineering-report" aria-label="Managed AWS Security Posture Review engineering remediation report">
    <header className="engineering-report-header"><div><div className="engineering-eyebrow">Engineering Remediation Report</div><h2>{assessment.title}</h2><p>Customer-facing remediation procedures for confirmed findings from this point-in-time AWS security assessment.</p></div><div className="engineering-identity">{report.customer && <><span>Customer / Organization</span><strong>{report.customer.organization}</strong><span>AWS Account ID</span><strong>{report.customer.awsAccountId}</strong></>}<span>Assessment ID</span><strong>{assessmentId(report)}</strong><span>Prepared</span><strong>{formattedDate(report.generatedAt)}</strong></div></header>

    <section className="engineering-summary"><div className="engineering-summary-card"><span>Controls evaluated</span><strong>{evaluated}</strong></div><div className="engineering-summary-card attention"><span>Confirmed findings</span><strong>{confirmed.length}</strong></div><div className="engineering-summary-card"><span>Evaluation issues</span><strong>{evaluationIssues.length}</strong></div><div className="engineering-summary-card clean"><span>Passed</span><strong>{passed.length}</strong></div><div className="engineering-summary-card"><span>Not applicable</span><strong>{notApplicable.length}</strong></div></section>

    <section className="engineering-intro"><ShieldCheck size={22} /><div><strong>How to use this report</strong><p>Work confirmed findings from highest severity downward. Each confirmed finding starts on its own page when printed or exported to PDF. The AWS Console procedure is the recommended default. Advanced CLI/CloudShell options appear only when they add useful repeatability or capability. The runbook also shows the observed state, technical impact, prerequisites, important considerations, AWS-side verification, and first-party AWS references. Evaluation issues start on their own pages because they are not confirmed misconfigurations.</p></div></section>

    <section className="engineering-section-heading"><div><span className="engineering-eyebrow">Remediation runbooks</span><h2>{confirmed.length ? `${confirmed.length} confirmed ${confirmed.length === 1 ? "finding" : "findings"}` : "No confirmed remediation required"}</h2></div><span>Highest severity first</span></section>
    {confirmed.length ? <div className="engineering-findings">{confirmed.map((finding, index) => <ManagedRunbook finding={finding} index={index} key={finding.id} />)}</div> : <div className="engineering-clean-callout"><CheckCircle2 size={20} /><span>All successfully evaluated controls passed. No remediation runbooks are required for this assessed baseline.</span></div>}

    {evaluationIssues.length > 0 && <section className="engineering-passed-section"><div className="engineering-section-heading"><div><span className="engineering-eyebrow">Assessment follow-up</span><h2>Evaluation issues</h2></div><span>{evaluationIssues.length} require follow-up</span></div><div className="engineering-findings">{evaluationIssues.map(finding => <section className="engineering-evaluation-page engineering-print-page-start" key={finding.id}><div className="engineering-evaluation-warning"><CircleAlert size={19} /><div><strong>{finding.title}</strong><span>{finding.details}</span><span>This result does not establish that the AWS configuration is compliant or noncompliant. Do not make an AWS configuration change based solely on this result. Resolve the assessment access or evaluation condition first, then request follow-up verification.</span></div></div></section>)}</div></section>}

    {notApplicable.length > 0 && <section className="engineering-passed-section engineering-appendix-page"><div className="engineering-section-heading"><div><span className="engineering-eyebrow">Scope applicability</span><h2>Not applicable appendix</h2></div><span>{notApplicable.length} excluded from pass calculation</span></div><div className="engineering-passed-grid">{notApplicable.map(finding => <div className="engineering-passed-item" key={finding.id}><CircleAlert size={17} /><div><strong>{finding.title}</strong><span>{finding.details}</span></div></div>)}</div></section>}

    <section className="engineering-passed-section engineering-appendix-page"><div className="engineering-section-heading"><div><span className="engineering-eyebrow">Evidence of good state</span><h2>Passed controls appendix</h2></div><span>{passed.length} passed</span></div><div className="engineering-passed-grid">{passed.map(finding => <div className="engineering-passed-item" key={finding.id}><CheckCircle2 size={17} /><div><strong>{finding.title}</strong><span>{finding.details}</span></div></div>)}</div></section>

    <section className="engineering-methodology engineering-appendix-page"><div><span>Assessment type</span><strong>Point-in-time</strong></div><div><span>Access model</span><strong>Read-only</strong></div><div><span>Ruleset</span><strong>{report.ruleset?.version || "Not available"}</strong></div><div><span>Region scope</span><strong>{regionScope}</strong></div><div><span>Controls in ruleset</span><strong>{report.findings.length}</strong></div><div><span>Controls evaluated</span><strong>{evaluated}</strong></div><div><span>Not applicable</span><strong>{notApplicable.length}</strong></div><p>{assessment.scopeStatement}</p><div className="engineering-disclaimer"><Disclaimer text={assessment.frameworkDisclaimer} /></div></section>
  </article>;
}