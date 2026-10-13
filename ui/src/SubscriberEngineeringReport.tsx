import { AlertTriangle, CheckCircle2, CircleAlert, ExternalLink, FileText, RefreshCw, ShieldCheck, TerminalSquare, Wrench } from "lucide-react";
import type { Finding, Report } from "./reportAdapter";
import { reportRoute } from "./reportDelivery";
import "./subscriberReports.css";

const SEVERITY_WEIGHT: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
const ADVANCED_CLI_NOTE = "Optional for users comfortable with AWS CLI or CloudShell. The AWS Console procedure above remains the recommended default. Confirm the active AWS account and Region, replace every value in angle brackets with an environment-specific value, and review the expected configuration impact before execution.";

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

function SubscriberRunbook({ finding, index }: { finding: Finding; index: number }) {
  const guidance = finding.guidance;
  const runbook = guidance?.engineeringRemediation;
  if (!guidance || !runbook) return null;

  return <section className="subscriber-runbook engineering-print-page-start" id={`finding-${finding.id}`}>
    <header className="subscriber-runbook-header">
      <span className="subscriber-runbook-number">{index + 1}</span>
      <div>
        <div className="subscriber-runbook-meta">
          <span className={`subscriber-severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
          <span>{guidance.remediationEffort} effort</span>
          <span>{guidance.awsSecurityArea}</span>
        </div>
        <h2>{finding.title}</h2>
      </div>
    </header>

    <div className="subscriber-runbook-context">
      <div><strong>What AWS Security Coach observed</strong><p>{finding.details || "No additional observation detail was returned."}</p>{finding.resource && <small>Resource: {finding.resource}</small>}</div>
      <div className="risk"><strong>Why this matters</strong><p>{guidance.customerRisk}</p></div>
    </div>

    <div className="subscriber-target-state"><Wrench size={18} /><div><span>Target state</span><strong>{runbook.objective}</strong></div></div>

    <section className="subscriber-runbook-block"><span>Where to go in AWS</span><code className="subscriber-console-path">{runbook.consolePath}</code></section>
    <section className="subscriber-runbook-block"><span>Before you start</span><ul>{runbook.prerequisites.map((item, itemIndex) => <li key={`${finding.id}-pre-${itemIndex}`}>{item}</li>)}</ul></section>
    <section className="subscriber-runbook-block"><span>Step-by-step remediation</span><ol className="subscriber-numbered-steps">{runbook.steps.map((step, stepIndex) => <li key={`${finding.id}-step-${stepIndex}`}><strong>{stepIndex + 1}</strong><span>{step}</span></li>)}</ol></section>

    {runbook.cliCommands.length > 0 && <section className="subscriber-runbook-block subscriber-cli-block engineering-keep-together">
      <span><TerminalSquare size={16} /> Advanced / Optional CLI</span>
      <p>{ADVANCED_CLI_NOTE}</p>
      {runbook.cliCommands.map((command, commandIndex) => <div className="subscriber-cli" key={`${finding.id}-cli-${commandIndex}`}><strong>{command.label}</strong><code>{command.command}</code></div>)}
    </section>}

    <section className="subscriber-caution engineering-keep-together"><AlertTriangle size={18} /><div><strong>Important considerations</strong><ul style={{ marginTop: 14 }}>{runbook.cautions.map((item, itemIndex) => <li style={{ marginTop: itemIndex ? 8 : 0 }} key={`${finding.id}-caution-${itemIndex}`}>{item}</li>)}</ul></div></section>
    <section className="subscriber-verify engineering-keep-together"><CheckCircle2 size={18} /><div><strong>Verify in AWS</strong><ol>{runbook.verificationSteps.map((item, itemIndex) => <li key={`${finding.id}-verify-${itemIndex}`}>{item}</li>)}</ol></div></section>
    <section className="subscriber-reassess engineering-keep-together"><RefreshCw size={18} /><div><strong>Verify with AWS Security Coach</strong><p>After the AWS-side verification is complete, return to AWS Security Coach and run a new assessment for this connected account. Confirm this control reports PASS before considering the finding closed.</p></div></section>

    <footer className="subscriber-aws-context">
      <div><span>AWS Security Pillar area</span><strong>{guidance.awsSecurityArea}</strong></div>
      <div><span>Design principle</span><strong>{guidance.awsDesignPrinciple}</strong></div>
      <p>{guidance.awsBestPracticeContext}</p>
      <a href={guidance.awsReference.url} target="_blank" rel="noreferrer">{guidance.awsReference.title} <ExternalLink size={14} /></a>
    </footer>
  </section>;
}

export function subscriberEngineeringReportReady(report: Report): boolean {
  return Boolean(report.assessment) && report.findings.every(finding => Boolean(finding.guidance?.engineeringRemediation));
}

export default function SubscriberEngineeringReport({ report }: { report: Report }) {
  const assessment = report.assessment;
  if (!assessment) return null;

  const confirmed = sortFindings(report.findings.filter(finding => finding.status === "FAIL" || finding.status === "WARN"));
  const evaluationIssues = report.findings.filter(finding => finding.status === "ERROR");
  const notApplicable = report.findings.filter(finding => finding.status === "NOT_APPLICABLE");
  const passed = report.findings.filter(finding => finding.status === "PASS");
  const evaluated = report.findings.length - notApplicable.length;
  const managementHref = report.scanId ? reportRoute(report.scanId, "self-service", "management") : "#/";

  return <article className="subscriber-report subscriber-engineering-report" aria-label="AWS Security Coach subscriber engineering report">
    <header className="subscriber-header">
      <div>
        <div className="subscriber-brand"><ShieldCheck size={18} /> AWS Security Coach</div>
        <div className="subscriber-eyebrow">Engineering Remediation Report</div>
        <h1>AWS Security Posture Review</h1>
        <p>Operational runbooks for confirmed findings, with AWS-side verification and a self-service reassessment step.</p>
      </div>
      <div className="subscriber-id-card"><span>Assessment ID</span><strong>{assessmentId(report)}</strong><span>Completed</span><strong>{formattedDate(report.generatedAt)}</strong></div>
    </header>

    <section className="subscriber-scoreboard">
      <div><span>Controls evaluated</span><strong>{evaluated}</strong></div>
      <div className={confirmed.length ? "needs-attention" : "clean"}><span>Confirmed findings</span><strong>{confirmed.length}</strong></div>
      <div className={evaluationIssues.length ? "evaluation" : "clean"}><span>Evaluation issues</span><strong>{evaluationIssues.length}</strong></div>
      <div className="clean"><span>Passed</span><strong>{passed.length}</strong></div>
      <div><span>Not applicable</span><strong>{notApplicable.length}</strong></div>
    </section>

    <section className="subscriber-next-step">
      <FileText size={21} />
      <div><strong>Use this report as the remediation workspace</strong><p>Work confirmed findings from highest severity downward. Evaluation issues are separated because they are not confirmed AWS misconfigurations.</p></div>
      <a href={managementHref}>Open Management Report</a>
    </section>

    {confirmed.length > 0 ? <div className="subscriber-runbook-list">{confirmed.map((finding, index) => <SubscriberRunbook key={finding.id} finding={finding} index={index} />)}</div> : <div className="subscriber-clean"><CheckCircle2 size={20} /><span>All applicable, successfully evaluated controls passed. No remediation runbooks are required for this assessment.</span></div>}

    {evaluationIssues.length > 0 && <section className="subscriber-section subscriber-evaluation-section"><div className="subscriber-section-heading"><div><span>Assessment follow-up</span><h2>Evaluation issues</h2></div></div><p className="subscriber-section-copy">Do not make an AWS configuration change based solely on these results. Resolve the access or evaluation condition and run a new assessment first.</p><div className="subscriber-evaluation-list">{evaluationIssues.map(finding => <section className="engineering-print-page-start" key={finding.id}><div><CircleAlert size={18} /><div><strong>{finding.title}</strong><span>{finding.details}</span></div></div></section>)}</div></section>}

    {notApplicable.length > 0 && <section className="subscriber-section engineering-appendix-page"><div className="subscriber-section-heading"><div><span>Scope applicability</span><h2>Not applicable appendix</h2></div><small>{notApplicable.length} excluded from pass calculation</small></div><div className="subscriber-evaluation-list">{notApplicable.map(finding => <div key={finding.id}><ShieldCheck size={16} /><div><strong>{finding.title}</strong><span>{finding.details}</span></div></div>)}</div></section>}

    <section className="subscriber-section engineering-appendix-page">
      <div className="subscriber-section-heading"><div><span>Evidence of good state</span><h2>Passed controls appendix</h2></div><small>{passed.length} passed</small></div>
      <div className="subscriber-pass-grid">{passed.map(finding => <div key={finding.id}><CheckCircle2 size={16} /><span>{finding.title}</span></div>)}</div>
    </section>

    <section className="subscriber-scope engineering-appendix-page">
      <div><span>Assessment type</span><strong>Point-in-time</strong></div><div><span>Access model</span><strong>Read-only</strong></div><div><span>Ruleset</span><strong>{report.ruleset?.version || "Not available"}</strong></div><div><span>Region scope</span><strong>{report.target?.regionScope.join(", ") || "Not available"}</strong></div><div><span>Controls in ruleset</span><strong>{report.findings.length}</strong></div><div><span>Controls evaluated</span><strong>{evaluated}</strong></div><div><span>Not applicable</span><strong>{notApplicable.length}</strong></div>
      <p>{assessment.scopeStatement}</p><div className="subscriber-disclaimer">{assessment.frameworkDisclaimer}</div>
    </section>
  </article>;
}