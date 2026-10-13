import { AlertTriangle, CheckCircle2, ExternalLink, ShieldCheck } from "lucide-react";
import type { Finding, Report } from "./reportAdapter";
import "./managementReport.css";
import "./managementReportEnhancements.css";

type ManagementReportProps = {
  report: Report;
  targetName?: string;
};

const SEVERITY_WEIGHT: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

const AREA_ORDER = [
  "Identity and access management",
  "Detection",
  "Infrastructure protection",
  "Data protection",
];

function attentionFindings(report: Report): Finding[] {
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
  const normalized = severity.toLowerCase();
  return `management-badge management-severity management-severity-${normalized}`;
}

function disposition(report: Report): { title: string; copy: string } {
  const active = attentionFindings(report);
  if (active.some(finding => finding.status === "ERROR")) {
    return {
      title: "Assessment follow-up required",
      copy: "One or more controls could not be evaluated reliably. Resolve the evaluation issue and reassess before relying on the result as a complete baseline for the assessed controls.",
    };
  }
  if (active.some(finding => ["CRITICAL", "HIGH"].includes(finding.severity))) {
    return {
      title: "Immediate remediation recommended",
      copy: "Prioritize the highest-severity findings first, then reassess the affected controls after changes are complete.",
    };
  }
  if (active.some(finding => finding.severity === "MEDIUM")) {
    return {
      title: "Remediation recommended",
      copy: "Address the identified control gaps as part of the next security maintenance window, then reassess the affected controls.",
    };
  }
  if (active.length > 0) {
    return {
      title: "Review recommended",
      copy: "Review the identified items and determine whether remediation is appropriate for the workload and organizational requirements.",
    };
  }
  return {
    title: "No immediate action identified within assessed scope",
    copy: "All assessed controls passed at the time of review. Continue normal security maintenance and reassess after material AWS configuration changes.",
  };
}

function areaSummary(report: Report) {
  const areas = new Map<string, { total: number; passed: number; attention: number }>();
  for (const finding of report.findings) {
    const area = finding.guidance?.awsSecurityArea;
    if (!area) continue;
    const current = areas.get(area) ?? { total: 0, passed: 0, attention: 0 };
    current.total += 1;
    if (finding.status === "PASS") current.passed += 1;
    else current.attention += 1;
    areas.set(area, current);
  }

  return [...areas.entries()].sort(([left], [right]) => {
    const leftIndex = AREA_ORDER.indexOf(left);
    const rightIndex = AREA_ORDER.indexOf(right);
    if (leftIndex === -1 && rightIndex === -1) return left.localeCompare(right);
    if (leftIndex === -1) return 1;
    if (rightIndex === -1) return -1;
    return leftIndex - rightIndex;
  });
}

function Disclaimer({ text }: { text: string }) {
  const marker = "NOT";
  const markerIndex = text.indexOf(marker);
  if (markerIndex === -1) return <>{text}</>;
  return <>
    {text.slice(0, markerIndex)}<strong>{marker}</strong>{text.slice(markerIndex + marker.length)}
  </>;
}

export default function ManagementReport({ report }: ManagementReportProps) {
  const assessment = report.assessment;
  if (!assessment) return null;

  const total = report.findings.length;
  const passed = report.findings.filter(finding => finding.status === "PASS").length;
  const active = attentionFindings(report);
  const topActions = active.slice(0, 3);
  const confirmed = report.findings.filter(finding => finding.status === "PASS");
  const areas = areaSummary(report);
  const recommendation = disposition(report);
  const regionScope = report.target?.regionScope.join(", ") || "Not available";
  const rulesetVersion = report.ruleset?.version || "Not available";
  const connectorAssessment = report.target?.type === "connector";

  return <article className="management-report" aria-label="AWS Security Posture Review management summary">
    <header className="management-report-header">
      <div>
        <div className="management-eyebrow">Management Summary</div>
        <h2>{assessment.title}</h2>
        <p className="management-target">Point-in-time review of selected foundational AWS security controls.</p>
      </div>
      <div className="management-identity">
        <span>Assessment ID</span><strong>{assessmentId(report)}</strong>
        <span>Prepared</span><strong>{formattedDate(report.generatedAt)}</strong>
      </div>
    </header>

    <section className="management-overview">
      <div className="management-overview-main">
        <span className="management-overview-number">{passed} of {total}</span>
        <span className="management-overview-label">assessed checks passed</span>
      </div>
      <div className={active.length === 0 ? "management-overview-state clean" : "management-overview-state attention"}>
        {active.length === 0 ? <CheckCircle2 size={20} /> : <AlertTriangle size={20} />}
        <div>
          <strong>{active.length === 0 ? "All assessed checks passed" : `${active.length} ${active.length === 1 ? "check needs" : "checks need"} attention`}</strong>
          <span>{active.length === 0 ? `The assessed baseline returned ${total} passing checks.` : "Priorities below are ordered by severity."}</span>
        </div>
      </div>
    </section>

    <section className="management-section">
      <div className="management-section-heading">
        <div><span className="management-section-kicker">Priority</span><h3>Top Actions</h3></div>
        <span className="management-section-note">Highest severity first</span>
      </div>
      {topActions.length > 0 ? (
        <div className="management-actions">
          {topActions.map((finding, index) => <div className="management-action" key={finding.id}>
            <div className="management-action-index">{index + 1}</div>
            <div className="management-action-body">
              <div className="management-action-meta">
                <span className={severityClass(finding.severity)}>{finding.severity}</span>
                {finding.guidance?.remediationEffort && <span className="management-badge management-effort">{finding.guidance.remediationEffort} effort</span>}
                {finding.guidance?.awsSecurityArea && <span className="management-area-label">{finding.guidance.awsSecurityArea}</span>}
              </div>
              <h4>{finding.title}</h4>
              {finding.details && <div className="management-observed"><strong>What we observed:</strong> {finding.details}</div>}
              {finding.guidance?.customerRisk && <div className="management-impact">
                <strong>Why this matters</strong>
                <p>{finding.guidance.customerRisk}</p>
              </div>}
              {finding.guidance?.remediation && <div className="management-recommendation"><strong>Recommended action:</strong> {finding.guidance.remediation}</div>}
              {finding.guidance?.awsReference && <a className="management-action-reference" href={finding.guidance.awsReference.url} target="_blank" rel="noreferrer">
                AWS reference: {finding.guidance.awsReference.title} <ExternalLink size={13} />
              </a>}
            </div>
          </div>)}
        </div>
      ) : (
        <div className="management-clean-callout"><CheckCircle2 size={20} /><span>All assessed checks passed; no remediation action is listed for the assessed controls.</span></div>
      )}
    </section>

    <section className="management-section">
      <div className="management-section-heading">
        <div><span className="management-section-kicker">AWS context</span><h3>Security Pillar Areas</h3></div>
      </div>
      <div className="management-area-grid">
        {areas.map(([area, counts]) => <div className="management-area-card" key={area}>
          <div className="management-area-title"><ShieldCheck size={18} /><span>{area}</span></div>
          <div className="management-area-count"><strong>{counts.passed} of {counts.total}</strong> checks passed</div>
          <div className={counts.attention === 0 ? "management-area-state clean" : "management-area-state attention"}>
            {counts.attention === 0 ? "All assessed checks passed in this area" : `${counts.attention} ${counts.attention === 1 ? "item" : "items"} need attention`}
          </div>
        </div>)}
      </div>
    </section>

    <section className="management-section">
      <div className="management-section-heading">
        <div><span className="management-section-kicker">Evidence of good state</span><h3>Controls Confirmed</h3></div>
        <span className="management-section-note">{confirmed.length} passed</span>
      </div>
      <div className="management-confirmed-grid">
        {confirmed.map(finding => <div className="management-confirmed-item" key={finding.id}>
          <CheckCircle2 size={17} /><span>{finding.title}</span>
        </div>)}
      </div>
    </section>

    <section className="management-section management-methodology">
      <div className="management-section-heading">
        <div><span className="management-section-kicker">Bounded assessment</span><h3>Scope & Methodology</h3></div>
      </div>
      <div className="management-scope-grid">
        <div><span>Assessment type</span><strong>Point-in-time</strong></div>
        <div><span>Access model</span><strong>Read-only</strong></div>
        <div><span>Region scope</span><strong>{regionScope}</strong></div>
        <div><span>Ruleset version</span><strong>{rulesetVersion}</strong></div>
        <div><span>Controls assessed</span><strong>{total}</strong></div>
        <div><span>Resource changes</span><strong>None</strong></div>
      </div>
      <p>{assessment.scopeStatement}</p>
      <p>{connectorAssessment
        ? "The review used temporary read-only access through a customer-deployed AWS connector. The assessment did not modify AWS resources."
        : "The review used read-only AWS permissions and did not modify AWS resources."}</p>
      <div className="management-disclaimer"><Disclaimer text={assessment.frameworkDisclaimer} /></div>
    </section>

    <section className="management-disposition">
      <div><span className="management-section-kicker">Recommended disposition</span><h3>{recommendation.title}</h3></div>
      <p>{recommendation.copy}</p>
      <p className="management-reassessment">Reassessment is recommended after material AWS configuration changes or after remediation of identified findings.</p>
    </section>

    {assessment.frameworkContext?.referenceUrl && <a className="management-framework-link" href={assessment.frameworkContext.referenceUrl} target="_blank" rel="noreferrer">
      AWS Well-Architected Security Pillar reference <ExternalLink size={14} />
    </a>}
  </article>;
}
