import type { Finding, Report } from "./reportAdapter";
import { CONTENT_WIDTH, MARGIN_X, PdfBuilder, sanitizePdfText, SLATE } from "./simplePdf";

export type SubscriberPdfDocumentType = "management" | "engineering";

const SEVERITY_WEIGHT: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
const NAVY = [0.035, 0.085, 0.17] as const;
const WHITE = [1, 1, 1] as const;
const LIGHT_TEXT = [0.84, 0.88, 0.93] as const;
const MUTED_LIGHT = [0.64, 0.73, 0.84] as const;
const ACCENT_BLUE = [0.08, 0.30, 0.78] as const;
const HIGH = [0.82, 0.36, 0.02] as const;
const MEDIUM = [0.86, 0.52, 0.04] as const;
const LOW = [0.08, 0.30, 0.78] as const;
const CRITICAL = [0.73, 0.12, 0.16] as const;
const INFO = [0.38, 0.45, 0.55] as const;
const BORDER = [0.84, 0.88, 0.92] as const;
const SOFT_BLUE = [0.95, 0.97, 1] as const;
const ADVANCED_CLI_NOTE = "Optional for users comfortable with AWS CLI or CloudShell. The AWS Console procedure above remains the recommended default. Confirm the active AWS account and Region, replace every value in angle brackets with an environment-specific value, and review the expected configuration impact before execution.";
const SELF_SERVICE_REASSESSMENT = "After the AWS-side verification is complete, return to AWS Security Coach and run a new assessment for this connected account. Confirm the affected control reports PASS before considering the finding closed.";

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((left, right) => {
    const severity = (SEVERITY_WEIGHT[right.severity] ?? 0) - (SEVERITY_WEIGHT[left.severity] ?? 0);
    return severity || left.title.localeCompare(right.title);
  });
}

function formattedDate(value?: string): string {
  if (!value) return "Not available";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return sanitizePdfText(value);
  return new Intl.DateTimeFormat("en-US", { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" }).format(parsed);
}

function dateStamp(value?: string): string {
  const parsed = value ? new Date(value) : new Date();
  const date = Number.isNaN(parsed.getTime()) ? new Date() : parsed;
  return date.toISOString().slice(0, 10);
}

function assessmentId(report: Report): string {
  const year = report.generatedAt && !Number.isNaN(new Date(report.generatedAt).getTime()) ? new Date(report.generatedAt).getUTCFullYear() : new Date().getUTCFullYear();
  const shortId = report.scanId?.replace(/[^A-Za-z0-9]/g, "").slice(0, 8).toUpperCase() || "PENDING";
  return `ASC-${year}-${shortId}`;
}

function regionScope(report: Report): string {
  return report.target?.regionScope.join(", ") || "Not available";
}

function severityColor(severity: string) {
  if (severity === "CRITICAL") return CRITICAL;
  if (severity === "HIGH") return HIGH;
  if (severity === "MEDIUM") return MEDIUM;
  if (severity === "LOW") return LOW;
  return INFO;
}

function findingMeta(finding: Finding): string {
  const area = finding.guidance?.awsSecurityArea;
  const effort = finding.guidance?.remediationEffort;
  return [area, effort ? `Estimated effort: ${effort.toLowerCase()}` : undefined].filter(Boolean).join(" | ");
}

function coverPage(pdf: PdfBuilder, report: Report, documentLabel: string, subtitle: string): void {
  pdf.rect(0, 0, 612, 792, NAVY);
  pdf.rect(0, 0, 10, 792, ACCENT_BLUE);
  pdf.spacer(116);
  pdf.text("AWS SECURITY COACH", MARGIN_X, { font: "bold", size: 9, color: MUTED_LIGHT, lineHeight: 12, maxWidth: CONTENT_WIDTH });
  pdf.spacer(12);
  pdf.text(documentLabel, MARGIN_X, { font: "bold", size: 28, color: WHITE, lineHeight: 34, maxWidth: CONTENT_WIDTH });
  pdf.spacer(10);
  pdf.text(subtitle, MARGIN_X, { size: 11.5, color: LIGHT_TEXT, lineHeight: 16, maxWidth: CONTENT_WIDTH - 36 });
  pdf.spacer(90);
  pdf.text("ASSESSMENT", MARGIN_X, { font: "bold", size: 7.5, color: MUTED_LIGHT, lineHeight: 10, maxWidth: CONTENT_WIDTH });
  pdf.spacer(5);
  pdf.text(assessmentId(report), MARGIN_X, { font: "bold", size: 18, color: WHITE, lineHeight: 23, maxWidth: CONTENT_WIDTH });
  pdf.spacer(22);
  pdf.text(`Completed: ${formattedDate(report.generatedAt)}`, MARGIN_X, { size: 10, color: LIGHT_TEXT, lineHeight: 14, maxWidth: CONTENT_WIDTH });
  pdf.text(`Region scope: ${regionScope(report)}`, MARGIN_X, { size: 10, color: LIGHT_TEXT, lineHeight: 14, maxWidth: CONTENT_WIDTH });
  pdf.spacer(96);
  pdf.text("AWS Security Coach", MARGIN_X, { font: "bold", size: 10.5, color: WHITE, lineHeight: 14, maxWidth: CONTENT_WIDTH });
  pdf.text("Point-in-time, read-only AWS security posture assessment", MARGIN_X, { size: 9.5, color: MUTED_LIGHT, lineHeight: 13, maxWidth: CONTENT_WIDTH });
  pdf.newPage();
}

function hero(pdf: PdfBuilder, report: Report, documentLabel: string, subtitle: string): void {
  pdf.rect(MARGIN_X, 50, CONTENT_WIDTH, 205, NAVY);
  pdf.rect(MARGIN_X, 50, 6, 205, ACCENT_BLUE);
  pdf.spacer(18);
  pdf.text(documentLabel.toUpperCase(), MARGIN_X + 24, { font: "bold", size: 8, color: MUTED_LIGHT, lineHeight: 11, maxWidth: CONTENT_WIDTH - 48 });
  pdf.spacer(6);
  pdf.text(report.assessment?.title || "AWS Security Posture Review", MARGIN_X + 24, { font: "bold", size: 25, color: WHITE, lineHeight: 29, maxWidth: CONTENT_WIDTH - 48 });
  pdf.spacer(5);
  pdf.text(subtitle, MARGIN_X + 24, { size: 10.6, color: LIGHT_TEXT, lineHeight: 14.5, maxWidth: CONTENT_WIDTH - 48 });
  pdf.spacer(18);
  const colWidth = (CONTENT_WIDTH - 84) / 3;
  const h1 = pdf.labelValue("Assessment", assessmentId(report), MARGIN_X + 24, colWidth);
  const h2 = pdf.labelValue("Completed", formattedDate(report.generatedAt), MARGIN_X + 42 + colWidth, colWidth);
  const h3 = pdf.labelValue("Ruleset", report.ruleset?.version || "Not available", MARGIN_X + 60 + colWidth * 2, colWidth);
  pdf.advance(Math.max(h1, h2, h3));
  pdf.spacer(18);
  pdf.rule();
  pdf.spacer(4);
}

function findingPageHeader(pdf: PdfBuilder, label: string, finding: Finding): void {
  const tone = severityColor(finding.severity);
  pdf.rect(MARGIN_X, 50, CONTENT_WIDTH, 108, SOFT_BLUE, BORDER);
  pdf.rect(MARGIN_X, 50, 6, 108, tone);
  pdf.spacer(13);
  pdf.text(label.toUpperCase(), MARGIN_X + 18, { font: "bold", size: 7.5, color: SLATE, lineHeight: 10, maxWidth: CONTENT_WIDTH - 36 });
  pdf.spacer(4);
  pdf.text(finding.severity, MARGIN_X + 18, { font: "bold", size: 8.3, color: tone, lineHeight: 11, maxWidth: CONTENT_WIDTH - 36 });
  pdf.spacer(3);
  pdf.text(finding.title, MARGIN_X + 18, { font: "bold", size: 19, color: NAVY, lineHeight: 23, maxWidth: CONTENT_WIDTH - 36 });
  const meta = findingMeta(finding);
  if (meta) {
    pdf.spacer(3);
    pdf.text(meta, MARGIN_X + 18, { size: 9, color: SLATE, lineHeight: 12, maxWidth: CONTENT_WIDTH - 36 });
  }
  pdf.spacer(20);
}

function addManagementPdf(pdf: PdfBuilder, report: Report): void {
  const assessment = report.assessment;
  const passed = report.findings.filter(f => f.status === "PASS");
  const na = report.findings.filter(f => f.status === "NOT_APPLICABLE");
  const confirmed = sortFindings(report.findings.filter(f => f.status === "FAIL" || f.status === "WARN"));
  const errors = sortFindings(report.findings.filter(f => f.status === "ERROR"));
  const evaluated = report.findings.length - na.length;

  coverPage(pdf, report, "Management Report", "Self-service executive view of the foundational AWS controls assessed for this connected account.");
  hero(pdf, report, "Management Report", "Point-in-time visibility into the foundational AWS controls assessed for this connected account.");
  pdf.metrics([
    { label: "Controls evaluated", value: String(evaluated) },
    { label: "Passed", value: String(passed.length), tone: "clean" },
    { label: "Needs attention", value: String(confirmed.length), tone: confirmed.length ? "attention" : "clean" },
    ...(errors.length ? [{ label: "Evaluation issues", value: String(errors.length), tone: "attention" as const }] : []),
    ...(na.length ? [{ label: "Not applicable", value: String(na.length), tone: "neutral" as const }] : []),
  ]);

  pdf.callout("Your assessment is a point-in-time result", "Make AWS changes using the Engineering Remediation Report, then run a new assessment in AWS Security Coach to confirm the affected controls now pass.", "blue");
  pdf.kicker("Priority");
  pdf.heading("What to Address First", 17);
  if (confirmed.length) {
    confirmed.slice(0, 3).forEach((finding, index) => {
      pdf.callout(`${index + 1}. ${finding.severity} - ${finding.title}`, `${finding.details || "No additional observation detail was returned."}${finding.guidance?.customerRisk ? `\n\nWhy it matters: ${finding.guidance.customerRisk}` : ""}${finding.guidance?.remediation ? `\n\nRecommended action: ${finding.guidance.remediation}` : ""}`, "blue");
    });
  } else {
    pdf.callout("No confirmed remediation required", "All applicable, successfully evaluated controls passed. No confirmed remediation is required within this assessed baseline.", "green");
  }

  if (errors.length) {
    pdf.section("Assessment follow-up");
    errors.forEach(f => pdf.callout(f.title, `${f.details || "This control could not be evaluated reliably."} Resolve the access or evaluation condition and run a new assessment before treating the control as passed or failed.`, "orange"));
  }

  pdf.newPage();
  pdf.kicker("Workflow");
  pdf.heading("Close the Loop", 20);
  pdf.numberedList([
    "Review the Engineering Remediation Report for exact AWS remediation steps and cautions.",
    "Make the approved AWS changes and verify the target state directly in AWS.",
    "Return to AWS Security Coach and run a new assessment for the connected account.",
    "Confirm remediated controls report PASS and investigate any new or remaining findings.",
  ]);
  pdf.section("Passed controls");
  pdf.bulletList(passed.map(f => f.title));
  if (na.length) {
    pdf.section("Not applicable controls");
    na.forEach(f => pdf.callout(f.title, f.details || "This control was not applicable to the assessed account state.", "blue"));
  }

  pdf.newPage();
  pdf.kicker("Bounded assessment");
  pdf.heading("Scope", 20);
  pdf.metrics([
    { label: "Assessment type", value: "Point-in-time" },
    { label: "Access model", value: "Read-only" },
  ]);
  pdf.labeledParagraph("Region scope", regionScope(report));
  pdf.labeledParagraph("Ruleset version", report.ruleset?.version || "Not available");
  pdf.labeledParagraph("Controls in ruleset", String(report.findings.length));
  pdf.labeledParagraph("Controls evaluated", String(evaluated));
  if (assessment?.scopeStatement) pdf.callout("Assessment scope", assessment.scopeStatement, "blue");
  if (assessment?.frameworkDisclaimer) pdf.callout("Framework scope", assessment.frameworkDisclaimer, "blue");
  pdf.callout("Next step", SELF_SERVICE_REASSESSMENT, "green");
}

function addFindingPdf(pdf: PdfBuilder, finding: Finding, index: number, total: number): void {
  const guidance = finding.guidance;
  const runbook = guidance?.engineeringRemediation;
  if (!guidance || !runbook) return;

  pdf.newPage();
  findingPageHeader(pdf, `Engineering Finding ${index + 1} of ${total}`, finding);
  pdf.callout("What AWS Security Coach observed", finding.details || "No additional observation detail was returned.", "blue");
  if (finding.resource) pdf.callout("Affected resource", finding.resource, "blue");
  pdf.callout("Why this matters", guidance.customerRisk, "orange");
  pdf.section("Target state", runbook.objective);
  pdf.section("Where to go in AWS", runbook.consolePath);
  pdf.section("Before you start");
  pdf.bulletList(runbook.prerequisites);
  pdf.section("Step-by-step remediation");
  pdf.numberedList(runbook.steps);
  if (runbook.cliCommands.length) {
    pdf.section("Advanced / Optional CLI", ADVANCED_CLI_NOTE);
    runbook.cliCommands.forEach(command => pdf.codeBlock(command.label, command.command));
  }
  pdf.callout("Important considerations", runbook.cautions.map(item => `- ${item}`).join("\n\n"), "orange");
  pdf.ensureSpace(120);
  pdf.section("Verify in AWS");
  pdf.numberedList(runbook.verificationSteps);
  pdf.callout("Assessment success criteria", guidance.verificationCriteria, "green");
  pdf.callout("Verify with AWS Security Coach", SELF_SERVICE_REASSESSMENT, "green");
  pdf.callout("AWS Security Pillar context", `${guidance.awsSecurityArea} - ${guidance.awsDesignPrinciple}. ${guidance.awsBestPracticeContext}`, "blue");
  pdf.kicker("Official AWS guidance");
  pdf.linkText(guidance.awsReference.title, guidance.awsReference.url, MARGIN_X, { font: "bold", size: 9.5, color: ACCENT_BLUE, lineHeight: 12.5 });
  pdf.linkText(guidance.awsReference.url, guidance.awsReference.url, MARGIN_X, { size: 8.2, color: ACCENT_BLUE, lineHeight: 10.5 });
}

function addEngineeringPdf(pdf: PdfBuilder, report: Report): void {
  const assessment = report.assessment;
  const confirmed = sortFindings(report.findings.filter(f => f.status === "FAIL" || f.status === "WARN"));
  const errors = sortFindings(report.findings.filter(f => f.status === "ERROR"));
  const na = report.findings.filter(f => f.status === "NOT_APPLICABLE");
  const passed = report.findings.filter(f => f.status === "PASS");
  const evaluated = report.findings.length - na.length;

  coverPage(pdf, report, "Engineering Remediation Report", "Self-service AWS-native remediation and verification guide for confirmed findings in this point-in-time assessment.");
  hero(pdf, report, "Engineering Remediation Report", "Operational runbooks for confirmed findings, with AWS-side verification and a self-service reassessment step.");
  pdf.metrics([
    { label: "Controls evaluated", value: String(evaluated) },
    { label: "Confirmed findings", value: String(confirmed.length), tone: confirmed.length ? "attention" : "clean" },
    { label: "Passed", value: String(passed.length), tone: "clean" },
    ...(errors.length ? [{ label: "Evaluation issues", value: String(errors.length), tone: "attention" as const }] : []),
    ...(na.length ? [{ label: "Not applicable", value: String(na.length), tone: "neutral" as const }] : []),
  ]);
  pdf.callout("Use this report as the remediation workspace", "Work confirmed findings from highest severity downward. Evaluation issues are separated because they are not confirmed AWS misconfigurations. After each approved change, verify the target state in AWS and then run a new AWS Security Coach assessment.", "blue");

  confirmed.forEach((finding, index) => addFindingPdf(pdf, finding, index, confirmed.length));

  errors.forEach((finding, index) => {
    pdf.newPage();
    findingPageHeader(pdf, `Assessment Follow-up ${index + 1} of ${errors.length}`, finding);
    pdf.callout("Evaluation issue - not a confirmed misconfiguration", finding.details || "This control could not be evaluated reliably.", "orange");
    pdf.callout("Required next step", "Resolve the assessment access or evaluation condition first, then run a new AWS Security Coach assessment. Do not make an AWS configuration change based solely on this result.", "blue");
  });

  pdf.newPage();
  pdf.kicker("Appendix");
  pdf.heading("Assessment Evidence & Methodology", 20);
  if (na.length) {
    pdf.section("Not applicable controls");
    na.forEach(f => pdf.callout(f.title, f.details || "Not applicable to the assessed account state.", "blue"));
  }
  pdf.section("Passed controls");
  pdf.bulletList(passed.map(f => `${f.title}${f.details ? ` - ${f.details}` : ""}`));
  pdf.section("Methodology");
  pdf.metrics([
    { label: "Assessment type", value: "Point-in-time" },
    { label: "Access model", value: "Read-only" },
  ]);
  pdf.labeledParagraph("Region scope", regionScope(report));
  pdf.labeledParagraph("Ruleset version", report.ruleset?.version || "Not available");
  pdf.labeledParagraph("Control coverage", `${report.findings.length} controls in the ruleset; ${evaluated} evaluated; ${na.length} not applicable.`);
  if (assessment?.scopeStatement) pdf.callout("Assessment scope", assessment.scopeStatement, "blue");
  if (assessment?.frameworkDisclaimer) pdf.callout("Framework scope", assessment.frameworkDisclaimer, "blue");
  pdf.callout("Self-service reassessment", SELF_SERVICE_REASSESSMENT, "green");
}

export function subscriberPdfFilename(report: Report, documentType: SubscriberPdfDocumentType): string {
  const label = documentType === "management" ? "Management-Report" : "Engineering-Report";
  return `AWS-Security-Coach_${assessmentId(report)}_${label}_${dateStamp(report.generatedAt)}.pdf`;
}

export function buildSubscriberPdf(report: Report, documentType: SubscriberPdfDocumentType): Uint8Array {
  if (!report.assessment) throw new Error("Report metadata is not available for this scan.");
  const title = `${report.assessment.title} - ${documentType === "management" ? "Management Report" : "Engineering Remediation Report"}`;
  const pdf = new PdfBuilder(title, `AWS Security Coach - ${assessmentId(report)}`);
  if (documentType === "management") addManagementPdf(pdf, report);
  else addEngineeringPdf(pdf, report);
  return pdf.bytes();
}

export function downloadSubscriberPdf(report: Report, documentType: SubscriberPdfDocumentType): void {
  const bytes = buildSubscriberPdf(report, documentType);
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  const blob = new Blob([buffer], { type: "application/pdf" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = subscriberPdfFilename(report, documentType);
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
