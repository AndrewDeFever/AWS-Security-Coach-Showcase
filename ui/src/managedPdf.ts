import type { Finding, Report } from "./reportAdapter";
import { CONTENT_WIDTH, MARGIN_X, PdfBuilder, sanitizePdfText, SLATE } from "./simplePdf";
import {
  MANAGED_ASSESSMENT_CONTACT,
  MANAGED_ASSESSMENT_PROVIDER,
  MANAGED_FOLLOW_UP,
  MANAGED_SEVERITY_EXPLANATION,
} from "./managedReportPolicy";

export type ManagedPdfDocumentType = "management" | "engineering";

const SEVERITY_WEIGHT: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
const AREA_ORDER = ["Identity and access management", "Detection", "Infrastructure protection", "Data protection"];
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

function areaSummary(report: Report): Array<[string, { evaluated: number; passed: number; attention: number; notApplicable: number }]> {
  const areas = new Map<string, { evaluated: number; passed: number; attention: number; notApplicable: number }>();
  for (const finding of report.findings) {
    const area = finding.guidance?.awsSecurityArea;
    if (!area) continue;
    const current = areas.get(area) ?? { evaluated: 0, passed: 0, attention: 0, notApplicable: 0 };
    if (finding.status === "NOT_APPLICABLE") current.notApplicable += 1;
    else {
      current.evaluated += 1;
      if (finding.status === "PASS") current.passed += 1;
      else current.attention += 1;
    }
    areas.set(area, current);
  }
  return [...areas.entries()].sort(([left], [right]) => {
    const l = AREA_ORDER.indexOf(left);
    const r = AREA_ORDER.indexOf(right);
    if (l === -1 && r === -1) return left.localeCompare(right);
    if (l === -1) return 1;
    if (r === -1) return -1;
    return l - r;
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

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((left, right) => {
    const severity = (SEVERITY_WEIGHT[right.severity] ?? 0) - (SEVERITY_WEIGHT[left.severity] ?? 0);
    return severity || left.title.localeCompare(right.title);
  });
}

function customerName(report: Report): string { return report.customer?.organization || "Customer"; }
function accountId(report: Report): string { return report.customer?.awsAccountId || "Unknown account"; }
function regionScope(report: Report): string { return report.target?.regionScope.join(", ") || "Not available"; }
function providerContact(): string { return `Assessment provider: ${MANAGED_ASSESSMENT_PROVIDER}. ${MANAGED_ASSESSMENT_CONTACT}`; }

function severityColor(severity: string) {
  if (severity === "CRITICAL") return CRITICAL;
  if (severity === "HIGH") return HIGH;
  if (severity === "MEDIUM") return MEDIUM;
  if (severity === "LOW") return LOW;
  return INFO;
}

function highestSeverity(findings: Finding[]): string | undefined {
  return sortFindings(findings)[0]?.severity;
}

function wrappedLineCount(value: string, maxWidth: number, size: number, widthFactor: number): number {
  const words = sanitizePdfText(value).trim().split(/\s+/).filter(Boolean);
  if (!words.length) return 1;
  let lines = 1;
  let line = "";
  for (const word of words) {
    const candidate = line ? `${line} ${word}` : word;
    if (candidate.length * size * widthFactor <= maxWidth) {
      line = candidate;
      continue;
    }
    lines += 1;
    line = word;
  }
  return lines;
}

function coverPage(pdf: PdfBuilder, report: Report, documentLabel: string, subtitle: string): void {
  pdf.rect(0, 0, 612, 792, NAVY);
  pdf.rect(0, 0, 10, 792, ACCENT_BLUE);
  pdf.spacer(116);
  pdf.text("AWS SECURITY POSTURE REVIEW", MARGIN_X, { font: "bold", size: 9, color: MUTED_LIGHT, lineHeight: 12, maxWidth: CONTENT_WIDTH });
  pdf.spacer(12);
  pdf.text(documentLabel, MARGIN_X, { font: "bold", size: 28, color: WHITE, lineHeight: 34, maxWidth: CONTENT_WIDTH });
  pdf.spacer(10);
  pdf.text(subtitle, MARGIN_X, { size: 11.5, color: LIGHT_TEXT, lineHeight: 16, maxWidth: CONTENT_WIDTH - 36 });
  pdf.spacer(72);
  pdf.text("PREPARED FOR", MARGIN_X, { font: "bold", size: 7.5, color: MUTED_LIGHT, lineHeight: 10, maxWidth: CONTENT_WIDTH });
  pdf.spacer(5);
  pdf.text(customerName(report), MARGIN_X, { font: "bold", size: 18, color: WHITE, lineHeight: 23, maxWidth: CONTENT_WIDTH });
  pdf.spacer(28);
  pdf.text(`AWS Account: ${accountId(report)}`, MARGIN_X, { size: 10, color: LIGHT_TEXT, lineHeight: 14, maxWidth: CONTENT_WIDTH });
  pdf.text(`Assessment: ${assessmentId(report)}`, MARGIN_X, { size: 10, color: LIGHT_TEXT, lineHeight: 14, maxWidth: CONTENT_WIDTH });
  pdf.text(`Prepared: ${formattedDate(report.generatedAt)}`, MARGIN_X, { size: 10, color: LIGHT_TEXT, lineHeight: 14, maxWidth: CONTENT_WIDTH });
  pdf.spacer(82);
  pdf.text(MANAGED_ASSESSMENT_PROVIDER, MARGIN_X, { font: "bold", size: 10.5, color: WHITE, lineHeight: 14, maxWidth: CONTENT_WIDTH });
  pdf.text("Point-in-time, read-only AWS security posture assessment", MARGIN_X, { size: 9.5, color: MUTED_LIGHT, lineHeight: 13, maxWidth: CONTENT_WIDTH });
  pdf.newPage();
}

function hero(pdf: PdfBuilder, report: Report, documentLabel: string, subtitle: string): void {
  const top = 50;
  const innerX = MARGIN_X + 24;
  const innerWidth = CONTENT_WIDTH - 48;
  const title = report.assessment?.title || "AWS Security Posture Review";
  const customer = customerName(report);
  const items = [
    ["AWS Account", accountId(report)],
    ["Assessment", assessmentId(report)],
    ["Prepared", formattedDate(report.generatedAt)],
  ] as const;
  const gap = 18;
  const colWidth = (innerWidth - gap * 2) / 3;
  const documentLabelLines = wrappedLineCount(documentLabel.toUpperCase(), innerWidth, 8, 0.54);
  const titleLines = wrappedLineCount(title, innerWidth, 25, 0.54);
  const subtitleLines = wrappedLineCount(subtitle, innerWidth, 10.6, 0.5);
  const customerLines = wrappedLineCount(customer, innerWidth, 14.5, 0.54);
  const metaHeights = items.map(([label, value]) => (
    wrappedLineCount(label.toUpperCase(), colWidth, 7, 0.54) * 9
    + wrappedLineCount(value, colWidth, 10.5, 0.54) * 13
    + 10
  ));
  const metaHeight = Math.max(...metaHeights);
  const height = 18
    + documentLabelLines * 11
    + 6
    + titleLines * 29
    + 5
    + subtitleLines * 14.5
    + 12
    + 9
    + customerLines * 18
    + 14
    + metaHeight
    + 18;

  pdf.rect(MARGIN_X, top, CONTENT_WIDTH, height, NAVY);
  pdf.rect(MARGIN_X, top, 6, height, ACCENT_BLUE);
  pdf.spacer(18);
  pdf.text(documentLabel.toUpperCase(), innerX, { font: "bold", size: 8, color: MUTED_LIGHT, lineHeight: 11, maxWidth: innerWidth });
  pdf.spacer(6);
  pdf.text(title, innerX, { font: "bold", size: 25, color: WHITE, lineHeight: 29, maxWidth: innerWidth });
  pdf.spacer(5);
  pdf.text(subtitle, innerX, { size: 10.6, color: LIGHT_TEXT, lineHeight: 14.5, maxWidth: innerWidth });
  pdf.spacer(12);
  pdf.text("PREPARED FOR", innerX, { font: "bold", size: 6.8, color: MUTED_LIGHT, lineHeight: 9, maxWidth: innerWidth });
  pdf.text(customer, innerX, { font: "bold", size: 14.5, color: WHITE, lineHeight: 18, maxWidth: innerWidth });
  pdf.spacer(14);
  const h1 = pdf.labelValue(items[0][0], items[0][1], innerX, colWidth);
  const h2 = pdf.labelValue(items[1][0], items[1][1], innerX + colWidth + gap, colWidth);
  const h3 = pdf.labelValue(items[2][0], items[2][1], innerX + (colWidth + gap) * 2, colWidth);
  pdf.advance(Math.max(h1, h2, h3));
  pdf.spacer(18);
  pdf.rule();
  pdf.spacer(4);
}

function executiveTakeaway(passed: number, evaluated: number, confirmed: Finding[], errors: Finding[], naCount: number): string {
  const parts = [`${passed} of ${evaluated} evaluated controls passed at the time of review.`];
  if (confirmed.length) {
    const severity = highestSeverity(confirmed);
    parts.push(`${confirmed.length} confirmed ${confirmed.length === 1 ? "finding requires" : "findings require"} remediation${severity ? `; the highest confirmed severity is ${severity}` : ""}.`);
  } else parts.push("No confirmed remediation findings were identified within the assessed scope.");
  if (errors.length) parts.push(`${errors.length} ${errors.length === 1 ? "control requires" : "controls require"} assessment follow-up before a conclusion can be relied upon.`);
  if (naCount) parts.push(`${naCount} ${naCount === 1 ? "control was" : "controls were"} not applicable and excluded from the pass calculation.`);
  return parts.join(" ");
}

function findingMeta(finding: Finding): string {
  const area = finding.guidance?.awsSecurityArea;
  const effort = finding.guidance?.remediationEffort;
  return [area, effort ? `Estimated effort: ${effort.toLowerCase()}` : undefined].filter(Boolean).join(" | ");
}

function findingPageHeader(pdf: PdfBuilder, label: string, finding: Finding): void {
  const top = 50;
  const contentWidth = CONTENT_WIDTH - 36;
  const titleLines = wrappedLineCount(finding.title, contentWidth, 19, 0.54);
  const meta = findingMeta(finding);
  const metaLines = meta ? wrappedLineCount(meta, contentWidth, 9, 0.5) : 0;
  const bottomPadding = 15;
  const blockGap = 6;
  const height = 13 + 10 + 4 + 11 + 3 + titleLines * 23 + (meta ? 3 + metaLines * 12 : 0) + bottomPadding;
  const tone = severityColor(finding.severity);
  pdf.rect(MARGIN_X, top, CONTENT_WIDTH, height, SOFT_BLUE, BORDER);
  pdf.rect(MARGIN_X, top, 6, height, tone);
  pdf.spacer(13);
  pdf.text(label.toUpperCase(), MARGIN_X + 18, { font: "bold", size: 7.5, color: SLATE, lineHeight: 10, maxWidth: contentWidth });
  pdf.spacer(4);
  pdf.text(finding.severity, MARGIN_X + 18, { font: "bold", size: 8.3, color: tone, lineHeight: 11, maxWidth: contentWidth });
  pdf.spacer(3);
  pdf.text(finding.title, MARGIN_X + 18, { font: "bold", size: 19, color: NAVY, lineHeight: 23, maxWidth: contentWidth });
  if (meta) {
    pdf.spacer(3);
    pdf.text(meta, MARGIN_X + 18, { size: 9, color: SLATE, lineHeight: 12, maxWidth: contentWidth });
  }
  pdf.spacer(bottomPadding + blockGap);
}

function addManagementAction(pdf: PdfBuilder, finding: Finding, index: number, total: number): void {
  const guidance = finding.guidance;
  pdf.newPage();
  findingPageHeader(pdf, `Management Action ${index + 1} of ${total}`, finding);
  pdf.callout("What we found", finding.details || "No additional observation detail was returned.", "blue");
  if (guidance?.customerRisk) pdf.callout("Why it matters", guidance.customerRisk, "orange");
  if (guidance?.remediation) pdf.callout("Recommended next step", guidance.remediation, "blue");
  if (guidance?.verificationCriteria) pdf.callout("Success looks like", guidance.verificationCriteria, "green");
  if (guidance?.awsReference) pdf.reference(guidance.awsReference.title, guidance.awsReference.url);
}

function addManagementPdf(pdf: PdfBuilder, report: Report): void {
  const assessment = report.assessment;
  const passed = report.findings.filter(f => f.status === "PASS");
  const na = report.findings.filter(f => f.status === "NOT_APPLICABLE");
  const confirmed = sortFindings(report.findings.filter(f => f.status === "FAIL" || f.status === "WARN"));
  const errors = sortFindings(report.findings.filter(f => f.status === "ERROR"));
  const evaluated = report.findings.length - na.length;

  coverPage(pdf, report, "Management Summary", "Executive view of selected foundational AWS security controls, confirmed findings, and recommended next steps.");
  hero(pdf, report, "Management Summary", "Executive view of selected foundational AWS security controls, confirmed findings, and recommended next steps.");
  pdf.metrics([
    { label: "Controls evaluated", value: String(evaluated) },
    { label: "Passed", value: String(passed.length), tone: "clean" },
    { label: "Confirmed findings", value: String(confirmed.length), tone: confirmed.length ? "attention" : "clean" },
    ...(errors.length ? [{ label: "Evaluation issues", value: String(errors.length), tone: "attention" as const }] : []),
    ...(na.length ? [{ label: "Not applicable", value: String(na.length), tone: "neutral" as const }] : []),
  ]);
  pdf.callout("Executive takeaway", executiveTakeaway(passed.length, evaluated, confirmed, errors, na.length), confirmed.length || errors.length ? "orange" : "green");

  pdf.kicker("Priority overview");
  pdf.heading("Confirmed Findings", 17);
  if (confirmed.length) {
    confirmed.forEach((finding, index) => {
      pdf.ensureSpace(58);
      pdf.callout(`${index + 1}. ${finding.severity} - ${finding.title}`, findingMeta(finding) || "Confirmed remediation finding.", "blue");
    });
  } else pdf.callout("No confirmed remediation required", "No confirmed remediation findings were identified within the successfully evaluated controls.", "green");
  if (errors.length) pdf.callout("Assessment follow-up", `${errors.length} ${errors.length === 1 ? "control could" : "controls could"} not be evaluated reliably. Treat these as follow-up items rather than confirmed misconfigurations.`, "orange");

  confirmed.forEach((finding, index) => addManagementAction(pdf, finding, index, confirmed.length));

  if (errors.length) {
    pdf.newPage();
    pdf.kicker("Assessment follow-up");
    pdf.heading("Controls Not Fully Evaluated", 20);
    pdf.text("These items require assessment follow-up. They are not confirmed AWS misconfigurations.", MARGIN_X, { size: 11, color: SLATE, lineHeight: 15 });
    pdf.spacer(12);
    errors.forEach(finding => pdf.callout(finding.title, `${finding.details || "The control could not be evaluated reliably."} Do not make an AWS configuration change based solely on this result.`, "orange"));
  }

  pdf.newPage();
  pdf.kicker("Assessment context");
  pdf.heading("What the Review Confirmed", 20);
  pdf.callout("Evidence matters", "The assessment documents both remediation priorities and controls already confirmed in the desired state. Passed controls remain part of the customer deliverable rather than disappearing from view.", "blue");
  pdf.section("Security Pillar areas");
  for (const [area, counts] of areaSummary(report)) {
    const state = counts.attention
      ? `${counts.passed} of ${counts.evaluated} evaluated checks passed; ${counts.attention} ${counts.attention === 1 ? "item needs" : "items need"} attention${counts.notApplicable ? `; ${counts.notApplicable} not applicable` : ""}.`
      : `${counts.passed} of ${counts.evaluated} evaluated checks passed; ${counts.evaluated ? "all applicable checks passed" : "no applicable checks"}${counts.notApplicable ? `; ${counts.notApplicable} not applicable` : ""}.`;
    pdf.labeledParagraph(area, state);
  }
  pdf.section("Controls confirmed in good state");
  pdf.bulletList(passed.map(f => f.title));
  if (na.length) {
    pdf.section("Controls not applicable");
    na.forEach(f => pdf.callout(f.title, f.details || "This control was not applicable to the assessed account state.", "blue"));
  }

  pdf.newPage();
  pdf.kicker("Bounded assessment");
  pdf.heading("Scope & Next Step", 20);
  pdf.metrics([
    { label: "Assessment type", value: "Point-in-time" },
    { label: "Access model", value: "Read-only" },
  ]);
  const scopeSummary = [
    assessment?.scopeStatement,
    "Account-global controls were evaluated at the account level. The SSH/RDP security-group control covered all AWS Regions enabled for the account at assessment time.",
    assessment?.frameworkDisclaimer,
  ].filter(Boolean).join(" ");
  pdf.callout("Assessment scope", scopeSummary, "blue");
  pdf.callout("Access model", report.target?.type === "connector" ? "The review used temporary read-only access through a customer-deployed AWS role and did not modify AWS resources." : "The review used read-only AWS permissions and did not modify AWS resources.", "blue");
  pdf.callout("Assessment provider & contact", providerContact(), "blue");
  pdf.callout("Included follow-up verification", MANAGED_FOLLOW_UP, "green");
  const disposition = confirmed.length
    ? `Complete the confirmed remediation actions, validate the AWS-side success criteria, then contact ${MANAGED_ASSESSMENT_PROVIDER} for the included point-in-time verification of the affected controls.`
    : errors.length
      ? `Resolve the assessment follow-up items, then contact ${MANAGED_ASSESSMENT_PROVIDER} for point-in-time verification before relying on the affected controls.`
      : "Retain this report as point-in-time evidence of the assessed controls and repeat the review after material AWS configuration changes.";
  pdf.callout("Recommended disposition", disposition, confirmed.length || errors.length ? "orange" : "green");
}

function addFindingPdf(pdf: PdfBuilder, finding: Finding, index: number, total: number): void {
  const guidance = finding.guidance;
  const runbook = guidance?.engineeringRemediation;
  if (!guidance || !runbook) return;

  pdf.newPage();
  findingPageHeader(pdf, `Engineering Finding ${index + 1} of ${total}`, finding);
  pdf.callout("What we observed", finding.details || "No additional observation detail was returned.", "blue");
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
  pdf.callout(
    "Follow-up verification",
    `After the AWS-side checks are complete, contact ${MANAGED_ASSESSMENT_PROVIDER} through the stated contact channel when remediation is ready for verification. ${MANAGED_FOLLOW_UP}`,
    "green",
  );
  pdf.callout(
    "AWS Security Pillar context",
    `${guidance.awsSecurityArea} - ${guidance.awsDesignPrinciple}. ${guidance.awsBestPracticeContext}`,
    "blue",
  );
  pdf.kicker("Official AWS guidance");
  pdf.linkText(guidance.awsReference.title, guidance.awsReference.url, MARGIN_X, { font: "bold", size: 9.5, color: ACCENT_BLUE, lineHeight: 12.5 });
  pdf.linkText(guidance.awsReference.url, guidance.awsReference.url, MARGIN_X, { size: 8.2, color: ACCENT_BLUE, lineHeight: 10.5 });
  pdf.spacer(5);
}

function addEngineeringPdf(pdf: PdfBuilder, report: Report): void {
  const assessment = report.assessment;
  const confirmed = sortFindings(report.findings.filter(f => f.status === "FAIL" || f.status === "WARN"));
  const errors = sortFindings(report.findings.filter(f => f.status === "ERROR"));
  const na = report.findings.filter(f => f.status === "NOT_APPLICABLE");
  const passed = report.findings.filter(f => f.status === "PASS");
  const evaluated = report.findings.length - na.length;

  coverPage(pdf, report, "Engineering Remediation Report", "Detailed AWS-native remediation and verification guide for the confirmed findings in this point-in-time assessment.");
  hero(pdf, report, "Engineering Remediation Report", "Detailed AWS-native remediation and verification guide for the confirmed findings in this point-in-time assessment.");
  pdf.metrics([
    { label: "Controls evaluated", value: String(evaluated) },
    { label: "Confirmed findings", value: String(confirmed.length), tone: confirmed.length ? "attention" : "clean" },
    { label: "Passed", value: String(passed.length), tone: "clean" },
    ...(errors.length ? [{ label: "Evaluation issues", value: String(errors.length), tone: "attention" as const }] : []),
    ...(na.length ? [{ label: "Not applicable", value: String(na.length), tone: "neutral" as const }] : []),
  ]);
  pdf.callout("How to use this report", "Work confirmed findings from highest severity downward. Each confirmed finding begins on a new page and continues naturally as needed. The AWS Console procedure is the recommended default. Advanced CLI/CloudShell options appear only when they add useful repeatability or capability. Every runbook also includes preparation checks, ordered remediation steps, important considerations, AWS-side verification, assessment success criteria, and official AWS guidance.", "blue");
  if (confirmed.length) {
    pdf.kicker("Execution plan");
    pdf.heading("Remediation Roadmap", 17);
    confirmed.forEach((finding, index) => pdf.callout(`${index + 1}. ${finding.severity} - ${finding.title}`, findingMeta(finding) || "Confirmed remediation finding.", "blue"));
  } else pdf.callout("No confirmed remediation required", "All successfully evaluated controls passed. No remediation runbooks are required for this assessed baseline.", "green");

  confirmed.forEach((finding, index) => addFindingPdf(pdf, finding, index, confirmed.length));

  errors.forEach((finding, index) => {
    pdf.newPage();
    findingPageHeader(pdf, `Assessment Follow-up ${index + 1} of ${errors.length}`, finding);
    pdf.callout("Evaluation issue - not a confirmed misconfiguration", finding.details || "This control could not be evaluated reliably.", "orange");
    pdf.callout("Required next step", "Resolve the assessment access or evaluation condition first, then request follow-up verification. Do not make an AWS configuration change based solely on this result.", "blue");
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
  pdf.callout("Severity model", MANAGED_SEVERITY_EXPLANATION, "blue");
  pdf.callout("Assessment provider & contact", providerContact(), "blue");
  pdf.callout("Included follow-up verification", MANAGED_FOLLOW_UP, "green");
}

export function managedPdfFilename(report: Report, documentType: ManagedPdfDocumentType): string {
  const organization = customerName(report).replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "") || "Customer";
  const account = accountId(report).replace(/[^0-9]/g, "") || "AWS-Account";
  const label = documentType === "management" ? "Management-Report" : "Engineering-Report";
  return `${organization}_${account}_${label}_${dateStamp(report.generatedAt)}.pdf`;
}

export function buildManagedPdf(report: Report, documentType: ManagedPdfDocumentType): Uint8Array {
  if (!report.assessment) throw new Error("Customer report metadata is not available for this scan.");
  if (!report.customer) throw new Error("Customer identity metadata is not available for this managed assessment.");
  const title = `${report.assessment.title} - ${documentType === "management" ? "Management Summary" : "Engineering Remediation Report"}`;
  const pdf = new PdfBuilder(title, `${customerName(report)} - AWS account ${accountId(report)}`);
  if (documentType === "management") addManagementPdf(pdf, report);
  else addEngineeringPdf(pdf, report);
  return pdf.bytes();
}

export function downloadManagedPdf(report: Report, documentType: ManagedPdfDocumentType): void {
  const bytes = buildManagedPdf(report, documentType);
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  const blob = new Blob([buffer], { type: "application/pdf" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = managedPdfFilename(report, documentType);
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}