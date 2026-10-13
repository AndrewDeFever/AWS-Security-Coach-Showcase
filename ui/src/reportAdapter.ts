import type { ReportDeliveryModel } from "./reportDelivery";

export type AwsReference = {
  title: string;
  url: string;
};

export type EngineeringCliCommand = {
  label: string;
  command: string;
};

export type EngineeringRemediation = {
  objective: string;
  consolePath: string;
  prerequisites: string[];
  steps: string[];
  cliCommands: EngineeringCliCommand[];
  cautions: string[];
  verificationSteps: string[];
};

export type FindingGuidance = {
  awsSecurityArea: string;
  awsDesignPrinciple: string;
  awsBestPracticeContext: string;
  customerRisk: string;
  remediationEffort: string;
  remediation: string;
  verificationCriteria: string;
  awsReference: AwsReference;
  engineeringRemediation?: EngineeringRemediation;
};

export type Finding = {
  id: string;
  title: string;
  status: string;
  severity: string;
  details?: string;
  resource?: string;
  guidance?: FindingGuidance;
};

export type FrameworkContext = {
  framework: string;
  pillar: string;
  referenceUrl: string;
};

export type AssessmentProfile = {
  title: string;
  assessmentType: string;
  accessModel: string;
  scopeStatement: string;
  frameworkDisclaimer: string;
  frameworkContext?: FrameworkContext;
  controlCount: number;
  guidanceVersion: string;
};

export type ReportRuleset = {
  id: string;
  version: string;
  checkCount: number;
};

export type ReportTarget = {
  type: "tool-account" | "connector";
  accountRef: string;
  regionScope: string[];
};

export type ReportCustomer = {
  organization: string;
  awsAccountId: string;
};

export type Report = {
  format: "v1" | "legacy";
  status: string;
  deliveryModel: ReportDeliveryModel;
  scanId?: string;
  generatedAt?: string;
  assessment?: AssessmentProfile;
  ruleset?: ReportRuleset;
  target?: ReportTarget;
  customer?: ReportCustomer;
  findings: Finding[];
};

type JsonRecord = Record<string, unknown>;

const V1_SCHEMA_VERSION = "1.0";
const ALLOWED_STATUSES = new Set(["PASS", "FAIL", "WARN", "ERROR", "NOT_APPLICABLE"]);
const ALLOWED_SEVERITIES = new Set(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);

function record(value: unknown): JsonRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : {};
}

function text(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

function textArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map(text).filter((item): item is string => Boolean(item));
}

function positiveInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : undefined;
}

function normalizedEngineeringRemediation(value: unknown): EngineeringRemediation | undefined {
  const remediation = record(value);
  if (Object.keys(remediation).length === 0) return undefined;

  const cliCommands = Array.isArray(remediation.cliCommands)
    ? remediation.cliCommands.map(commandValue => {
        const command = record(commandValue);
        const label = text(command.label);
        const body = text(command.command);
        return label && body ? { label, command: body } : null;
      }).filter((command): command is EngineeringCliCommand => command !== null)
    : [];

  const normalized: EngineeringRemediation = {
    objective: text(remediation.objective) ?? "",
    consolePath: text(remediation.consolePath) ?? "",
    prerequisites: textArray(remediation.prerequisites),
    steps: textArray(remediation.steps),
    cliCommands,
    cautions: textArray(remediation.cautions),
    verificationSteps: textArray(remediation.verificationSteps),
  };

  return normalized.objective && normalized.consolePath && normalized.prerequisites.length > 0 && normalized.steps.length > 0 && normalized.cautions.length > 0 && normalized.verificationSteps.length > 0 ? normalized : undefined;
}

function normalizedGuidance(value: unknown): FindingGuidance | undefined {
  const guidance = record(value);
  const reference = record(guidance.awsReference);
  const normalized: FindingGuidance = {
    awsSecurityArea: text(guidance.awsSecurityArea) ?? "",
    awsDesignPrinciple: text(guidance.awsDesignPrinciple) ?? "",
    awsBestPracticeContext: text(guidance.awsBestPracticeContext) ?? "",
    customerRisk: text(guidance.customerRisk) ?? "",
    remediationEffort: (text(guidance.remediationEffort) ?? "").toUpperCase(),
    remediation: text(guidance.remediation) ?? "",
    verificationCriteria: text(guidance.verificationCriteria) ?? "",
    awsReference: { title: text(reference.title) ?? "", url: text(reference.url) ?? "" },
    engineeringRemediation: normalizedEngineeringRemediation(guidance.engineeringRemediation),
  };

  const required = [normalized.awsSecurityArea, normalized.awsDesignPrinciple, normalized.awsBestPracticeContext, normalized.customerRisk, normalized.remediationEffort, normalized.remediation, normalized.verificationCriteria, normalized.awsReference.title, normalized.awsReference.url];
  return required.every(Boolean) ? normalized : undefined;
}

function normalizedFinding(item: unknown, index: number): Finding {
  const row = record(item);
  const status = (text(row.status) ?? "UNKNOWN").toUpperCase();
  const severity = (text(row.severity) ?? text(row.level) ?? "UNKNOWN").toUpperCase();
  return {
    id: text(row.id) ?? text(row.findingId) ?? `finding-${index + 1}`,
    title: text(row.title) ?? text(row.name) ?? `Finding ${index + 1}`,
    status,
    severity,
    details: text(row.description) ?? text(row.details),
    resource: text(row.resource),
    guidance: normalizedGuidance(row.guidance),
  };
}

function validateV1Finding(finding: Finding, index: number): void {
  if (!ALLOWED_STATUSES.has(finding.status)) throw new Error(`The report contains an unsupported status at finding ${index + 1}.`);
  if (!ALLOWED_SEVERITIES.has(finding.severity)) throw new Error(`The report contains an unsupported severity at finding ${index + 1}.`);
}

function normalizedAssessment(value: unknown): AssessmentProfile | undefined {
  const assessment = record(value);
  if (Object.keys(assessment).length === 0) return undefined;
  const controlCount = positiveInteger(assessment.controlCount);
  const framework = record(assessment.frameworkContext);
  const frameworkName = text(framework.framework);
  const pillar = text(framework.pillar);
  const referenceUrl = text(framework.referenceUrl);
  const frameworkContext = frameworkName && pillar && referenceUrl ? { framework: frameworkName, pillar, referenceUrl } : undefined;

  const normalized: AssessmentProfile = {
    title: text(assessment.title) ?? "",
    assessmentType: text(assessment.assessmentType) ?? "",
    accessModel: text(assessment.accessModel) ?? "",
    scopeStatement: text(assessment.scopeStatement) ?? "",
    frameworkDisclaimer: text(assessment.frameworkDisclaimer) ?? "",
    frameworkContext,
    controlCount: controlCount ?? 0,
    guidanceVersion: text(assessment.guidanceVersion) ?? "",
  };

  return normalized.title && normalized.assessmentType && normalized.accessModel && normalized.scopeStatement && normalized.frameworkDisclaimer && normalized.controlCount > 0 && normalized.guidanceVersion ? normalized : undefined;
}

function normalizedRuleset(value: unknown): ReportRuleset | undefined {
  const ruleset = record(value);
  const id = text(ruleset.id);
  const version = text(ruleset.version);
  const checkCount = positiveInteger(ruleset.checkCount);
  return id && version && checkCount ? { id, version, checkCount } : undefined;
}

function normalizedTarget(value: unknown): ReportTarget | undefined {
  const target = record(value);
  const type = text(target.type);
  const accountRef = text(target.accountRef);
  const regionScope = Array.isArray(target.regionScope) ? target.regionScope.map(text).filter((item): item is string => Boolean(item)) : [];
  if ((type !== "tool-account" && type !== "connector") || !accountRef || regionScope.length === 0) return undefined;
  return { type, accountRef, regionScope };
}

function normalizedCustomer(value: unknown): ReportCustomer | undefined {
  const customer = record(value);
  if (Object.keys(customer).length === 0) return undefined;
  const organization = text(customer.organization);
  const awsAccountId = text(customer.awsAccountId);
  if (!organization || !awsAccountId || !/^\d{12}$/.test(awsAccountId)) return undefined;
  return { organization, awsAccountId };
}

function normalizeV1(report: JsonRecord): Report {
  const schemaVersion = text(report.schemaVersion);
  if (schemaVersion !== V1_SCHEMA_VERSION) throw new Error("The report uses an unsupported schema version.");
  const scan = record(report.scan);
  const rows = Array.isArray(report.findings) ? report.findings : null;
  if (!rows) throw new Error("The V1 report does not contain a findings array.");

  const findings = rows.map(normalizedFinding);
  findings.forEach(validateV1Finding);
  const deliveryModel: ReportDeliveryModel = text(report.deliveryModel) === "self-service" ? "self-service" : "managed";

  return {
    format: "v1",
    status: (text(scan.status) ?? "UNKNOWN").toUpperCase(),
    deliveryModel,
    scanId: text(scan.scanId),
    generatedAt: text(scan.generatedAt),
    assessment: normalizedAssessment(report.assessment),
    ruleset: normalizedRuleset(report.ruleset),
    target: normalizedTarget(report.target),
    customer: normalizedCustomer(report.customer),
    findings,
  };
}

function normalizeLegacy(root: JsonRecord, report: JsonRecord): Report {
  const rows = Array.isArray(report.findings) ? report.findings : [];
  return {
    format: "legacy",
    status: String(root.status ?? root.scanStatus ?? report.status ?? record(report.summary).status ?? "UNKNOWN").toUpperCase(),
    deliveryModel: "managed",
    generatedAt: text(report.generatedAt),
    findings: rows.map(normalizedFinding),
  };
}

export function normalizeReport(payload: unknown): Report {
  const root = record(payload);
  const report = record(root.report ?? root.payload ?? root);
  if ("schemaVersion" in report) return normalizeV1(report);
  return normalizeLegacy(root, report);
}
