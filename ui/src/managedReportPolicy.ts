import type { Report } from "./reportAdapter";

export const MANAGED_ASSESSMENT_PROVIDER = "Example Security Provider";
export const MANAGED_ASSESSMENT_CONTACT = "Configure the customer contact method for your deployment before delivering managed assessments.";
export const MANAGED_FOLLOW_UP = "One follow-up point-in-time verification of remediated findings is included at no additional cost.";
export const MANAGED_SEVERITY_EXPLANATION = "Severity uses AWS Security Hub terminology and priority meanings: CRITICAL, HIGH, MEDIUM, LOW, and INFORMATIONAL. AWS Security Coach assigns each finding's severity deterministically from its own ruleset; the label is not imported from Security Hub and is not an AWS-assigned severity for this assessment. CRITICAL requires immediate attention, HIGH is a priority, MEDIUM should be addressed but is not urgent, LOW has lower standalone urgency, and INFORMATIONAL indicates no confirmed security gap. This report may abbreviate INFORMATIONAL as INFO.";

export function prepareManagedReport(report: Report): Report {
  // Preserve assessment scope as assessment scope. Managed service/provider policy is
  // rendered explicitly by the managed report experiences rather than hidden inside
  // the technical scope statement.
  return report;
}
