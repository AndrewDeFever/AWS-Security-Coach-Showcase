import "./app.css";

export type LegalPageName = "terms" | "privacy" | "security";

const CONTACT_EMAIL = "security@example.invalid";
const LAST_UPDATED = "August 19, 2026";

export function legalPageFromHash(hash: string): LegalPageName | null {
  const normalized = hash.toLowerCase().replace(/^#\/?/, "").replace(/\/$/, "");
  if (normalized === "terms" || normalized === "privacy" || normalized === "security") return normalized;
  return null;
}

function LegalHeader({ title, eyebrow }: { title: string; eyebrow: string }) {
  return <header className="legal-header">
    <a className="legal-back" href="#">← AWS Security Coach</a>
    <div className="topbar-kicker">{eyebrow}</div>
    <h1 className="legal-title">{title}</h1>
    <p className="legal-updated">Last updated: {LAST_UPDATED}</p>
  </header>;
}

function TermsPage() {
  return <>
    <LegalHeader eyebrow="Example Operator" title="Terms of Service" />
    <section className="legal-card">
      <p>AWS Security Coach is a service operated by <strong>Example Operator</strong>. These Terms govern your access to and use of AWS Security Coach.</p>
      <h2>1. Using the service</h2>
      <p>By accessing or using AWS Security Coach, you agree to these Terms. You must use the service only for AWS accounts and resources that you own or are authorized to assess. You are responsible for maintaining the security of your account and for activity performed through it.</p>
      <h2>2. AWS access and customer responsibilities</h2>
      <p>AWS Security Coach uses a customer-deployed, read-only cross-account connector to perform supported posture checks. You control whether that connector remains installed in your AWS account and may remove AWS Security Coach access by deleting the connector CloudFormation stack.</p>
      <p>You are responsible for reviewing the CloudFormation template, permissions, assessment results, and any remediation decision before making changes to your AWS environment. AWS Security Coach does not make remediation changes to your AWS account through the read-only connector.</p>
      <h2>3. Assessment limitations</h2>
      <p>AWS Security Coach evaluates a bounded set of security checks at a point in time. Results are informational and are not a certification, penetration test, guarantee of security, guarantee of compliance, or substitute for a complete professional security review. A successful scan does not mean an AWS account is secure or free of vulnerabilities.</p>
      <h2>4. Acceptable use</h2>
      <p>You may not use the service to access systems without authorization, interfere with the service, attempt to bypass access controls, introduce malicious code, abuse service resources, or use the service in violation of applicable law.</p>
      <h2>5. Service changes and availability</h2>
      <p>AWS Security Coach may change, add, remove, suspend, or discontinue features as the service develops. Availability is not guaranteed, and maintenance, cloud-provider issues, security events, or other operational conditions may interrupt access.</p>
      <h2>6. Third-party services</h2>
      <p>The service depends on third-party infrastructure, including Amazon Web Services. Your use of AWS remains subject to your agreements with AWS. Example Operator is not responsible for third-party services, outages, pricing, or changes outside its control.</p>
      <h2>7. Intellectual property</h2>
      <p>AWS Security Coach, its software, branding, documentation, and original content are owned by or licensed to Example Operator except where third-party rights apply. These Terms do not transfer ownership of the service or its intellectual property to you.</p>
      <h2>8. Suspension and termination</h2>
      <p>You may stop using the service at any time. Example Operator may suspend or terminate access when reasonably necessary to protect the service, other users, or third parties; respond to suspected abuse or legal requirements; or enforce these Terms.</p>
      <h2>9. Disclaimer of warranties</h2>
      <p>To the maximum extent permitted by law, AWS Security Coach is provided on an “as is” and “as available” basis without warranties of merchantability, fitness for a particular purpose, non-infringement, uninterrupted operation, or error-free results.</p>
      <h2>10. Limitation of liability</h2>
      <p>To the maximum extent permitted by law, Example Operator and its operator will not be liable for indirect, incidental, special, consequential, exemplary, or punitive damages, or for lost profits, revenue, data, or business opportunities arising from use of the service. Aggregate liability for claims relating to the service will not exceed the amount you paid for the service during the 12 months before the event giving rise to the claim, or $100 if you paid nothing during that period.</p>
      <h2>11. Changes to these Terms</h2>
      <p>These Terms may be updated as AWS Security Coach evolves. The “Last updated” date identifies the current version. Continued use after an update constitutes acceptance of the updated Terms to the extent permitted by law.</p>
      <h2>12. Contact</h2>
      <p>Questions about these Terms may be sent to <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>.</p>
    </section>
  </>;
}

function PrivacyPage() {
  return <>
    <LegalHeader eyebrow="Example Operator" title="Privacy Policy" />
    <section className="legal-card">
      <p>This Privacy Policy explains how AWS Security Coach, a service operated by <strong>Example Operator</strong>, handles information when you use the service.</p>
      <h2>1. Information we collect</h2>
      <p><strong>Account information.</strong> We process information needed to create and operate your account, such as your email address, authentication identifiers, and account ownership records.</p>
      <p><strong>Connector information.</strong> We process connector identifiers, customer-defined display names, AWS account association data, connector status, configuration metadata, and protected values required to establish and verify read-only cross-account access.</p>
      <p><strong>Assessment information.</strong> We process scan identifiers, scan status, security findings, report data, timestamps, and related operational metadata generated while performing supported checks.</p>
      <p><strong>Operational information.</strong> We may process service logs, request metadata, error information, and security events needed to operate, troubleshoot, protect, and improve the service.</p>
      <h2>2. How we use information</h2>
      <p>We use information to authenticate users, establish authorized AWS connections, perform requested security assessments, generate reports, operate and secure the service, troubleshoot failures, prevent abuse, communicate about the service, and comply with applicable legal obligations.</p>
      <h2>3. AWS credentials and access</h2>
      <p>AWS Security Coach does not ask for or store your AWS console password or long-lived AWS access keys as part of the connector workflow. Cross-account scans use temporary AWS STS sessions through the dedicated read-only connector role. Connector-specific protected configuration is handled separately from public scan results.</p>
      <h2>4. Service providers</h2>
      <p>We use service providers, including Amazon Web Services, to host, authenticate, store, secure, and operate AWS Security Coach. Those providers process information only as necessary to provide their services to us and are subject to their own contractual and legal obligations.</p>
      <h2>5. Sale and advertising</h2>
      <p>We do not sell personal information. AWS Security Coach is not operated as an advertising platform, and we do not use customer assessment data for targeted advertising.</p>
      <h2>6. Retention</h2>
      <p>We retain information for as long as reasonably necessary to provide and secure the service, maintain appropriate business and security records, resolve disputes, enforce agreements, and comply with legal obligations. Retention periods may differ by data type and may change as the service matures.</p>
      <h2>7. Security</h2>
      <p>We use technical and organizational safeguards intended to protect information, including authenticated access, environment separation, least-privilege AWS permissions, encryption-capable AWS services, and bounded read-only connector access. No system can guarantee absolute security.</p>
      <h2>8. Your choices and requests</h2>
      <p>You can remove AWS Security Coach access to an AWS account by deleting its connector CloudFormation stack. You may also contact us to ask questions about your personal information or request access, correction, or deletion where applicable. Some information may need to be retained for security, backup, legal, or operational reasons.</p>
      <h2>9. Children</h2>
      <p>AWS Security Coach is intended for business and professional use and is not directed to children.</p>
      <h2>10. Changes to this policy</h2>
      <p>We may update this Privacy Policy as the service changes. The “Last updated” date identifies the current version.</p>
      <h2>11. Contact</h2>
      <p>Privacy questions and requests may be sent to <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>.</p>
    </section>
  </>;
}

function SecurityPage() {
  return <>
    <LegalHeader eyebrow="AWS Security Coach" title="Security & Data Handling" />
    <section className="legal-card">
      <p>This page summarizes the security boundaries customers should understand before connecting an AWS account. It is intended to complement, not replace, the Terms of Service and Privacy Policy.</p>
      <h2>Read-only by design</h2>
      <p>The AWS Security Coach connector creates a dedicated IAM role with the bounded read-only permissions required by the supported posture checks. The connector is not intended to modify workloads, change IAM configuration, or perform automatic remediation.</p>
      <h2>Temporary cross-account sessions</h2>
      <p>Security Coach accesses a connected AWS account through temporary AWS STS sessions. The connector uses a connector-specific ExternalId as an additional trust control. During setup, the ExternalId is shown to the authenticated customer so it can be supplied to the customer-owned CloudFormation stack.</p>
      <h2>Customer-controlled removal</h2>
      <p>The connector stack lives in the customer AWS account. Deleting that CloudFormation stack removes the connector IAM role and ends the AWS access path controlled by that stack.</p>
      <h2>Protected configuration</h2>
      <p>Connector trust configuration is treated separately from ordinary customer-facing scan results. Public-facing scan views intentionally avoid exposing protected connector configuration such as role ARNs, ExternalIds, or temporary AWS credentials.</p>
      <h2>Authenticated authorization</h2>
      <p>Scan targets are resolved server-side for the signed-in account. A connector must be verified and approved before it becomes available as a scan target. Customer-facing target selection is based on authorized application membership rather than arbitrary AWS account identifiers supplied by the browser.</p>
      <h2>Bounded assessment scope</h2>
      <p>AWS Security Coach currently evaluates a defined set of AWS security checks. Findings reflect the checks that were executed and the AWS state observed at that time. A clean result is not a certification and does not prove that the AWS environment is secure.</p>
      <h2>Data handled by the service</h2>
      <p>The service processes account identity information, connector metadata, scan execution records, findings, reports, and operational logs needed to provide and secure AWS Security Coach. See the <a href="#/privacy">Privacy Policy</a> for additional information.</p>
      <h2>Report a concern</h2>
      <p>If you believe you found a security or privacy issue involving AWS Security Coach, contact <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a> with enough detail for us to investigate. Do not include passwords, AWS secret access keys, temporary credentials, or other unnecessary secrets.</p>
    </section>
  </>;
}

export function LegalPage({ page }: { page: LegalPageName }) {
  return <div className="app legal-page"><main className="legal-shell">
    {page === "terms" ? <TermsPage /> : page === "privacy" ? <PrivacyPage /> : <SecurityPage />}
  </main></div>;
}

export function SiteFooter() {
  return <footer className="site-footer" aria-label="Legal and trust links">
    <div><strong>Example Operator</strong> · AWS Security Coach</div>
    <nav>
      <a href="#/terms">Terms of Service</a>
      <a href="#/privacy">Privacy Policy</a>
      <a href="#/security">Security &amp; Data Handling</a>
      <a href={`mailto:${CONTACT_EMAIL}`}>Contact</a>
    </nav>
  </footer>;
}
