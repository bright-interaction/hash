<svelte:head><title>Data Processing Agreement · Hash</title></svelte:head>

<p class="page-eyebrow">Legal · GDPR Article 28</p>
<h1>Data Processing Agreement</h1>
<p class="text-text-muted text-sm mb-2">Draft template · updated 2026-08-31</p>

<div class="draft-banner">
  <strong>Draft—not an executed DPA.</strong> This page does not apply automatically. Customer data
  processing must not begin until an approved DPA is incorporated into the customer agreement and
  its party details, instructions, security schedule, retention rules, and sub-processors are complete.
</div>

<h2>1. Parties and scope</h2>
<p>
  When executed, this Data Processing Agreement ("DPA") is between the Customer (the controller) and
  Bright Interaction AB (the processor) and forms part of the applicable customer agreement for the
  Hash e-signing platform.
</p>

<h2>2. Subject matter and duration</h2>
<p>
  The processor processes the personal data described in section 4 only on behalf of the controller
  and only for the duration of the Customer's subscription, plus the period stated in the executed
  retention schedule. Immutable evidence cannot be deleted before its configured Object Lock period
  expires; this draft does not assert that a particular period is required by Swedish law.
</p>

<h2>3. Nature and purpose of processing</h2>
<p>
  Hosting, storing, and rendering documents the Customer authors or uploads; transmitting signing
  invitations to recipients designated by the Customer; collecting recipient field values,
  comments, change-request text, and data-subject-request notes; capturing and persisting an audit
  trail (IP, user-agent, timestamp, signature image hash) for each signing event; producing a final
  signed PDF and a separately rendered audit certificate; delivering webhook notifications to
  endpoints the Customer configures.
</p>

<h2>4. Categories of data subjects and personal data</h2>
<ul>
  <li><strong>Customer's authorised users:</strong> identity claims from OIDC, server logs;</li>
  <li><strong>Recipients designated by the Customer:</strong> name, email, role, IP address,
    user-agent string, typed-name signature input and image, entered field values, comments, proposed
    change text, and any data-subject-request kind or note they submit;</li>
  <li><strong>Document content:</strong> document/template text, uploaded PDFs, variables, metadata,
    and whatever else the Customer chooses to put in a document.</li>
</ul>
<p>
  A signature artifact captured from one recipient is placed under the fixed seven-year immutable
  evidence retention even if another recipient later declines or the ceremony otherwise ends
  without completion. In that case Hash does not produce a final signed PDF or audit certificate.
</p>
<p>
  The processor does not seek out, intentionally process, or use for any secondary purpose any
  special-category data (Article 9 GDPR) or criminal-conviction data. Customers handling such data
  must notify the processor and request an addendum.
</p>

<h2>5. Sub-processors</h2>
<p>
  The executed DPA and approved schedule must list authorised sub-processors and define change notice,
  objection, and termination rights. This draft does not grant authorisation or promise a notice
  period before those terms are agreed.
</p>

<h2>6. Security</h2>
<p>
  The executed DPA must include deployment-specific technical and organisational measures. Hash's
  application layer provides the following controls:
</p>
<ul>
  <li>API keys stored as SHA-256 hashes; signer magic-link tokens stored as SHA-256 hashes;</li>
  <li>Webhook payloads HMAC-signed; audit certificates ed25519-signed;</li>
  <li>Fail-closed production configuration checks for signing keys, storage retention, and
    credentialed integrations;</li>
  <li>Immutable, version-pinned evidence objects when the configured object store supports and
    enforces the required Object Lock policy.</li>
</ul>
<p>
  TLS termination, database and object-storage encryption, network segregation, access review,
  backup location, retention, restore testing, and disaster recovery are infrastructure controls.
  They must be verified in production and recorded in the signed security schedule; this source-code
  template does not assert that a particular deployment has completed them.
</p>

<h2>7. International transfers</h2>
<p>
  The transfer position depends on the production infrastructure, email delivery, optional AI
  provider, customer-configured webhooks, and support arrangements. Before processing customer data,
  the operator must document each location and sub-processor and put an applicable transfer mechanism
  and assessment in place for any transfer outside the EEA. Self-hosting customers control their own
  deployment and integrations.
</p>

<h2>8. Data subject requests</h2>
<p>
  The processor will assist the Customer in responding to data-subject requests within reasonable
  timeframes. The current admin UI supports request tracking, a recipient-row JSON export, and a
  targeted erasure workflow. It does not provide complete self-service access, rectification,
  restriction, portability, or final-PDF export. The executed DPA and operating procedure must assign
  those unsupported steps and prevent a request from being treated as fulfilled without the required
  manual evidence.
</p>

<h2>9. Breach notification</h2>
<p>
  The executed DPA and incident-response plan must define a processor notification deadline, contact
  path, required information, updates, and escalation that allow the Customer to meet applicable
  legal duties. This source draft does not promise a 24-hour control that has not been operationally
  approved and exercised.
</p>

<h2>10. Audit</h2>
<p>
  Audit rights, frequency, confidentiality safeguards, costs, and available assurance evidence must
  be stated in the executed DPA. This draft does not claim a SOC 2 certification or equivalent audit.
</p>

<h2>11. Return and deletion</h2>
<p>
  The executed DPA must define export and deletion timelines that match the production backup policy
  and any legally required or immutable evidence-retention period. Data held under Object Lock cannot
  be deleted before its retention expires; the customer agreement must describe that limitation.
</p>

<h2>12. Standard Contractual Clauses</h2>
<p>
  If an approved production data flow transfers personal data outside the EEA, the executed DPA must
  include the applicable EU Standard Contractual Clauses and supplementary safeguards before that
  transfer is enabled.
</p>

<h2>Contact</h2>
<p>
  Bright Interaction AB, Stockholm, Sweden. <code>tom@brightinteraction.com</code>.
</p>
