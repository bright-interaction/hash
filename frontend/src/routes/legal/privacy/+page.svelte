<svelte:head><title>Privacy Policy · Hash</title></svelte:head>

<p class="page-eyebrow">Legal</p>
<h1>Privacy Policy</h1>
<p class="text-text-muted text-sm mb-2">Last updated: 2026-08-31</p>

<div class="draft-banner">
  <strong>Draft—not approved for customer launch.</strong> This notice must be reviewed by Swedish
  counsel and reconciled with the signed production sub-processor, retention, and data-flow schedules
  before customer data is processed.
</div>

<h2>1. Who we are</h2>
<p>
  Bright Interaction AB ("we", "us", "Hash") is a Swedish company that operates the Hash
  e-signing platform. We are the controller for the personal data we process about you in your
  capacity as a customer or visitor of <code>brightinteraction.com</code>.
</p>
<p>
  When you use Hash to send documents for signature, you (the customer) are the controller of the
  signers' personal data; Bright Interaction is the processor. When executed and incorporated into
  the customer agreement, an approved Data Processing Agreement governs that relationship. The
  linked <a href="/legal/dpa">DPA page</a> is currently only a draft and does not apply automatically.
</p>

<h2>2. What we collect</h2>
<h3>From customers (account holders)</h3>
<ul>
  <li>Identity claims from your OIDC provider: email, name, subject identifier;</li>
  <li>API keys you mint (we store the SHA-256 hash, never the plaintext);</li>
  <li>Document and template content, variables, metadata (names, recipients, status), recipient
    field values, comments, change-request text, and audit events;</li>
  <li>Data-subject request type, status, and any note entered to scope the request;</li>
  <li>Subscription and checkout records: selected plan and interval, status, amount and currency,
    provider customer/payment/mandate/subscription identifiers, invoice metadata, and hosted checkout
    or invoice URLs. Hash does not store card or bank-account credentials;</li>
  <li>Hash application request logs (method, path, status, duration). The application logger does not
    add client IP or user-agent; any ingress/proxy logging must be documented in the approved
    production operations and retention schedule.</li>
</ul>

<h3>Payment-provider data flow</h3>
<p>
  Non-local Hash deployments use the configured production payment provider (Mollie in this release)
  to create and manage subscriptions. At checkout, Hash sends the authenticated user's email, the
  exact tenant organisation name, the organisation UUID, selected plan/interval, amount,
  currency, return URL, and webhook URL. The provider returns customer, payment, mandate, and
  subscription identifiers, payment status, and hosted checkout/invoice links that Hash persists.
  The approved customer notice and sub-processor/controller schedule must state the provider's legal
  role, location, purposes, terms, and its own retention before billing is enabled.
</p>
<h3>From signers (recipients)</h3>
<ul>
  <li>Email and name as supplied by the sender;</li>
  <li>IP and user-agent on mandatory signer interactions, including first view, field submissions,
    acknowledgement or signature, decline, change requests, and data-subject requests. These are
    recorded with the applicable event; completed ceremonies include applicable evidence in their
    audit certificate, while a decline remains an audit event and produces no completion certificate;</li>
  <li>Document field values, comments, proposed change text, optional decline reasons, and
    data-subject-request notes that you submit through the signer page. A decline reason is disclosed
    to the sender and recorded in the audit event;</li>
  <li>The signature image you adopt (typed name + chosen calligraphy font). On completion, the image
    is rendered into the final PDF; its SHA-256 digest is bound into the audit evidence and
    certificate. A captured signature artifact and digest can be retained even if another recipient
    later declines or the ceremony otherwise ends without completion.</li>
  <li>For acknowledgement documents, the acceptance event and its context are recorded, but Hash
    creates no signature image or signature representation. A completed final PDF and a separate
    acknowledgement audit certificate are produced when all required recipients accept;</li>
</ul>

<h2>3. Where we host</h2>
<p>
  The hosted Hash deployment is intended to use infrastructure in the European Economic Area.
  The actual production locations, email provider, enabled AI provider (if any), and other
  sub-processors must match the approved sub-processor schedule before customer data is processed.
  Hash does not use documents to train models. Optional AI features are disabled unless configured;
  when enabled, the selected document content is transmitted to the configured provider to perform
  the requested operation.
</p>

<h2>4. Lawful basis</h2>
<ul>
  <li><strong>Account holders:</strong> the approved customer privacy notice must identify the
    operator's applicable basis; this draft does not impose one universal basis;</li>
  <li><strong>Signers:</strong> this release accepts only an explicit controller confirmation that
    GDPR Article 6(1)(b), contract or requested pre-contractual steps, applies to the document. Hash
    records that confirmation and the controller identity/contact at send time and discloses them
    before the recipient proceeds. A ceremony requiring another basis is blocked; Hash does not
    determine whether Article 6(1)(b) is legally sufficient for a transaction;</li>
  <li><strong>Marketing visitors:</strong> the approved marketing notice and consent configuration
    must identify the applicable basis before launch.</li>
</ul>

<h2>5. Retention</h2>
<ul>
  <li>Only draft documents can currently be deleted through the product. Deletion hides the draft
    immediately, then keeps its database row for a fixed 90-day grace period before the worker
    hard-deletes it; deletion of an independently owned source object is retried until successful.
    A source object shared from a template remains with that template;</li>
  <li>Sent, in-progress, declined, voided, and expired documents cannot currently be deleted through
    the document API and have no general automatic purge. The approved agreement and operating
    schedule must state how those rows are handled, subject to the immutable signature-artifact rule
    below;</li>
  <li>When a document is sent, independently owned source or rendered PDF versions are placed under
    a fixed seven-year immutable retention period. Completed final PDFs and their separate audit
    certificates use the same period, including unsigned final PDFs for acknowledgement ceremonies.
    The controller agreement and approved notice must accurately disclose that implemented period.
    Evidence protected by Object Lock cannot be deleted before it expires;</li>
  <li>Signature artifacts captured before a multi-recipient ceremony later declines, is voided, or
    otherwise ends without completion are also placed under the same fixed seven-year immutable
    retention. No final signed PDF or audit certificate is produced for a declined ceremony;</li>
  <li>Account closure does not currently trigger a general automatic purge. The approved production
    offboarding procedure must cover export and manual deletion of data not subject to immutable or
    other applicable retention;</li>
  <li>Application and infrastructure logs: according to the approved production operations schedule;
    this draft does not promise a period that has not been implemented and attested;</li>
  <li>Webhook delivery records: according to the approved production retention schedule. The current
    application does not automatically enforce a 90-day purge, so no such deletion promise applies
    until a tested purge control is deployed.</li>
  <li>Subscription, checkout, payment, mandate, and invoice records: according to the approved billing
    and accounting retention schedule. Hash does not currently implement a general automatic purge
    for these records, and the payment provider may have independent legal retention duties.</li>
	<li>Signer analytics collection is disabled in this production release. The worker retains a
	  90-day purge for any legacy raw events and document/block aggregates from pre-release testing.</li>
</ul>

<h2>6. Your rights</h2>
<p>
  You can request access, correction, deletion, restriction, portability, or to object to processing.
  Email <code>tom@brightinteraction.com</code> with your request. Requests are handled under the
  applicable GDPR deadline and the approved identity-verification and extension procedure; this
  draft does not replace that procedure with a fixed operational promise.
  You also have the right to lodge a complaint with the Swedish IMY (Integritetsskyddsmyndigheten).
</p>

<h2>7. Sub-processors</h2>
<ul>
  <li><strong>Hetzner Online GmbH</strong> - infrastructure hosting (Falkenstein, DE);</li>
  <li><strong>Cloudflare</strong> - DNS for the intended hosted deployment. Any proxying or DDoS
    processing role must be documented before it is enabled;</li>
  <li><strong>Email delivery provider</strong> - the production provider and processing location must
    be identified in the approved sub-processor schedule;</li>
  <li><strong>Payment provider (Mollie in this release)</strong> - subscription and payment processing.
    The approved schedule must classify its role and document the account identity, data categories,
    locations, transfer basis, terms, and retention before production billing is used;</li>
  <li><strong>Optional AI provider</strong> - only when an organisation enables AI features. The
    hosted operator must identify the provider, purpose, location, and transfer mechanism in the
    approved sub-processor schedule before enabling it;</li>
  <li><strong>No QTSP currently receives document data from Hash.</strong> AES and QES signing
    are unavailable in this production release.</li>
</ul>

<h2>8. Cookies</h2>
<p>
  The Hash app sets one authenticated-session cookie (<code>HttpOnly</code>, <code>Secure</code>,
  <code>SameSite=Strict</code>) containing only an HMAC-signed session reference. During OIDC login it
  also sets three necessary, <code>HttpOnly</code>, <code>Secure</code>, <code>SameSite=Lax</code>
  state, nonce, and PKCE-verifier cookies; each expires after ten minutes and is cleared by the login
  callback. These are security cookies, not tracking cookies. The marketing site
  <code>brightinteraction.com</code> uses our own
  <a href="https://cookieproof.brightinteraction.com">CookieProof</a> consent platform.
</p>

<h2>9. Updates</h2>
<p>
  The executed customer notice must define how material changes are communicated. The "last updated"
  date at the top reflects the most recent source draft change.
</p>

<h2>Contact</h2>
<p>
  Bright Interaction AB, Stockholm, Sweden. Privacy questions: <code>tom@brightinteraction.com</code>.
</p>
