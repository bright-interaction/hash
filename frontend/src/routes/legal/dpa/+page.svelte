<svelte:head><title>Data Processing Agreement · Hash</title></svelte:head>

<p class="page-eyebrow">Legal · GDPR Article 28</p>
<h1>Data Processing Agreement</h1>
<p class="text-text-muted text-sm mb-2">Template version: 1.0 · 2026-05-10</p>

<div class="draft-banner">
  <strong>Template, not a contract.</strong> This DPA template applies automatically to every customer of
  the hosted Hash service unless a custom DPA is signed. Customers handling special-category data
  should request a tailored DPA.
</div>

<h2>1. Parties and scope</h2>
<p>
  This Data Processing Agreement ("DPA") is entered into between the Customer (the controller) and
  Bright Interaction AB (the processor) and forms part of the Terms of Service for the Hash
  e-signing platform.
</p>

<h2>2. Subject matter and duration</h2>
<p>
  The processor processes the personal data described in section 4 only on behalf of the controller
  and only for the duration of the Customer's subscription, plus the retention period defined in the
  Privacy Policy (typically 7 years for signed documents under Swedish commercial-contract law).
</p>

<h2>3. Nature and purpose of processing</h2>
<p>
  Hosting, storing, and rendering documents the Customer authors or uploads; transmitting signing
  invitations to recipients designated by the Customer; capturing and persisting an audit trail
  (IP, user-agent, timestamp, signature image hash) for each signing event; producing a final signed
  PDF and a separately rendered audit certificate; delivering webhook notifications to endpoints
  the Customer configures.
</p>

<h2>4. Categories of data subjects and personal data</h2>
<ul>
  <li><strong>Customer's authorised users:</strong> identity claims from OIDC, server logs;</li>
  <li><strong>Recipients designated by the Customer:</strong> name, email, role, and at sign time
    IP address, user-agent string, typed-name signature input;</li>
  <li><strong>Document content:</strong> whatever the Customer chooses to put in a document.</li>
</ul>
<p>
  The processor does not seek out, intentionally process, or use for any secondary purpose any
  special-category data (Article 9 GDPR) or criminal-conviction data. Customers handling such data
  must notify the processor and request an addendum.
</p>

<h2>5. Sub-processors</h2>
<p>
  The Customer authorises the processor to use the sub-processors listed in the Privacy Policy. The
  processor will give 30 days' notice before adding or replacing a sub-processor; if the Customer
  objects, either party may terminate the affected service.
</p>

<h2>6. Security</h2>
<p>
  The processor implements technical and organisational measures appropriate to the risk, including:
</p>
<ul>
  <li>TLS in transit on all public endpoints (HSTS, modern ciphers);</li>
  <li>Encryption at rest of MinIO buckets (SSE-S3) and Postgres data volumes;</li>
  <li>API keys stored as SHA-256 hashes; signer magic-link tokens stored as SHA-256 hashes;</li>
  <li>Webhook payloads HMAC-signed; audit certificates ed25519-signed;</li>
  <li>Network-level segregation (Tailscale mesh between application services);</li>
  <li>Backup retention of 30 days with restic to a separate Hetzner storage box;</li>
  <li>Access logged and reviewed; principle of least privilege applied across all components.</li>
</ul>

<h2>7. International transfers</h2>
<p>
  No personal data is transferred outside the European Economic Area as part of the operation of
  Hash. Hetzner is a German company, hosting in Germany. Self-hosting customers may configure
  alternate locations entirely under their own control.
</p>

<h2>8. Data subject requests</h2>
<p>
  The processor will assist the Customer in responding to data-subject requests within reasonable
  timeframes. Standard requests (access, correction, erasure) can be self-served via the Customer's
  admin UI; complex requests are forwarded to <code>tom@brightinteraction.com</code>.
</p>

<h2>9. Breach notification</h2>
<p>
  The processor will notify the Customer without undue delay (and no later than 24 hours) after
  becoming aware of a personal-data breach affecting Customer data, with sufficient information for
  the Customer to meet its 72-hour reporting obligation under Article 33 GDPR.
</p>

<h2>10. Audit</h2>
<p>
  On reasonable notice and not more than once per twelve months, the Customer may audit the
  processor's compliance with this DPA. Routine assurance is provided through the SOC-2-equivalent
  practices Bright Interaction publishes annually.
</p>

<h2>11. Return and deletion</h2>
<p>
  On termination, the processor returns all Customer data in machine-readable form within 30 days
  and deletes the data subject to the retention periods in the Privacy Policy. Backups are aged out
  according to the standard rotation; on request the processor can confirm in writing when the
  final copy has been overwritten.
</p>

<h2>12. Standard Contractual Clauses</h2>
<p>
  This DPA does not require SCCs because no transfers leave the EEA. If a future deployment changes
  this position, the parties agree to incorporate the most recent EU SCCs by reference.
</p>

<h2>Contact</h2>
<p>
  Bright Interaction AB, Stockholm, Sweden. <code>tom@brightinteraction.com</code>.
</p>
