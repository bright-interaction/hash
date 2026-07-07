<svelte:head><title>Terms of Service · Hash</title></svelte:head>

<p class="page-eyebrow">Legal</p>
<h1>Terms of Service</h1>
<p class="text-text-muted text-sm mb-2">Last updated: 2026-05-10</p>

<div class="draft-banner">
  <strong>Draft for Swedish-counsel review.</strong> This page is a working draft of the Hash Terms of Service.
  Bright Interaction AB intends to have these reviewed by Swedish counsel before paid customers go live.
  In the meantime they reflect the actual operation of the service.
</div>

<h2>1. The service</h2>
<p>
  Hash is a software platform operated by <strong>Bright Interaction AB</strong> (org.no. to be filled, registered in Sweden) that lets organisations
  author, send, and electronically sign documents. The platform is delivered as a hosted service at
  <code>esign.brightinteraction.com</code> and is also available for self-hosted deployment under the
  same Apache 2.0 licence as the underlying source code.
</p>

<h2>2. Your account</h2>
<p>
  To use Hash you must create an account or be invited to one. You are responsible for maintaining the
  confidentiality of your credentials and API keys, and for all activity that occurs under them. Hash
  identifies users via OpenID Connect through the configured identity provider (Zitadel for the hosted
  offering) and via per-user API keys for programmatic + MCP access.
</p>

<h2>3. Your content</h2>
<p>
  You retain all rights to the documents and templates you upload, author, or send through Hash.
  Bright Interaction does not claim any licence over your content beyond what is strictly necessary to
  operate the service: store the document, render it for signers, deliver email notifications, generate
  the audit certificate, and serve copies back to you on request.
</p>
<p>
  We do not use your documents to train AI models. We do not share them with third parties except as
  required to operate the service (for example, the SMTP relay we use to deliver invite emails) and as
  required by law.
</p>

<h2>4. Electronic signatures</h2>
<p>
  Hash produces signatures at the <strong>Simple Electronic Signature (SES)</strong> and
  <strong>Advanced Electronic Signature (AES)</strong> tiers under EU Regulation 910/2014 (eIDAS).
  See <a href="/legal/eidas">our eIDAS page</a> for what that means and where it applies.
</p>
<p>
  Signatures at the <strong>Qualified Electronic Signature (QES)</strong> tier require a Qualified Trust
  Service Provider and are provided through a separately-contracted backend (Idura, Signicat, Scrive)
  when configured. Hash itself is not a QTSP.
</p>
<p>
  By using Hash to send a document for signature, you represent that the underlying transaction is
  one that is permitted under applicable law to be signed electronically, and that the recipients have
  consented to receive electronic communications.
</p>

<h2>5. Acceptable use</h2>
<p>You agree not to use Hash to:</p>
<ul>
  <li>Send documents for signing that you do not have lawful authority to send;</li>
  <li>Send unsolicited bulk email through the platform;</li>
  <li>Reverse-engineer, abuse, or attempt to breach security boundaries of the service;</li>
  <li>Process special categories of personal data (Art. 9 GDPR) without ensuring an appropriate
    lawful basis and notifying us at least 14 days in advance;</li>
  <li>Send documents whose subject matter would violate the laws of Sweden or the European Union.</li>
</ul>

<h2>6. Availability and support</h2>
<p>
  The hosted Hash service runs on Hetzner infrastructure in Falkenstein, Germany. We target 99.5%
  monthly uptime and publish status at <code>status.brightinteraction.com</code>. Scheduled maintenance
  is announced at least 24 hours in advance. Support is available through the contact channels listed
  at <code>brightinteraction.com/contact</code>.
</p>

<h2>7. Fees</h2>
<p>
  The current pricing is published at <code>brightinteraction.com/pricing</code>. Prices are quoted in
  EUR and exclude VAT. Subscriptions auto-renew at the end of each billing period unless cancelled.
  No refunds are issued for partial periods, but you can downgrade or cancel at any time and your
  documents remain accessible through the end of the current period.
</p>

<h2>8. Liability</h2>
<p>
  Bright Interaction provides Hash "as is". To the maximum extent permitted by law, our total
  liability under this agreement is limited to the fees you paid in the twelve months preceding the
  claim. We do not assume the legal risk of the contracts you execute on the platform; that risk
  remains with you and your counterparties.
</p>

<h2>9. Termination</h2>
<p>
  Either party may terminate this agreement on 30 days' notice. We will provide a complete export of
  your documents and audit certificates within 30 days of termination, after which we will delete your
  data subject to the retention requirements in the DPA.
</p>

<h2>10. Governing law</h2>
<p>
  This agreement is governed by the laws of Sweden. Disputes are submitted to the exclusive jurisdiction
  of the Stockholm District Court, except that either party may seek interim relief in the courts where
  it is established.
</p>

<h2>Contact</h2>
<p>
  Bright Interaction AB · Stockholm, Sweden · <code>tom@brightinteraction.com</code>
</p>
