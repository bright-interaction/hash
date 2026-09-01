<svelte:head><title>eIDAS · Hash signature scope</title></svelte:head>

<p class="page-eyebrow">Legal · eIDAS Regulation 910/2014</p>
<h1>Electronic signatures and Hash's current scope</h1>
<p class="text-text-muted text-sm mb-6">A plain-language product-scope note for senders, signers, and counsel; not legal advice.</p>

<div class="draft-banner">
  <strong>Product scope—not a legal suitability opinion.</strong> Transaction-specific form,
  identity, evidence, and retention requirements must be reviewed by qualified counsel before use.
</div>

<h2>Three tiers of electronic signature</h2>
<p>
  EU Regulation 910/2014 (commonly "eIDAS") defines three tiers. This Hash production release
  supports the SES path only. AES and QES are unavailable and cannot be selected; a document
  requiring either higher tier is blocked rather than silently downgraded.
</p>
<ol>
  <li>
    <strong>Simple Electronic Signature (SES)</strong> ,  any electronic mark indicating signing
    intent. eIDAS Article 25 prohibits courts from denying these legal effect <em>solely</em>
    because they are electronic. That rule does not establish that SES satisfies every transaction's
    form, identity, or evidence requirements.
  </li>
  <li>
    <strong>Advanced Electronic Signature (AES)</strong> ,  uniquely linked to the signer, capable
    of identifying them, created with means under their sole control, and bound to the document
    such that any later change is detectable. Hash records useful SES evidence, but does not
    currently claim that its signing ceremony or evidence meets all AES requirements.
  </li>
  <li>
    <strong>Qualified Electronic Signature (QES)</strong> ,  an AES created by a qualified
    electronic-signature creation device (QSCD) and based on a qualified certificate from a QTSP
    listed on the EU Trusted List. QES has the same legal effect as a handwritten signature across
    the EU. Hash does not currently provide or broker a production-capable QES ceremony.
  </li>
</ol>

<h2>Evidence Hash records</h2>
<p>
  When a signer adopts a signature in Hash, the platform records:
</p>
<ul>
  <li>The signer's email address and name (as supplied by the sender);</li>
	<li>The IP address and user-agent recorded for the first document view and attached to subsequent
	  mandatory interactions, including field submission, signature/acknowledgement, decline, change
	  request, and data-subject request;</li>
  <li>An exact timestamp for those recorded events;</li>
  <li>The chosen calligraphy font and the typed name;</li>
  <li>A SHA-256 hash of the rendered signature image, embedded in the audit log;</li>
  <li>A SHA-256 hash of the final PDF, persisted in the database and printed on the audit certificate.</li>
</ul>
<p>
  For a successfully completed ceremony, the applicable evidence is bundled into an audit
  certificate, which is then signed using an ed25519 keypair held by the Hash server. If a co-signer
  later declines and the ceremony does not complete, Hash retains the captured event/signature
  evidence but does not produce a final signed PDF or audit certificate. The public key for completed
  certificates is published at
  <code>/.well-known/hash-public-key</code>. The built-in <a href="/verify">/verify</a> page performs
  server-assisted verification: pasted material and uploaded evidence bundles are transmitted to this
  Hash instance. Independent offline verification requires a separate local Ed25519 tool and a trusted
  copy of the issuer key; Hash does not currently ship an offline browser verifier.
</p>

<h2>Transaction-specific assessment</h2>
<p>
  Hash's audit trail is designed to preserve who acted, when, from which recorded network/client
  context, and against which document digest. A court, regulator, or counterparty determines the
  weight and sufficiency of that evidence; Hash does not guarantee enforceability.
</p>
<p>
  The required signature form and assurance level depend on the transaction and jurisdiction. Do
  not infer from a generic contract category that SES, AES, or QES is sufficient; obtain a
  transaction-specific legal assessment.
</p>

<h2>Hash is not a QTSP</h2>
<p>
  <strong>Hash is not a Qualified Trust Service Provider.</strong> We do not hold
  qualified-certificate-issuance authority. Hash has no production-capable QES integration in
  this release, and a product or plan label must not be treated as a qualified certificate.
</p>
<p>
  If a transaction requires AES or QES, use a separately validated service and legal workflow.
  Do not send it through Hash until the relevant tier is implemented and independently reviewed.
</p>

<h2>Sweden-specific notes</h2>
<p>
  Swedish form and evidence requirements depend on the instrument and circumstances. Hash's audit
  trail is designed to preserve SES evidence, but whether an electronic form is permitted and that
  evidence is sufficient in a specific matter is a legal question rather than a product guarantee.
</p>

<h2>Want a deeper dive?</h2>
<p>
  For a technical review, read the source: the audit certificate generator at
  <code>internal/sign/flow.go</code> and the Ed25519 signer
  at <code>internal/sign/cert.go</code> are source-available under the Hash Sustainable Use License.
</p>
