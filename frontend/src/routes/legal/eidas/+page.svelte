<svelte:head><title>eIDAS · How Hash signatures are legally binding</title></svelte:head>

<p class="page-eyebrow">Legal · eIDAS Regulation 910/2014</p>
<h1>Why Hash signatures are legally binding</h1>
<p class="text-text-muted text-sm mb-6">A short, plain-language explainer for senders, signers, and counsel.</p>

<h2>Three tiers of electronic signature</h2>
<p>
  EU Regulation 910/2014 (commonly "eIDAS") defines three tiers. Hash issues the first two and
  integrates with a Qualified Trust Service Provider for the third when configured.
</p>
<ol>
  <li>
    <strong>Simple Electronic Signature (SES)</strong> ,  any electronic mark indicating signing
    intent. eIDAS Article 25 prohibits courts from denying these legal effect <em>solely</em>
    because they are electronic. Suitable for most B2B contracts: NDAs, service agreements,
    consulting engagements, fee agreements, statements of work.
  </li>
  <li>
    <strong>Advanced Electronic Signature (AES)</strong> ,  uniquely linked to the signer, capable
    of identifying them, created with means under their sole control, and bound to the document
    such that any later change is detectable. Hash emits AES-grade evidence by default
    (audit trail, document hash, ed25519-signed audit certificate).
  </li>
  <li>
    <strong>Qualified Electronic Signature (QES)</strong> ,  an AES that uses a qualified
    certificate from a QTSP listed on the EU Trusted List. QES has the same legal effect as a
    handwritten signature across the EU. Hash integrates with Idura, Signicat, and Scrive
    when QES is required (typically for real-estate, certain employment-law instruments,
    and powers of attorney).
  </li>
</ol>

<h2>What makes a Hash signature defendable</h2>
<p>
  When a signer adopts a signature in Hash, the platform records:
</p>
<ul>
  <li>The signer's email address and name (as supplied by the sender);</li>
  <li>The IP address and user-agent of every view, sign, and decline event;</li>
  <li>An exact timestamp of each event;</li>
  <li>The chosen calligraphy font and the typed name;</li>
  <li>A SHA-256 hash of the rendered signature image, embedded in the audit log;</li>
  <li>A SHA-256 hash of the final PDF, persisted in the database and printed on the audit certificate.</li>
</ul>
<p>
  This evidence package is bundled into a one-page audit certificate, which is then signed using an
  ed25519 keypair held by the Hash server. The public key is published at
  <code>/.well-known/hash-public-key</code> and any party can verify the certificate offline at
  <a href="/verify">/verify</a>.
</p>

<h2>What courts actually look at</h2>
<p>
  In an enforcement dispute, the question is rarely "was this technically a QES" but rather
  "can the parties prove the signing event happened the way they say it did". The audit trail
  Hash produces is engineered to answer that question precisely: who, what, when, from where,
  and bound to what document body.
</p>
<p>
  Courts in Sweden, Germany, France, and the rest of the EU routinely accept SES and AES evidence
  for commercial contracts. Specific contracts that require QES (real-estate transfers,
  prenuptial agreements, certain employment-law instruments, powers of attorney for real estate)
  are the exception, not the rule.
</p>

<h2>Where Hash is and isn't a QTSP</h2>
<p>
  <strong>Hash is not a Qualified Trust Service Provider.</strong> Hash is software, like
  PandaDoc or DocuSign at their SES/AES tiers. We do not hold qualified-certificate-issuance
  authority. When a customer's transaction requires QES, Hash delegates the signing event to
  one of the QTSPs we integrate with (Idura, Signicat, Scrive); the qualified certificate is
  issued by them, not by us.
</p>
<p>
  This is the same operating model PandaDoc, DocuSign, HelloSign, and every other major
  e-signing platform follow. The SES/AES surface is software, not regulated trust services.
</p>

<h2>Sweden-specific notes</h2>
<p>
  Avtalslagen does not require a written form for most commercial contracts. Verbal agreements are
  valid; electronic agreements are <em>a fortiori</em> valid. The proof requirement (bevisbörda)
  is the same as for paper: the party asserting the signature must prove it. Hash' audit trail
  meets that bar for the contract types Swedish SMBs sign every day.
</p>

<h2>Want a deeper dive?</h2>
<p>
  Email <code>tom@brightinteraction.com</code> for the long-form whitepaper, or read the source:
  the audit certificate generator at <code>internal/sign/flow.go</code> and the ed25519 signer
  at <code>internal/sign/cert.go</code> are open source under Apache 2.0.
</p>
