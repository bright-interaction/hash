import { test, expect, type APIRequestContext } from '@playwright/test';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';

// These tests require the live Hash stack and its seeded MCP API key. The
// happy path intentionally drives the browser ceremony rather than calling
// POST /sign directly: it proves the embedded SPA, Article 13 notice, signer
// controls, finalizer, object storage, and stable PDF download route together.

test.describe('signing flow', () => {
  test('browser round-trip: author → send → sign → final PDF', async ({ page, request }) => {
    test.setTimeout(60_000);
    const { documentID, signPath } = await draftAndSend(request, 'browser-sign');

    await page.goto(signPath);
    await acknowledgePrivacyNotice(page);

    await expect(page.getByText('Mutual NDA', { exact: true })).toBeVisible();
    await expect(page.getByPlaceholder('Type your full name')).toHaveValue('Counterparty Co');
    await page.getByRole('button', { name: 'Adopt and sign' }).click();
    await expect(page.getByRole('heading', { name: 'Adopt your signature' })).toBeVisible();
    await page.getByRole('button', { name: 'Sign with this signature' }).click();

    await expect(page.getByRole('heading', { name: 'Signed', exact: true })).toBeVisible({ timeout: 45_000 });
    const finalPDFPath = await completedArtifactPath(page);
    // Completion rotates the mutation-capable ceremony token into a fresh,
    // bounded artifact credential. The old token must not remain usable.
    expect(finalPDFPath).not.toBe(`${signPath}/final-pdf`);

    const pdf = await request.get(finalPDFPath);
    expect(pdf.status()).toBe(200);
    expect(pdf.headers()['content-type']).toContain('application/pdf');
    expect((await pdf.body()).subarray(0, 5).toString()).toBe('%PDF-');
    expect((await request.get(`${signPath}/final-pdf`)).status()).toBe(404);

    const fetched = await tool(request, 'get_document', { id: documentID });
    expect(fetched.status).toBe('completed');
  });

  test('decline UI keeps the ceremony open when the server rejects the request', async ({ page, request }) => {
    const { signPath } = await draftAndSend(request, 'decline-error');
    let declineCalls = 0;
    await page.route(`**${signPath}/decline`, async (route) => {
      declineCalls += 1;
      await route.fulfill({
        status: 409,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'document is no longer accepting responses' })
      });
    });

    await page.goto(signPath);
    await acknowledgePrivacyNotice(page);
    await page.getByRole('button', { name: 'Decline', exact: true }).click();
    await page.getByRole('button', { name: 'Decline document' }).click();

    const declineDialog = page.getByRole('dialog');
    await expect(declineDialog.getByRole('heading', { name: 'Decline this document?' })).toBeVisible();
    await expect(declineDialog.getByText('document is no longer accepting responses')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'You declined this document' })).toHaveCount(0);
    expect(declineCalls).toBe(1);
  });

  test('client-side token navigation isolates a delayed old ceremony response', async ({ page }) => {
    const oldToken = 'old-route-token-regression-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const newToken = 'new-route-token-regression-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const oldPath = `/sign/${oldToken}`;
    const newPath = `/sign/${newToken}`;
    const oldArtifactPath = '/sign/old-artifact-credential-must-not-leak/final-pdf';
    const oldDocumentName = 'Old token regression document';
    const newDocumentName = 'New token regression document';
    const oldRecipientName = 'Old Route Recipient';
    const newRecipientName = 'New Route Recipient';

    let markOldSignRequestSeen!: () => void;
    const oldSignRequestSeen = new Promise<void>((resolve) => (markOldSignRequestSeen = resolve));
    let releaseOldSignResponse!: () => void;
    const oldSignResponseReleased = new Promise<void>((resolve) => (releaseOldSignResponse = resolve));
    let markOldSignResponseDelivered!: () => void;
    const oldSignResponseDelivered = new Promise<void>((resolve) => (markOldSignResponseDelivered = resolve));

    const oldContext = signerContext(oldToken, oldDocumentName, oldRecipientName, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
    const newContext = signerContext(newToken, newDocumentName, newRecipientName, 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
    const oldAcknowledgementKey = signerAcknowledgementKey(oldContext);
    const newAcknowledgementKey = signerAcknowledgementKey(newContext);
    const oldLegacyKey = `hash_signer_a13:${oldToken}`;
    const newLegacyKey = `hash_signer_a13:${newToken}`;
    const contexts = new Map([
      [oldPath, oldContext],
      [newPath, newContext]
    ]);

    // Simulate a browser upgraded from the legacy token-bearing key format.
    // The signer page must delete this credential-bearing key and require a
    // fresh acknowledgement under the opaque document+recipient key.
    await page.addInitScript((legacyKey) => localStorage.setItem(legacyKey, 'without-telemetry'), oldLegacyKey);

    // Everything below the SPA shell is mocked, so this regression neither
    // consumes an organization quota nor depends on shared database fixtures.
    await page.route('**/sign/**', async (route) => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;

      // The initial top-level navigation must reach Hash so it can return the
      // embedded SPA. Subsequent in-app navigation must not create another
      // document request (the marker assertion below proves that).
      if (request.resourceType() === 'document') {
        await route.continue();
        return;
      }

      if (request.method() === 'GET' && contexts.has(pathname)) {
        await route.fulfill({ status: 200, json: contexts.get(pathname) });
        return;
      }
      if (request.method() === 'GET' && pathname.endsWith('/document')) {
        const isOld = pathname.startsWith(oldPath);
        await route.fulfill({
          status: 200,
          contentType: 'text/html; charset=utf-8',
          body: `<p data-block-id="route-proof">${isOld ? 'OLD ROUTE BODY' : 'NEW ROUTE BODY'}</p>`
        });
        return;
      }
      if (request.method() === 'GET' && pathname.endsWith('/fields')) {
        await route.fulfill({ status: 200, json: { fields: [] } });
        return;
      }
      if (request.method() === 'GET' && pathname.endsWith('/comments')) {
        await route.fulfill({ status: 200, json: { comments: [] } });
        return;
      }
      if (request.method() === 'POST' && pathname.endsWith('/view')) {
        await route.fulfill({ status: 200, json: { ok: true, status: 'viewed' } });
        return;
      }
      if (request.method() === 'POST' && pathname === `${oldPath}/sign`) {
        markOldSignRequestSeen();
        await oldSignResponseReleased;
        await route.fulfill({
          status: 200,
          json: { status: 'completed', completed: true, final_pdf_url: oldArtifactPath }
        });
        markOldSignResponseDelivered();
        return;
      }

      await route.fulfill({ status: 404, json: { error: `unexpected mocked signer request: ${request.method()} ${pathname}` } });
    });

    try {
      await page.goto(oldPath);
      await acknowledgePrivacyNotice(page);
      await expect(page.getByText('OLD ROUTE BODY', { exact: true })).toBeVisible();
      await expect(page.getByPlaceholder('Type your full name')).toHaveValue(oldRecipientName);
      expect(await page.evaluate((key) => localStorage.getItem(key), oldLegacyKey)).toBeNull();
      expect(await page.evaluate((key) => localStorage.getItem(key), oldAcknowledgementKey)).toBe('acknowledged');
      expect(await page.evaluate((tokens) => Object.keys(localStorage).filter((key) => tokens.some((token) => key.includes(token))), [oldToken, newToken])).toEqual([]);

      await page.getByRole('button', { name: 'Adopt and sign' }).click();
      await page.getByRole('button', { name: 'Sign with this signature' }).click();
      await oldSignRequestSeen;

      // A synthetic same-origin link still travels through SvelteKit's click
      // router. Keeping this window marker proves the page was not reloaded.
      await page.evaluate((href) => {
        (window as typeof window & { __hashSignerRouteMarker?: string }).__hashSignerRouteMarker = 'preserved';
        const link = document.createElement('a');
        link.href = href;
        link.textContent = 'Navigate to replacement ceremony';
        document.body.append(link);
        link.click();
      }, newPath);
      await expect(page).toHaveURL(new RegExp(`${newPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`));
      expect(
        await page.evaluate(
          () => (window as typeof window & { __hashSignerRouteMarker?: string }).__hashSignerRouteMarker
        )
      ).toBe('preserved');

      const newNotice = page.getByRole('dialog', { name: 'Before you respond: how we handle your data' });
      await expect(newNotice).toBeVisible();
      await expect(newNotice).toContainText(newDocumentName);
      await expect(newNotice).not.toContainText(oldDocumentName);
      expect(await page.evaluate((key) => localStorage.getItem(key), newLegacyKey)).toBeNull();
      expect(await page.evaluate((key) => localStorage.getItem(key), newAcknowledgementKey)).toBeNull();
      await expect(page.getByText('NEW ROUTE BODY', { exact: true })).toBeVisible();
      await expect(page.getByPlaceholder('Type your full name')).toHaveValue(newRecipientName);

      // Deliver the old completion only after the new ceremony and its fresh
      // Article 13 gate are visible. The old async continuation must be inert.
      releaseOldSignResponse();
      await oldSignResponseDelivered;
      await expect(page.getByRole('heading', { name: 'Signed', exact: true })).toHaveCount(0);
      await expect(page.locator(`a[href="${oldArtifactPath}"]`)).toHaveCount(0);
      await expect(page.getByPlaceholder('Type your full name')).toHaveValue(newRecipientName);
      await expect(newNotice).toBeVisible();
    } finally {
      // Avoid leaving the intercepted request pending if an earlier assertion
      // fails; repeated resolve calls are harmless.
      releaseOldSignResponse();
    }
  });

  test('two required roles finalize only after signer and approver both sign', async ({ page, request }) => {
    test.setTimeout(90_000);
    const unique = `two-role-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const doc = await tool(request, 'create_document', {
      name: `Two-role signing proof ${unique}`,
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [
          { id: 'body', type: 'paragraph', text: `TWO ROLE CONTENT ${unique}` },
          { id: 'signer-field', type: 'signature_field', attrs: { recipient_role: 'signer' } },
          { id: 'approver-field', type: 'signature_field', attrs: { recipient_role: 'approver' } }
        ]
      }
    });
    await tool(request, 'add_recipient', {
      document_id: doc.id,
      role: 'signer',
      email: `signer-${unique}@example.com`,
      name: 'First Signer'
    });
    await tool(request, 'add_recipient', {
      document_id: doc.id,
      role: 'approver',
      email: `approver-${unique}@example.com`,
      name: 'Counter Approver'
    });
    const sent = await tool(request, 'send_document', { document_id: doc.id, lawful_basis: 'contract' });
    expect(sent.links).toHaveLength(2);
    const paths = Object.fromEntries(
      sent.links.map((link: { role: string; url: string }) => [link.role, new URL(link.url).pathname])
    ) as Record<string, string>;

    await signInBrowser(page, paths.signer, 'First Signer');
    await expect(page.getByText('The document will finalise once all parties have signed.')).toBeVisible();
    expect((await request.get(`${paths.signer}/final-pdf`)).status()).toBe(404);
    expect((await tool(request, 'get_document', { id: doc.id })).status).toBe('in_progress');

    await signInBrowser(page, paths.approver, 'Counter Approver');
    const approverArtifactPath = await completedArtifactPath(page);
    expect(approverArtifactPath).not.toBe(`${paths.approver}/final-pdf`);
    const approverPDF = await request.get(approverArtifactPath);
    expect(approverPDF.status()).toBe(200);
    expect((await approverPDF.body()).subarray(0, 5).toString()).toBe('%PDF-');
    // Finalization rotates every original mutation credential; recipients get
    // their individual read-only artifact links in the completion response or
    // notification instead of retaining the ceremony links.
    expect((await request.get(`${paths.approver}/final-pdf`)).status()).toBe(404);
    expect((await request.get(`${paths.signer}/final-pdf`)).status()).toBe(404);
    expect((await tool(request, 'get_document', { id: doc.id })).status).toBe('completed');
  });

  test('signer page rejects bogus magic links', async ({ request }) => {
    const res = await request.get('/sign/totally-fake-token-not-in-db');
    expect(res.status()).toBe(404);
  });

  test('signer-side route surface is mounted (404 for valid-format unknown token returns JSON)', async ({ request }) => {
    const res = await request.get('/sign/abcdef0123456789abcdef0123456789abcdef0123456789ABCDEF');
    expect(res.status()).toBe(404);
    const body = await res.json();
    expect(body.error).toContain('invalid');
  });
});

async function signInBrowser(page: import('@playwright/test').Page, signPath: string, typedName: string) {
  await page.goto(signPath);
  await acknowledgePrivacyNotice(page);
  await expect(page.getByPlaceholder('Type your full name')).toHaveValue(typedName);
  await page.getByRole('button', { name: 'Adopt and sign' }).click();
  await page.getByRole('button', { name: 'Sign with this signature' }).click();
  await expect(page.getByRole('heading', { name: 'Signed', exact: true })).toBeVisible({ timeout: 45_000 });
}

async function acknowledgePrivacyNotice(page: import('@playwright/test').Page) {
  const notice = page.getByRole('dialog', { name: 'Before you respond: how we handle your data' });
  // isVisible() is an immediate probe and raced the async signer-context load.
  // Each freshly minted token must render its own Article 13 notice, so wait
  // for that contract explicitly and for the overlay to leave before clicking.
  await expect(notice).toBeVisible();
  await expect(notice).toContainText('fixed 7-year evidence-retention policy');
  await expect(notice).not.toContainText(/statutory|legal obligation|legally[- ]binding/i);
  await notice.getByRole('button', { name: 'I understand, continue' }).click();
  await expect(notice).toBeHidden();
}

async function completedArtifactPath(page: import('@playwright/test').Page) {
  const link = page.getByRole('link', { name: 'Download signed PDF' });
  await expect(link).toHaveAttribute('href', /^\/sign\/[A-Za-z0-9_-]+\/final-pdf$/);
  const href = await link.getAttribute('href');
  if (!href) throw new Error('completed artifact link has no href');
  return href;
}

function signerContext(token: string, documentName: string, recipientName: string, recipientID: string) {
  return {
    document_id: token.startsWith('old-')
      ? '11111111-1111-4111-8111-111111111111'
      : '22222222-2222-4222-8222-222222222222',
    document_name: documentName,
    status: 'sent',
    source_kind: 'blocks',
    requires_signature: true,
    routing_tier: 'SES',
    recipient: {
      id: recipientID,
      email: `${token.startsWith('old-') ? 'old' : 'new'}-route@example.com`,
      name: recipientName,
      role: 'signer',
      status: 'sent',
      locale: 'en'
    },
    fonts: ['Caveat'],
    privacy: {
      controller: `${documentName} controller`,
      controller_contact: 'controller@example.com',
      processor: 'Bright Interaction AB',
      processor_email: 'privacy@example.com',
      purpose_summary: `Administering the response process for ${documentName}. Hash does not determine the document's legal effect.`,
      legal_basis: 'Controller confirmed: GDPR Article 6(1)(b) — processing necessary for a contract or requested pre-contractual steps.',
      retention_years: 7,
      jurisdiction_dp: 'IMY, Sweden',
      policy_url: '/legal/privacy',
      dsr_endpoint: `/sign/${token}/dsr`,
      notice_digest: token.startsWith('old-') ? 'a'.repeat(64) : 'b'.repeat(64),
      copy: noticeCopy(documentName)
    }
  };
}

function signerAcknowledgementKey(context: ReturnType<typeof signerContext>) {
  return `hash_signer_a13:v3:${context.document_id}:${context.recipient.id}:${context.privacy.notice_digest}`;
}

function noticeCopy(documentName: string) {
  return {
    title: 'Before you respond: how we handle your data',
    intro: `You are about to respond to ${documentName}. Under GDPR Article 13 we have to tell you who is processing your data, why, and how to exercise your rights.`,
    controller_label: 'Data controller',
    controller_contact_label: 'Controller contact',
    processor_label: 'Data processor',
    purpose_label: 'Purpose',
    legal_basis_label: 'Legal basis',
    retention_label: 'Retention',
    retention_value: 'Hash applies a fixed 7-year evidence-retention policy.',
    authority_label: 'Supervisory authority',
    rights_summary: 'Your rights under GDPR Art. 15-22',
    rights_body: 'Access, rectification, erasure, restriction, portability, objection.',
    submit_request_label: 'Submit a data-subject request',
    kind_label: 'Kind',
    dsr_access_label: 'Access (Art. 15)',
    dsr_rectification_label: 'Rectification (Art. 16)',
    dsr_erasure_label: 'Erasure (Art. 17)',
    dsr_restriction_label: 'Restriction (Art. 18)',
    dsr_portability_label: 'Portability (Art. 20)',
    dsr_objection_label: 'Objection (Art. 21)',
    note_label: 'Note (optional)',
    note_placeholder: 'Anything that helps us scope the request',
    send_request_label: 'Send request',
    request_received: 'Request received.',
    read_policy_label: 'Read the full privacy policy',
    acknowledgement_label: 'I understand, continue',
    fine_print: 'Acknowledging this notice is required to respond to this document.'
  };
}

async function draftAndSend(request: APIRequestContext, label: string) {
  const unique = `${label}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const doc = await tool(request, 'create_document', {
    name: `E2E Signing NDA ${unique}`,
    source_kind: 'blocks',
    blocks_json: {
      version: 1,
      blocks: [
        { id: 'h1', type: 'heading', attrs: { level: 1 }, text: 'Mutual NDA' },
        { id: 'p1', type: 'paragraph', text: 'Between Bright Interaction and Acme Corp.' },
        {
          id: 'sig1',
          type: 'signature_field',
          attrs: { recipient_role: 'signer', label: 'Counterparty signature' }
        }
      ]
    }
  });
  expect(doc.status).toBe('draft');

  await tool(request, 'add_recipient', {
    document_id: doc.id,
    role: 'signer',
    email: `${unique}@example.com`,
    name: 'Counterparty Co'
  });

  const sent = await tool(request, 'send_document', { document_id: doc.id, lawful_basis: 'contract' });
  expect(sent.status).toBe('sent');
  expect(sent.links).toHaveLength(1);
  const signURL = new URL(sent.links[0].url as string);
  expect(signURL.pathname).toMatch(/^\/sign\/[A-Za-z0-9_-]+$/);

  return { documentID: doc.id as string, signPath: signURL.pathname };
}

async function rpcRaw(request: APIRequestContext, method: string, params: unknown) {
  const res = await request.post('/mcp', {
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      'Content-Type': 'application/json'
    },
    data: { jsonrpc: '2.0', id: 1, method, params }
  });
  if (res.status() !== 200) {
    throw new Error(`MCP HTTP ${res.status()}: ${await res.text()}`);
  }
  return res.json();
}

async function tool(request: APIRequestContext, name: string, args: unknown) {
  const res = await rpcRaw(request, 'tools/call', { name, arguments: args });
  if (res.error) {
    throw new Error(`rpc error: ${JSON.stringify(res.error)}`);
  }
  if (res.result.isError) {
    throw new Error(`tool error: ${res.result.content[0].text}`);
  }
  return JSON.parse(res.result.content[0].text);
}
