// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"bytes"
	"testing"

	"github.com/bright-interaction/hash/internal/sign"
)

func TestResolveCertificateIssuerKeyAcrossRotation(t *testing.T) {
	ceremonySigner, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	exportSigner, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("signed ceremony payload")
	signature := []byte(ceremonySigner.SignPayload(payload))

	b64, pemBytes, fingerprint, err := resolveCertificateIssuerKey(payload, signature, []string{
		exportSigner.PublicKeyBase64(), ceremonySigner.PublicKeyBase64(), ceremonySigner.PublicKeyBase64(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if b64 != ceremonySigner.PublicKeyBase64() || !bytes.Equal(pemBytes, []byte(ceremonySigner.PublicKeyPEM())) {
		t.Fatal("resolver did not select the historical ceremony key")
	}
	wantFingerprint, err := Ed25519PublicKeyFingerprint([]byte(ceremonySigner.PublicKeyPEM()))
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != wantFingerprint {
		t.Fatalf("fingerprint = %s, want %s", fingerprint, wantFingerprint)
	}

	if _, _, _, err := resolveCertificateIssuerKey(payload, signature, []string{exportSigner.PublicKeyBase64()}); err == nil {
		t.Fatal("resolver accepted a certificate without its historical trusted key")
	}
}
