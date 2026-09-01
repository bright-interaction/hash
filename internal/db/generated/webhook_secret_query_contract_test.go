// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package generated

import (
	"regexp"
	"strings"
	"testing"
)

func TestWebhookMetadataQueriesDoNotFetchSecretMaterial(t *testing.T) {
	for name, query := range map[string]string{
		"org list":      listWebhookEndpointsByOrg,
		"event fan-out": listActiveWebhookEndpointsForEvent,
	} {
		lower := strings.ToLower(query)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "select *") {
			t.Fatalf("%s query fetches webhook secret material:\n%s", name, query)
		}
	}
}

func TestWebhookCreatePersistsCiphertextAndLiteralBlankPlaintext(t *testing.T) {
	lower := strings.ToLower(createWebhookEndpoint)
	if !strings.Contains(lower, "secret_ciphertext") || !strings.Contains(lower, "secret, secret_ciphertext") {
		t.Fatalf("create query does not persist ciphertext:\n%s", createWebhookEndpoint)
	}
	if !strings.Contains(lower, "values ($1, $2, $3, $4, '', $5, $6)") {
		t.Fatalf("create query does not force plaintext secret blank:\n%s", createWebhookEndpoint)
	}
	returning := strings.ToLower(strings.Split(lower, "returning")[1])
	if strings.Contains(returning, "secret_ciphertext") || regexp.MustCompile(`(^|[\s,])secret([\s,]|$)`).MatchString(returning) {
		t.Fatalf("create query returns secret material:\n%s", createWebhookEndpoint)
	}
}
