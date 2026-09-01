// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
)

type billingOrgLoaderStub struct {
	orgs map[uuid.UUID]*generated.Org
}

func (s billingOrgLoaderStub) GetOrg(_ context.Context, id uuid.UUID) (*generated.Org, error) {
	org, ok := s.orgs[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return org, nil
}

func TestBillingCustomerNameComesFromAuthenticatedTenant(t *testing.T) {
	alphaID, betaID := uuid.New(), uuid.New()
	loader := billingOrgLoaderStub{orgs: map[uuid.UUID]*generated.Org{
		alphaID: {ID: alphaID, Name: "Customer Alpha AB"},
		betaID:  {ID: betaID, Name: "Customer Beta Oy"},
	}}
	alpha, err := billingCustomerOrgName(context.Background(), loader, alphaID)
	if err != nil || alpha != "Customer Alpha AB" {
		t.Fatalf("alpha billing identity = %q, %v", alpha, err)
	}
	beta, err := billingCustomerOrgName(context.Background(), loader, betaID)
	if err != nil || beta != "Customer Beta Oy" {
		t.Fatalf("beta billing identity = %q, %v", beta, err)
	}
	if alpha == beta || alpha == "Configured Operator AB" || beta == "Configured Operator AB" {
		t.Fatal("tenant checkout identity fell back to the global instance operator")
	}
}
