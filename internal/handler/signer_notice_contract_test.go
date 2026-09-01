// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// This contract test keeps every magic-link mutation that is visually behind
// the Article 13 gate from silently losing the server-side precondition when a
// handler is refactored. The DSR endpoint is intentionally excluded: exercising
// data-subject rights is available inside the notice before acknowledgement.
func TestSignerMutationHandlersEnforceCurrentNotice(t *testing.T) {
	files := map[string][]string{
		"sign.go": {
			"handleSignerView", "handleSignerSign", "handleSignerAccept",
			"handleSignerDecline", "handleSignerRequestChanges", "handleSignerCreateComment",
		},
		"fields.go":  {"handleSignerSubmitFields"},
		"ai_apps.go": {"handleSignerClarify"},
	}
	for filename, functions := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, function := range functions {
			decl := findFunction(parsed, function)
			if decl == nil {
				t.Fatalf("%s: missing %s", filename, function)
			}
			if !callsFunction(decl.Body, "requireSignerNoticeAcknowledgement") {
				t.Errorf("%s: %s does not enforce the current Article 13 notice", filename, function)
			}
		}
	}
}

func TestSignerClarifierAuditsBeforeExternalProcessingAndChecksResultAudit(t *testing.T) {
	raw, err := os.ReadFile("ai_apps.go")
	if err != nil {
		t.Fatal(err)
	}
	allSource := string(raw)
	start := strings.Index(allSource, "func (s *Server) handleSignerClarify")
	end := strings.Index(allSource, "func lookupBlockWithNeighbours")
	if start < 0 || end <= start {
		t.Fatal("could not isolate handleSignerClarify source")
	}
	source := allSource[start:end]
	rowLock := strings.Index(source, `GetDocumentForShare(`)
	lockedValidation := strings.Index(source, `sign.ValidateLockedNoticeEvidence(`)
	requestAudit := strings.Index(source, `Kind:        "clarifier.requested"`)
	externalCall := strings.Index(source, `s.Clarifier.Clarify(`)
	answerAudit := strings.Index(source, `Kind:        "clarifier.answered"`)
	lockRelease := strings.Index(source, `lockTx.Commit(`)
	if rowLock < 0 || lockedValidation <= rowLock || requestAudit <= lockedValidation ||
		externalCall <= requestAudit || answerAudit <= externalCall || lockRelease <= answerAudit {
		t.Fatalf("clarifier lock/revalidation/audit/provider order is unsafe: lock=%d validation=%d request=%d provider=%d answer=%d release=%d",
			rowLock, lockedValidation, requestAudit, externalCall, answerAudit, lockRelease)
	}
	if strings.Contains(source, `_, _ = s.Audit.Log`) {
		t.Fatal("clarifier ignores an audit-ledger write failure")
	}
	if strings.Contains(source, `s.Audit.LogTx`) {
		t.Fatal("clarifier request audit is not independently durable before provider processing")
	}
	if !strings.Contains(source, `context.WithTimeout(r.Context(), signerClarifierTimeout)`) {
		t.Fatal("clarifier external processing is not bounded by the request context")
	}
	if !strings.Contains(source, `lockTx.Rollback(rollbackCtx)`) {
		t.Fatal("clarifier does not release its ceremony row lock on every error path")
	}
}

func TestSignerFieldSubmissionRevalidatesNoticeAfterDocumentLock(t *testing.T) {
	raw, err := os.ReadFile("fields.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "func (s *Server) handleSignerSubmitFields")
	end := strings.Index(source, "func recipientCanFillFields")
	if start < 0 || end <= start {
		t.Fatal("could not isolate handleSignerSubmitFields source")
	}
	body := source[start:end]
	rowLock := strings.Index(body, "GetDocumentForUpdate(")
	revalidate := strings.Index(body, "sign.ValidateLockedNoticeEvidence(")
	mutation := strings.Index(body, "q.UpdateFieldValue(")
	if rowLock < 0 || revalidate <= rowLock || mutation <= revalidate {
		t.Fatalf("field lock/revalidation/mutation order is unsafe: lock=%d revalidate=%d mutation=%d", rowLock, revalidate, mutation)
	}
}

func findFunction(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

func callsFunction(node ast.Node, name string) bool {
	found := false
	ast.Inspect(node, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			found = found || fun.Name == name
		case *ast.SelectorExpr:
			found = found || fun.Sel.Name == name
		}
		return !found
	})
	return found
}
