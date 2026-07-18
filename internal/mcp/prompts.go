// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"errors"
	"fmt"
)

// registerPrompts registers BYOAI starter frames the MCP host surfaces in
// its UI. They are short instructions that nudge an agent to use the right
// authoring tools in sequence.
func registerPrompts(s *Server) {
	s.RegisterPrompt(Prompt{
		Name:        "draft_consulting_agreement",
		Description: "Draft a consulting agreement and ready it for signature.",
		Arguments: []PromptArg{
			{Name: "client_name", Description: "Counterparty (the client)", Required: true},
			{Name: "provider_name", Description: "Your org name", Required: true},
			{Name: "monthly_fee", Description: "Monthly fee in EUR", Required: true},
			{Name: "term_months", Description: "Engagement term in months (default 12)"},
			{Name: "governing_law", Description: "Governing law (default Sweden)"},
		},
		Renderer: func(args map[string]string) ([]PromptMessage, error) {
			if args["client_name"] == "" || args["provider_name"] == "" || args["monthly_fee"] == "" {
				return nil, errors.New("client_name, provider_name, monthly_fee required")
			}
			term := args["term_months"]
			if term == "" {
				term = "12"
			}
			law := args["governing_law"]
			if law == "" {
				law = "Sweden"
			}
			body := fmt.Sprintf(`You are drafting a consulting agreement using Hash MCP write tools.

Inputs:
  client_name = %s
  provider_name = %s
  monthly_fee = €%s
  term_months = %s
  governing_law = %s

Process:
  1. Read hash://schema/blocks once so you produce valid block JSON.
  2. Call create_document with source_kind="blocks", a name, and an
     initial blocks_json containing: heading "Consulting Agreement",
     paragraphs covering parties, term, fees, scope, IP, confidentiality,
     termination, and governing law.
  3. Call add_recipient twice (role="signer") for the client and the
     provider.
  4. Call add_signature_field for each signer (recipient_role="client"
     and "provider").
  5. Call list_document_fields to confirm every signer has a signature
     field before you hand off.
  6. Return the document id and a one-line summary of what you placed,
     then tell the human that calling send_document will email the
     signers and start the signing ceremony. Do NOT call send_document
     yourself unless the human explicitly confirms; if they do, call it
     and report the sign URLs. To fix a mistyped signer before sending,
     use update_recipient / delete_recipient (draft-only).

Style: clear, plain English; no boilerplate filler. Reference the
governing-law jurisdiction explicitly.`, args["client_name"], args["provider_name"], args["monthly_fee"], term, law)

			return []PromptMessage{{
				Role: "user",
				Content: struct {
					Type string `json:"type"`
					Text string `json:"text"`
				}{Type: "text", Text: body},
			}}, nil
		},
	})

	s.RegisterPrompt(Prompt{
		Name:        "extract_from_email",
		Description: "Read an email thread describing a deal and draft the contract.",
		Arguments: []PromptArg{
			{Name: "email_thread", Description: "Pasted email text", Required: true},
		},
		Renderer: func(args map[string]string) ([]PromptMessage, error) {
			thread := args["email_thread"]
			if thread == "" {
				return nil, errors.New("email_thread required")
			}
			body := fmt.Sprintf(`You are extracting deal terms from this email thread and producing a Hash draft.

EMAIL_THREAD:
---
%s
---

Steps:
  1. Identify the parties, scope, fee structure, term, governing law,
     and any custom clauses (NDA, IP assignment, exclusivity).
  2. If anything material is missing, list questions for the human under
     "OPEN_QUESTIONS:" but still produce the draft with reasonable
     defaults clearly marked as TODO.
  3. Read hash://schema/blocks to confirm valid block shapes.
  4. Call create_document with source_kind="blocks". Compose blocks for
     parties, recitals, scope, fees, term, IP, confidentiality, signatures.
  5. add_recipient for every party identified (role="signer").
  6. add_signature_field per signer.
  7. Reply with the document id, your OPEN_QUESTIONS list (if any), and
     the inferred parameters (term, fees, governing law).
  8. Do NOT send yet. Tell the human that send_document will email the
     signers, and only call it if they confirm (report the sign URLs on
     success). If a party was extracted with a wrong email, correct it
     with update_recipient before sending; drop a wrong one with
     delete_recipient. Both are draft-only.`, thread)
			return []PromptMessage{{
				Role: "user",
				Content: struct {
					Type string `json:"type"`
					Text string `json:"text"`
				}{Type: "text", Text: body},
			}}, nil
		},
	})

	s.RegisterPrompt(Prompt{
		Name:        "document_brief",
		Description: "Summarise a document's status, signers, and outstanding actions.",
		Arguments: []PromptArg{
			{Name: "document_id", Description: "Document UUID", Required: true},
		},
		Renderer: func(args map[string]string) ([]PromptMessage, error) {
			docID := args["document_id"]
			if docID == "" {
				return nil, errors.New("document_id required")
			}
			body := fmt.Sprintf(`Summarise document %s for an executive reader.

Steps:
  1. get_document with id=%s
  2. list_recipients for that document
  3. get_document_events for that document (most recent 30 are enough)

Then return: status; created/updated timestamps; recipients with their
status (signed/viewed/pending/declined); the most recent five events;
and any clear next action (eg "awaiting signature from {name} since
{since}").`, docID, docID)
			return []PromptMessage{{
				Role: "user",
				Content: struct {
					Type string `json:"type"`
					Text string `json:"text"`
				}{Type: "text", Text: body},
			}}, nil
		},
	})
}
