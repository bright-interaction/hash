// Package compliance implements Phase 12 (#8): Compliance-as-a-Service.
//
// 12.1 ships a Seeder that, on org onboarding, drops in a baseline
// compliance kit: a DPA template (Article 28), a Records of Processing
// document (Article 30), a GDPR Article 13 privacy notice, eIDAS
// routing rules appropriate for the business type, and (when a logo
// has been uploaded) extracted brand colours via Phase 8.5. Every
// artifact is a real Hash document/template, which means the
// customer's first send is one click away.
//
// 12.2 ships the EDPB-feed flagger: a nightly worker tick that scans
// the configured feed, parses any new advisories, and emits a
// compliance_flag per affected document so the /compliance dashboard
// can surface "review these contracts before next quarter."
//
// This file defines the per-business-type templates. The actual seed
// orchestration lives in seeder.go.
package compliance

import (
	"fmt"
	"strings"
)

// BusinessType labels the seed packet a new org receives. Strings stay
// stable so old baseline rows keep meaning the same thing.
type BusinessType string

const (
	BTLawFirm    BusinessType = "law_firm"
	BTSaaS       BusinessType = "saas"
	BTConsulting BusinessType = "consulting"
	BTHealthcare BusinessType = "healthcare"
	BTFintech    BusinessType = "fintech"
	BTOther      BusinessType = "other"
)

// Valid reports whether bt is one of the known business types.
func (bt BusinessType) Valid() bool {
	switch bt {
	case BTLawFirm, BTSaaS, BTConsulting, BTHealthcare, BTFintech, BTOther:
		return true
	}
	return false
}

// Templates carries the three baseline document bodies + the rules
// hint for the eIDAS seeder. Bodies are intentionally short, plain-
// language drafts: senders edit them before sending. They are NOT
// legal advice; we annotate that in a banner at the top.
type Templates struct {
	DPATitle             string
	DPABody              string
	RecordsTitle         string
	RecordsBody          string
	PrivacyNoticeTitle   string
	PrivacyNoticeBody    string
	// EIDAS hints: list of extra rule names the seeder should consider
	// installing for this business type. The Phase 9.2 SeedSwedishDefaults
	// always runs first; these augment for healthcare / fintech /
	// law-firm-specific thresholds.
	ExtraEIDASHints []string
}

// TemplatesFor returns the kit for a business type + jurisdiction.
// Jurisdiction shapes the eIDAS hints + the Article-26 transfer-clause
// language; only SE is fully fleshed out today, others fall back to a
// generic EU baseline.
func TemplatesFor(bt BusinessType, jurisdiction string) Templates {
	juris := strings.ToUpper(jurisdiction)
	if juris == "" {
		juris = "SE"
	}
	common := commonBoilerplate(juris)
	switch bt {
	case BTHealthcare:
		t := defaultTemplates(common)
		t.DPABody = healthcareDPA(common)
		t.ExtraEIDASHints = []string{"healthcare-record-keeping-aes"}
		return t
	case BTFintech:
		t := defaultTemplates(common)
		t.DPABody = fintechDPA(common)
		t.ExtraEIDASHints = []string{"fintech-transaction-qes-1m"}
		return t
	case BTLawFirm:
		t := defaultTemplates(common)
		t.DPABody = lawFirmDPA(common)
		t.ExtraEIDASHints = []string{"client-engagement-aes"}
		return t
	case BTSaaS, BTConsulting, BTOther:
		return defaultTemplates(common)
	}
	return defaultTemplates(common)
}

// commonBoilerplate returns the per-jurisdiction header notes used
// across every template body. Keeping these in one place means we
// upgrade Article-26 transfer language once when EDPB tightens it.
func commonBoilerplate(juris string) map[string]string {
	transfer := "International transfers from the EU/EEA rely on the EU Standard Contractual Clauses (2021/914) + supplementary measures as required by Schrems II."
	if juris == "SE" {
		transfer = "Internationella överföringar från EU/EES sker på basis av EU:s standardklausuler (2021/914) och kompletterande åtgärder enligt Schrems II."
	}
	return map[string]string{
		"jurisdiction": juris,
		"transfer":     transfer,
		"banner": fmt.Sprintf(
			"DRAFT KIT v1 (auto-seeded by Hash for jurisdiction=%s). Review with counsel before use. The text below is a starting point, not legal advice.",
			juris,
		),
	}
}

func defaultTemplates(b map[string]string) Templates {
	return Templates{
		DPATitle:           "Data Processing Agreement (DPA)",
		DPABody:            defaultDPA(b),
		RecordsTitle:       "Records of Processing Activities (GDPR Article 30)",
		RecordsBody:        defaultRecords(b),
		PrivacyNoticeTitle: "Privacy Notice (GDPR Article 13)",
		PrivacyNoticeBody:  defaultPrivacyNotice(b),
	}
}

func defaultDPA(b map[string]string) string {
	return fmt.Sprintf(`# Data Processing Agreement

> %s

## 1. Parties + roles
The Controller (your organisation) instructs the Processor (the counterparty) to process personal data described in Annex A.

## 2. Subject matter, duration, nature, purpose
Processing is limited to the purposes documented in the master agreement. Duration matches the master agreement plus the retention windows in Annex B.

## 3. Security measures (Article 32)
The Processor implements appropriate technical + organisational measures: encryption in transit + at rest, access logging, incident response, regular reviews.

## 4. Sub-processors
The Processor maintains a public list of sub-processors and notifies the Controller at least 30 days before adding one.

## 5. International transfers
%s

## 6. Audits
The Controller may audit annually on 30 days' notice; audit reports from independent auditors satisfy this on a yearly cadence.

## 7. Breach notification
The Processor notifies the Controller without undue delay (target: 24h) of any personal-data breach.

## 8. Deletion / return at end of service
Within 30 days of termination, the Processor deletes or returns all personal data and certifies in writing.

## Annex A: Categories of data + data subjects
- (Filled in per engagement.)

## Annex B: Retention windows
- (Filled in per engagement.)
`, b["banner"], b["transfer"])
}

func healthcareDPA(b map[string]string) string {
	return defaultDPA(b) + `

## Annex C: Healthcare-specific addenda
- Special categories of data under Article 9: explicit consent OR Article 9(2)(h) processing for healthcare purposes.
- Patientdatalagen (PDL) applies in Sweden; clinical records retain for a minimum of 10 years.
- Patient access requests must be routed through the data controller's DPO within 30 days.
`
}

func fintechDPA(b map[string]string) string {
	return defaultDPA(b) + `

## Annex C: Fintech / payment-services addenda
- PSD2 + GDPR overlap: payment data is personal data; processing relies on contractual necessity + legitimate interest depending on the flow.
- Anti-money-laundering (AML) records retain for 5 years post-relationship under EU AMLD.
- Transaction data exports to outside EU/EEA require SCC + transfer impact assessment.
`
}

func lawFirmDPA(b map[string]string) string {
	return defaultDPA(b) + `

## Annex C: Law-firm-specific addenda
- Client engagement records retain for 10 years (Advokatsamfundets vägledning, Sweden).
- Privileged communications: the Processor undertakes not to disclose client correspondence to third parties without the Controller's instruction.
- Conflict checks may be performed on contact lists but no further processing.
`
}

func defaultRecords(b map[string]string) string {
	return fmt.Sprintf(`# Records of Processing (Article 30)

> %s

| Processing activity | Lawful basis | Data subjects | Categories | Retention | Recipients |
| --- | --- | --- | --- | --- | --- |
| Customer contracts + invoicing | Contract necessity | Customers | Name, email, billing | 10 years post-end | Auditors, tax authority |
| Sales prospecting (B2B) | Legitimate interest | Business contacts | Name, work email, employer | 24 months from last contact | Hosted CRM (this org's instance) |
| Website analytics | Consent (cookie banner) | Website visitors | IP (truncated), device class | 14 months | Umami self-hosted |
| Recruitment | Consent + legitimate interest | Applicants | Application materials | 12 months from decision | Hiring manager |

DPO contact: replace_with_email@example.com.

## International transfers
%s

## Updates
This register is reviewed every 6 months; material changes are logged below with a timestamp + the responsible owner.
`, b["banner"], b["transfer"])
}

func defaultPrivacyNotice(b map[string]string) string {
	return fmt.Sprintf(`# Privacy Notice (Article 13)

> %s

## Who we are
Replace with your organisation's full legal name + registered address.

## What we collect, why, lawful basis
- Contact details when you reach out (email, name): legitimate interest, deleted 24 months after last contact.
- Website analytics (anonymised): your consent (cookie banner).
- Account data if you sign up: contract necessity, kept while your account is active.

## Sharing
We use these subprocessors: list them. We do not sell your data.

## International transfers
%s

## Your rights (Articles 15-22)
- Right of access, rectification, erasure ("right to be forgotten").
- Right to restrict + object to processing; right to data portability.
- Right to lodge a complaint with your supervisory authority (Sweden: IMY).

## How to reach us
DPO: replace_with_email@example.com. We aim to respond within 30 days.

## Changes
We post material changes here + email registered users.
`, b["banner"], b["transfer"])
}
