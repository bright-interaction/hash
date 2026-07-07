// Package agreement holds Hash's built-in starter document templates. The
// trees are authored once here (single source of truth) so the same content
// powers the demo artifacts, the "starter template" a tenant can seed from the
// Templates page, and any future starters. Keeping them in Go (not the DB) means
// they version with the code and render identically everywhere.
package agreement

import (
	"encoding/json"

	"github.com/brightinteraction/hash/internal/blocks"
)

// Starter identifies a built-in starter by a stable key used in the API.
type Starter struct {
	Key         string
	Name        string
	Description string
	Tree        blocks.Tree
	// Variables are the default {{token}} values. Stored as the document/
	// template variables_json object so substitution works the moment a
	// document is created from it.
	Variables map[string]string
}

// BlocksJSON marshals the block tree for persistence.
func (s Starter) BlocksJSON() json.RawMessage {
	b, _ := json.Marshal(s.Tree)
	return b
}

// VariablesJSON marshals the default variable map for persistence.
func (s Starter) VariablesJSON() json.RawMessage {
	b, _ := json.Marshal(s.Variables)
	return b
}

// Starters returns all built-in starters keyed by Key.
func Starters() map[string]Starter {
	return map[string]Starter{
		ServicesAgreement.Key: ServicesAgreement,
	}
}

// Get returns a starter by key.
func Get(key string) (Starter, bool) {
	s, ok := Starters()[key]
	return s, ok
}

// small block constructors keep the tree below readable.
func h(id string, level int, text string) blocks.Block {
	return blocks.Block{ID: id, Type: blocks.TypeHeading, Attrs: map[string]any{"level": level}, Text: text}
}
func p(id, text string) blocks.Block { return blocks.Block{ID: id, Type: blocks.TypeParagraph, Text: text} }
func quote(id, text string) blocks.Block {
	return blocks.Block{ID: id, Type: blocks.TypeQuote, Text: text}
}
func divider(id string) blocks.Block  { return blocks.Block{ID: id, Type: blocks.TypeDivider} }
func pageBreak(id string) blocks.Block { return blocks.Block{ID: id, Type: blocks.TypePageBreak} }
func li(id, text string) blocks.Block  { return blocks.Block{ID: id, Type: blocks.TypeListItem, Text: text} }

func table(id string, columns []string, rows [][]string) blocks.Block {
	// Validation + the renderer read attrs.columns as []any (JSON array shape),
	// so build it that way rather than []string.
	cols := make([]any, len(columns))
	for i, c := range columns {
		cols[i] = c
	}
	return blocks.Block{ID: id, Type: blocks.TypeTable, Attrs: map[string]any{"columns": cols}, Rows: rows}
}

func sigField(id, role, label string) blocks.Block {
	return blocks.Block{ID: id, Type: blocks.TypeSignatureField, Attrs: map[string]any{
		"recipient_role": role, "label": label, "required": true,
	}}
}

// ServicesAgreement is the reusable Swedish website + automations services /
// pilot agreement. It is generic (everything client-specific is a {{token}})
// and carries two structured tables: Bilaga 1 (tjanster) and Bilaga 2 (tidplan).
// Clause set synthesised from a six-perspective legal/commercial review.
var ServicesAgreement = Starter{
	Key:         "services-agreement-sv",
	Name:        "Tjänsteavtal: webbplats och automationer (svenska)",
	Description: "Komplett återanvändbart avtal med tjänstetabell, tidplan och platshållare.",
	Variables: map[string]string{
		"provider":                "Bright Interaction AB",
		"provider_orgnr":          "559XXX-XXXX",
		"provider_signatory":      "Tom Isgren",
		"provider_title":          "Grundare",
		"client":                  "Kundföretaget AB",
		"client_orgnr":            "55XXXX-XXXX",
		"client_signatory":        "",
		"client_title":            "",
		"effective_date":          "2026-06-23",
		"offer_valid_days":        "30",
		"offer_valid_until":       "2026-07-23",
		"price":                   "15 000",
		"vat_rate":                "25",
		"payment_terms_days":      "15",
		"delivery_weeks":          "3",
		"approval_days":           "5",
		"warranty_days":           "30",
		"liability_cap":           "15 000",
		"hourly_rate":             "1 200",
		"revisions":               "2",
		"termination_notice_days": "14",
		"cure_days":               "30",
		"force_majeure_days":      "60",
		"incident_notice_hours":   "48",
		"reference_optin":         "namngiven",
		"venue":                   "Stockholms tingsrätt",
		"city":                    "Stockholm",
	},
	Tree: blocks.Tree{Version: 1, Blocks: []blocks.Block{
		// Försättsblad (front page): title, key terms, and both parties.
		h("title", 1, "Tjänsteavtal"),
		p("subtitle", "Webbplats och automationer för {{client}}"),
		p("cover-meta", "Avtalsdatum: {{effective_date}}  ·  Avtalssumma: {{price}} kr ex moms  ·  Erbjudande giltigt t.o.m.: {{offer_valid_until}}"),
		p("cover-parties-label", "Detta avtal tecknas mellan följande parter:"),
		table("tbl-parties", []string{"Leverantör", "Kund"}, [][]string{
			{"{{provider}}", "{{client}}"},
			{"Org.nr {{provider_orgnr}}", "Org.nr {{client_orgnr}}"},
			{"Företrädare: {{provider_signatory}}", "Företrädare: {{client_signatory}}"},
			{"{{provider_title}}", "{{client_title}}"},
		}),
		pageBreak("pb-cover"),
		// Avtalstext (body).
		p("intro", "Detta avtal (\"Avtalet\") tecknas den {{effective_date}} mellan {{provider}}, org.nr {{provider_orgnr}} (\"Leverantören\"), och {{client}}, org.nr {{client_orgnr}} (\"Kunden\"). Avtalet omfattar att Leverantören bygger en webbplats på plattformen Atomicsite samt sätter upp automationer enligt Bilaga 1, med tidplan enligt Bilaga 2."),
		quote("price-hl", "Fast pris: {{price}} kr exklusive moms. Faktureras först efter godkänd slutleverans. Kunden får en färdig, ägd produkt; Leverantören får testa och iterera sina tjänster under leveransen."),

		h("h1", 2, "1. Bakgrund och pilotupplägg"),
		p("s1", "{{provider}} bygger en webbplats på Atomicsite samt automationer åt {{client}}. Eftersom detta är ett pilotuppdrag levereras det till ett rabatterat fast pris mot rätt att använda uppdraget som referens enligt avsnitt 22."),

		h("h2", 2, "2. Avtalets ingående och giltighet"),
		p("s2", "Avtalet är bindande när båda parter undertecknat eller när {{client}} skriftligen accepterat detta erbjudande, senast {{offer_valid_until}}. Erbjudandet gäller i {{offer_valid_days}} dagar från {{effective_date}}."),

		h("h3", 2, "3. Omfattning och bilagor"),
		p("s3", "Avtalad omfattning framgår av Bilaga 1 (Tjänster) och Bilaga 2 (Tidplan). Allt som inte uttryckligen anges som ingående är inte med i det fasta priset. Vid motstrid gäller huvudtexten före bilagorna, dock har Bilaga A (personuppgiftsbiträdesavtal) företräde i frågor om personuppgiftsbehandling."),

		h("h4", 2, "4. Kundens åtagande och förutsättningar"),
		p("s4", "{{client}} ska i tid tillhandahålla varumärkesmaterial (logotyp i vektorformat, färger, typsnitt), allt innehåll (texter, bilder, produktdata) samt nödvändig åtkomst till domän, DNS, befintligt CMS, CRM, e-post och betalkonto. {{client}} ansvarar för att inneha rätt att använda allt material som lämnas och för att innehåll och produkter följer lag och branschregler."),

		h("h5", 2, "5. Pris, valuta och moms"),
		p("s5", "Det fasta priset är {{price}} kr (SEK) exklusive moms. Moms tillkommer med vid var tid gällande sats, idag {{vat_rate}} procent. Båda parter är svenska och momsregistrerade."),

		h("h6", 2, "6. Det här ingår inte"),
		p("s6", "Priset omfattar endast leveranserna i Bilaga 1. Följande ingår inte och offereras separat: fler sidmallar än överenskommet, fler än {{revisions}} revideringsomgångar, copywriting, foto, grafisk produktion, ytterligare automationsflöden, integrationer mot tredjepartssystem, SEO-arbete samt löpande drift och support efter överlämning."),

		h("h7", 2, "7. Ändringar och tilläggsarbete"),
		p("s7", "Ändringar av omfattningen ska begäras skriftligt. {{provider}} lämnar uppskattning av pris och påverkan på tidplan innan arbete påbörjas, och tilläggsarbete startar först efter skriftligt godkännande. Tidplanen förskjuts i motsvarande mån. Tilläggsarbete debiteras per timme med {{hourly_rate}} kr ex moms eller enligt separat offert."),

		h("h8", 2, "8. Betalning och dröjsmål"),
		p("s8", "Hela priset faktureras efter godkänd slutleverans enligt avsnitt 9, med {{payment_terms_days}} dagars betalningsvillkor netto. Vid försenad betalning utgår dröjsmålsränta enligt räntelagen samt lagstadgad påminnelseavgift och inkassoersättning. {{provider}} får hålla inne överlämning och avpublicera levererat material tills förfallen betalning erlagts."),

		h("h9", 2, "9. Tidplan och leveransgodkännande"),
		p("s9", "Riktmärket är {{delivery_weeks}} veckor och tidplanen i Bilaga 2 börjar löpa först när {{client}} levererat material och åtkomst. Leverans anses godkänd när {{client}} skriftligen bekräftar att webbplatsen är publicerad och automationerna aktiva, eller om ingen skriftlig och saklig invändning inkommit inom {{approval_days}} arbetsdagar efter att {{provider}} aviserat färdigställande med leveransbevis. Invändning får endast avse väsentlig avvikelse från Bilaga 1."),

		h("h10", 2, "10. Acceptanskriterier"),
		p("s10", "Med godkänd leverans avses att webbplatsen är publicerad på avtalad domän, att varje automationsflöde testats med ett verifierat testfall (till exempel att ett ifyllt kontaktformulär ger en post i CRM) och att inga öppna kritiska fel finns."),

		h("h11", 2, "11. Garanti och felavhjälpande"),
		p("s11", "{{provider}} rättar kostnadsfritt väsentliga fel som beror på {{provider}}s arbete och som {{client}} påtalar skriftligen inom {{warranty_days}} dagar efter godkännande. Garantin täcker inte nya önskemål, fel orsakade av {{client}}s egna ändringar, ändringar hos tredjepartstjänster eller innehållsfel. I övrigt levereras tjänsten i befintligt skick utan garanti för oavbruten drift eller specifika affärsresultat."),

		h("h12", 2, "12. Drift, hosting och support efter överlämning"),
		p("s12", "Säkerhetsnivån A+ och EU-hosting gäller vid leverans. Löpande drift, hosting, säkerhetsuppdateringar, backup och support efter överlämning ingår inte utan tecknas separat. {{client}} ansvarar för säkerhetsnivån efter att drift övertagits eller egna ändringar gjorts."),

		h("h13", 2, "13. Överlämning och dokumentation"),
		p("s13", "Vid godkännande och full betalning överlämnas Atomicsite-binären, runbook och relevanta inloggningsuppgifter. {{client}} ansvarar för att förvara inloggningsuppgifter säkert. En digital genomgång om cirka en timme ingår; ytterligare utbildning är separat tjänst."),

		h("h14", 2, "14. Äganderätt, nyttjanderätt och öppen källkod"),
		p("s14", "{{client}} äger sitt innehåll, varumärke, domän och kunddata. Vid full betalning får {{client}} en icke-exklusiv och icke-överlåtbar nyttjanderätt till den levererade webbplatskonfigurationen. Atomicsite-binären levereras under sin öppna licens Apache 2.0, vilket redan i sig ger {{client}} en evig och oåterkallelig rätt att köra och driftsätta den. {{provider}} behåller alla generella metoder, mallar, byggblock och verktyg och får återanvända dem fritt. {{provider}} efterger den ideella rätten i den mån lagen tillåter."),

		h("h15", 2, "15. Domän och kontoägande"),
		p("s15", "{{client}} äger och bekostar domän, DNS, hostingkonto, e-postkonton, betalkonto och CRM-konto om inte annat avtalats. Tredjepartsavgifter bekostas av {{client}} och vidarefaktureras till självkostnad om {{provider}} lägger ut dem, men aldrig utan {{client}}s godkännande."),

		h("h16", 2, "16. Ansvarsbegränsning"),
		p("s16", "{{provider}}s totala ansvar under Avtalet är begränsat till det belopp {{client}} betalat, högst {{liability_cap}} kr. {{provider}} ansvarar inte för indirekt skada eller följdskada såsom utebliven vinst, förlorad omsättning, dataförlust eller förlust av goodwill. Begränsningarna gäller inte vid uppsåt, grov vårdslöshet eller där tvingande lag annars gäller."),

		h("h17", 2, "17. Kundens ansvar för material och ansvarsfrihet"),
		p("s17", "{{client}} garanterar att tillhandahållet material är lagligt och inte gör intrång i tredje parts rättigheter, och håller {{provider}} skadeslös för krav som grundar sig på {{client}}s material, produkter eller marknadsföring. {{provider}} håller {{client}} skadeslös för krav om att {{provider}}s egna verktyg eller metoder gör intrång i tredje parts rättigheter, begränsat enligt ansvarsbegränsningen."),

		h("h18", 2, "18. Personuppgifter"),
		p("s18", "När {{provider}} behandlar personuppgifter för {{client}}s räkning sker det som personuppgiftsbiträde enligt artikel 28 GDPR. {{client}} är personuppgiftsansvarig och {{provider}} biträde. Ett personuppgiftsbiträdesavtal (Bilaga A) gäller från driftstart, med instruktioner, säkerhetsåtgärder, underbiträden, radering vid avslut och incidentunderrättelse inom {{incident_notice_hours}} timmar, och har företräde i frågor om personuppgiftsbehandling."),

		h("h19", 2, "19. Force majeure"),
		p("s19", "Ingen part ansvarar för dröjsmål eller utebliven prestation som beror på omständighet utanför partens rimliga kontroll, såsom strömavbrott, avbrott hos tredjepartsleverantör, myndighetsbeslut eller omfattande cyberattack. Drabbad part ska underrätta motparten utan dröjsmål. Varar hindret längre än {{force_majeure_days}} dagar får endera parten säga upp Avtalet, varvid betalning sker för utfört arbete."),

		h("h20", 2, "20. Uppsägning, hävning och avbrott"),
		p("s20", "Båda parter får säga upp Avtalet med {{termination_notice_days}} dagars skriftligt varsel. Vid uppsägning eller avbrott ersätts {{provider}} för faktiskt utfört arbete proportionellt mot priset eller enligt timpris, och nyttjanderätt till delleveransen övergår först när denna betalats. Hävning får ske vid väsentligt avtalsbrott som inte rättas inom {{cure_days}} dagar efter skriftlig anmaning, eller vid motpartens insolvens."),

		h("h21", 2, "21. Underleverantörer och överlåtelse"),
		p("s21", "{{provider}} får anlita underleverantörer men ansvarar för deras del som för eget arbete inom ramen för ansvarsbegränsningen. Avtalet får inte överlåtas utan motpartens skriftliga samtycke, dock får {{provider}} överlåta till koncernbolag."),

		h("h22", 2, "22. Sekretess och referens"),
		p("s22", "Parterna håller information om varandra konfidentiell. {{provider}} får iterera sina tjänster under uppdraget. {{client}} ger {{provider}} rätt att namnge {{client}} som referenskund och visa skärmdumpar och säkerhetsbetyg efter publicering ({{reference_optin}}); referensmaterial innehåller inga personuppgifter om registrerade. {{client}} kan återkalla samtycket skriftligt."),

		h("h23", 2, "23. Meddelanden, ändringar och fullständig reglering"),
		p("s23", "Skriftliga meddelanden skickas till parternas angivna e-postadresser och anses mottagna samma arbetsdag om de skickats före kl 17, annars nästa arbetsdag. Ändringar och tillägg gäller endast skriftligen och undertecknade av båda parter. Detta avtal med bilagor utgör parternas fullständiga överenskommelse och ersätter alla tidigare utfästelser."),

		h("h24", 2, "24. Tillämplig lag och tvist"),
		p("s24", "Svensk lag gäller med undantag för dess lagvalsregler. Parterna ska först försöka lösa tvist genom förhandling. Kvarstående tvist avgörs av {{venue}}."),

		pageBreak("pb-bilaga1"),
		h("bil1", 2, "Bilaga 1: Tjänster (vad ingår)"),
		p("bil1p", "Följande tjänster ingår i det fasta priset. Rader markerade med ett pris utöver \"Ingår\" offereras separat."),
		table("tbl-services",
			[]string{"Tjänst", "Vad ingår", "Antal/Enhet", "Ingår i pris", "Pris ex moms"},
			[][]string{
				{"Webbplats på Atomicsite", "Responsiv sajt med {{client}}s brand, A+ säkerhetsprofil vid leverans, EU-hosting under uppdraget", "1 sajt, upp till 5 sidor", "Ja", "Ingår"},
				{"Innehållsmigrering", "Flytt av befintligt innehåll (text, bilder, produktdata) till ny sajt", "upp till 5 sidor", "Ja", "Ingår"},
				{"Automation: formulär till CRM", "Kontaktformulär skickar lead till CRM automatiskt med notis", "1 flöde", "Ja", "Ingår"},
				{"Överlämning", "Atomicsite-binär (Apache 2.0) + runbook + genomgång ca 1 timme", "1 paket", "Ja", "Ingår"},
			}),

		h("bil2", 2, "Bilaga 2: Tidplan och milstolpar"),
		p("bil2p", "Tidplanen börjar löpa när {{client}} levererat material och åtkomst enligt avsnitt 4. Riktmärke {{delivery_weeks}} veckor."),
		table("tbl-timeline",
			[]string{"Fas", "Leverabel", "Vecka", "Kundens beroende", "Godkännande"},
			[][]string{
				{"1. Uppstart och underlag", "Avstämning, sidkarta, insamling av material och åtkomst", "Vecka 1", "Logotyp (vektor), färger/typsnitt, texter, bilder, produktdata, åtkomst till domän/DNS och CRM", "Underlag bekräftat komplett"},
				{"2. Webbplats i Atomicsite", "Sajt uppbyggd med brand, struktur, EU-hosting och A+ säkerhetskonfiguration", "Vecka 1-2", "Feedback på utkast inom 2 arbetsdagar", "Utkast godkänt av {{client}}"},
				{"3. Innehållsmigrering", "Befintligt innehåll överfört och kvalitetssäkrat", "Vecka 2", "Tillgång till befintlig innehållskälla", "Innehåll granskat"},
				{"4. Automationsflöde", "Återkommande flöde byggt och testat med verifierat testfall (formulär till CRM)", "Vecka 2-3", "Tillgång och rättigheter i CRM samt mottagaradress", "Testresultat godkänt (post syns i CRM)"},
				{"5. Lansering och överlämning", "Publicering, överlämning av binär + runbook, genomgång", "Vecka {{delivery_weeks}}", "Beslut om publicering", "Leverans godkänd (garantiperiod startar)"},
			}),

		h("sign", 2, "Underskrift"),
		p("signp", "Avtalet undertecknas elektroniskt av båda parter och kan signeras i flera exemplar; varje exemplar gäller som original. Genom att signera bekräftar undertecknad behörighet att binda sin part och godkänner villkoren ovan."),

		p("sig-prov-label", "För Leverantören: {{provider}}, org.nr {{provider_orgnr}}. Företrädare {{provider_signatory}}, {{provider_title}}."),
		sigField("sig-provider", "approver", "Leverantörens underskrift"),

		divider("sig-div"),

		p("sig-client-label", "För Kunden: {{client}}, org.nr {{client_orgnr}}. Företrädare {{client_signatory}}, {{client_title}}."),
		sigField("sig-client", "signer", "Kundens underskrift"),
	}},
}
