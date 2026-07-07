package qes

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// IduraProvider hits the live Idura BankID API (https://api.idura.se).
// Idura is a Swedish QTSP that proxies BankID + delivers eIDAS QES.
// Required env:
//
//   HASH_QES_IDURA_BASE_URL  default https://api.idura.se
//   HASH_QES_IDURA_API_KEY   bearer token issued by Idura
//   HASH_QES_IDURA_TENANT    tenant slug
//
// Wire shape (Idura v1 REST):
//
//   POST {base}/v1/qes/sessions
//     {tenant, callback_url, document_digest_hex, signer_email, signer_name}
//     200 {session_id, redirect_url, expires_at}
//
//   POST callback_url
//     headers: X-Idura-Signature: t=<unix>,v1=<hex>
//     body: {session_id, status, identity_assertion: {...}, signature_b64,
//            cert_chain_pem, signer_name, signer_serial}
//
// On any 4xx/5xx, Start/Callback return wrapped errors so the handler
// can fail the session row + surface a clear message.
type IduraProvider struct {
	BaseURL string
	APIKey  string
	Tenant  string
	HTTP    *http.Client
}

func NewIduraProvider(baseURL, apiKey, tenant string) *IduraProvider {
	return &IduraProvider{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Tenant:  tenant,
		HTTP:    &http.Client{Timeout: 20 * time.Second},
	}
}

func (p *IduraProvider) Name() string { return "idura" }

type iduraStartRequest struct {
	Tenant            string `json:"tenant"`
	CallbackURL       string `json:"callback_url"`
	DocumentDigestHex string `json:"document_digest_hex"`
	SignerEmail       string `json:"signer_email"`
	SignerName        string `json:"signer_name"`
}

type iduraStartResponse struct {
	SessionID      string `json:"session_id"`
	RedirectURL    string `json:"redirect_url"`
	ExpiresAtUnix  int64  `json:"expires_at_unix"`
	CallbackSecret string `json:"callback_secret"`
}

func (p *IduraProvider) Start(ctx context.Context, in StartInput) (*StartResult, error) {
	if p.APIKey == "" {
		return nil, errors.New("qes: idura provider missing API key (set HASH_QES_IDURA_API_KEY)")
	}
	body, _ := json.Marshal(iduraStartRequest{
		Tenant:            p.Tenant,
		CallbackURL:       in.CallbackURL,
		DocumentDigestHex: hex.EncodeToString(in.SignedDigest[:]),
		SignerEmail:       in.RecipientEmail,
		SignerName:        in.RecipientName,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.BaseURL+"/v1/qes/sessions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qes idura: start request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("qes idura: start %d: %s", resp.StatusCode, string(raw))
	}
	var out iduraStartResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("qes idura: decode start: %w", err)
	}
	if out.SessionID == "" || out.RedirectURL == "" {
		return nil, errors.New("qes idura: empty session id or redirect url")
	}
	expires := time.Unix(out.ExpiresAtUnix, 0).UTC()
	if expires.IsZero() {
		expires = time.Now().UTC().Add(1 * time.Hour)
	}
	return &StartResult{
		ProviderSessionID: out.SessionID,
		RedirectURL:       out.RedirectURL,
		CallbackSecret:    out.CallbackSecret,
		ExpiresAt:         expires,
	}, nil
}

type iduraCallback struct {
	SessionID         string          `json:"session_id"`
	Status            string          `json:"status"`
	IdentityAssertion json.RawMessage `json:"identity_assertion"`
	SignatureB64      string          `json:"signature_b64"`
	CertChainPEM      string          `json:"cert_chain_pem"`
	SignerName        string          `json:"signer_name"`
	SignerSerial      string          `json:"signer_serial"`
	FailureReason     string          `json:"failure_reason"`
}

// Callback validates the QTSP's HMAC-signed callback. Idura signs:
//
//   X-Idura-Signature: t=<unix>,v1=<hex>
//
// over: "t=<ts>." + body. We bound the timestamp skew at 10 minutes so
// a replayed callback from yesterday can't complete a session.
func (p *IduraProvider) Callback(ctx context.Context, in CallbackInput) (*CallbackResult, error) {
	sigHdr := in.Headers["X-Idura-Signature"]
	if sigHdr == "" {
		sigHdr = in.Headers["x-idura-signature"]
	}
	if sigHdr == "" {
		return nil, ErrInvalidCallback
	}
	ts, hexSig, err := parseSignatureHeader(sigHdr)
	if err != nil {
		return nil, ErrInvalidCallback
	}
	if time.Since(time.Unix(ts, 0)).Abs() > 10*time.Minute {
		return nil, ErrInvalidCallback
	}
	mac := hmac.New(sha256.New, []byte(in.CallbackSecret))
	fmt.Fprintf(mac, "t=%d.", ts)
	mac.Write(in.RawBody)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(hexSig)) {
		return nil, ErrInvalidCallback
	}
	var cb iduraCallback
	if err := json.Unmarshal(in.RawBody, &cb); err != nil {
		return nil, fmt.Errorf("qes idura: decode callback: %w", err)
	}
	if cb.Status != "completed" {
		return nil, fmt.Errorf("qes idura: callback status=%s reason=%q", cb.Status, cb.FailureReason)
	}
	if cb.SignatureB64 == "" {
		return nil, errors.New("qes idura: callback missing signature_b64")
	}
	return &CallbackResult{
		IdentityAssertion: cb.IdentityAssertion,
		SignatureB64:      cb.SignatureB64,
		CertChainPEM:      cb.CertChainPEM,
		SignerName:        cb.SignerName,
		SignerSerial:      cb.SignerSerial,
	}, nil
}

// parseSignatureHeader parses "t=<unix>,v1=<hex>" into (timestamp, hex).
func parseSignatureHeader(h string) (int64, string, error) {
	var ts int64
	var hexSig string
	for _, part := range splitTwo(h, ",") {
		if len(part) > 2 && part[:2] == "t=" {
			n, err := parseInt64(part[2:])
			if err != nil {
				return 0, "", err
			}
			ts = n
		}
		if len(part) > 3 && part[:3] == "v1=" {
			hexSig = part[3:]
		}
	}
	if ts == 0 || hexSig == "" {
		return 0, "", errors.New("malformed signature header")
	}
	return ts, hexSig, nil
}

func splitTwo(s, sep string) []string {
	out := []string{}
	cur := ""
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			out = append(out, cur)
			cur = ""
			i += len(sep) - 1
			continue
		}
		cur += string(s[i])
	}
	out = append(out, cur)
	return out
}

func parseInt64(s string) (int64, error) {
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, errors.New("non-digit in int")
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}
