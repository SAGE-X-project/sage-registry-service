package registry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/sage-x-project/sage/pkg/agent/registry010"
)

const testDID = "did:sage:web:agents.example.com:billing-bot"

func candidate(t *testing.T) []byte {
	t.Helper()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	challenge, err := registry010.PoPChallenge010("web:agents.example.com", "billing-bot", "signer", "ed25519", public)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	value, err := json.Marshal(map[string]any{
		"record": map[string]any{
			"id": testDID, "controller": "controller", "state": "created", "version": "1",
			"services": []any{}, "keys": []any{map[string]any{
				"name": "signer", "alg": "ed25519", "key": encode(public), "state": "accepted",
				"proof": map[string]any{"signer": testDID + "#signer", "value": encode(ed25519.Sign(private, challenge))},
			}},
		}, "issued": 100, "expires": 105,
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testServer(t *testing.T) (*Server, *x509.Certificate, *int64) {
	t.Helper()
	cert := &x509.Certificate{Raw: []byte("verified-client")}
	pin := sha256.Sum256(cert.Raw)
	now := int64(100)
	server, err := New(Config{
		JournalPath: filepath.Join(t.TempDir(), "registry.log"), DID: testDID,
		Source: "https://agents.example.com", AdminHost: "admin.example.com",
		ClientActors: map[[32]byte]string{pin: "controller"}, Create: true,
		Now: func() time.Time { return time.Unix(now, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, cert, &now
}

func adminCall(server *Server, cert *x509.Certificate, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://admin.example.com/admin/registry", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	response := httptest.NewRecorder()
	server.Admin(response, request)
	return response
}

func publicCall(server *Server, target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.TLS = &tls.ConnectionState{}
	response := httptest.NewRecorder()
	server.Public(response, request)
	return response
}

func TestJournalBacksAdminAndPublicHandlers(t *testing.T) {
	server, cert, now := testServer(t)
	target := "https://agents.example.com/.well-known/sage/agents/billing-bot"
	if got := publicCall(server, target); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("empty journal status = %d", got.Code)
	}
	payload, _ := json.Marshal(map[string]string{
		"candidate":        base64.RawURLEncoding.EncodeToString(candidate(t)),
		"expected_version": "", "operation": "create",
	})
	if got := adminCall(server, cert, payload); got.Code != http.StatusNoContent {
		t.Fatalf("write status = %d: %s", got.Code, got.Body.String())
	}
	*now = 101
	got := publicCall(server, target)
	if got.Code != http.StatusOK || got.Header().Get("Content-Type") != "application/json" ||
		got.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("public status = %d: %s", got.Code, got.Body.String())
	}
	var envelope struct {
		Record  json.RawMessage `json:"record"`
		Issued  int64           `json:"issued"`
		Expires int64           `json:"expires"`
	}
	if json.Unmarshal(got.Body.Bytes(), &envelope) != nil || envelope.Issued != 101 ||
		envelope.Expires != 106 || registry010.CheckWebRegistryProofs010(got.Body.Bytes(), testDID, 101) != nil {
		t.Fatal("public response does not match the committed record")
	}
	if got := publicCall(server, target+"?fallback=1"); got.Code != http.StatusNotFound {
		t.Fatalf("query was accepted: %d", got.Code)
	}
	if got := adminCall(server, cert, []byte(`{"candidate":"a","candidate":"b","expected_version":"","operation":"create"}`)); got.Code != http.StatusBadRequest {
		t.Fatalf("duplicate field was accepted: %d", got.Code)
	}
	if got := adminCall(server, &x509.Certificate{Raw: []byte("other-client")}, payload); got.Code != http.StatusForbidden {
		t.Fatalf("unrecognized client was accepted: %d", got.Code)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if got := publicCall(server, target); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed journal status = %d", got.Code)
	}
}
