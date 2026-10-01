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
	inspectorPin := sha256.Sum256([]byte("inspector-client"))
	now := int64(100)
	server, err := New(Config{
		JournalPath: filepath.Join(t.TempDir(), "registry.log"), DID: testDID,
		Source: "https://agents.example.com", AdminHost: "admin.example.com",
		ClientActors: map[[32]byte]string{pin: "controller"}, Create: true,
		InspectorPins: map[[32]byte]struct{}{inspectorPin: {}},
		Now:           func() time.Time { return time.Unix(now, 0) },
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

func inspectCall(server *Server, cert *x509.Certificate) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "https://admin.example.com/admin/registry/inspection", nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains: [][]*x509.Certificate{{cert}}}
	response := httptest.NewRecorder()
	server.Admin(response, request)
	return response
}

func commandPayload(t *testing.T, values map[string]string) []byte {
	t.Helper()
	values["registry"] = "https://agents.example.com"
	values["did"] = testDID
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func nextCandidate(t *testing.T, server *Server, version, state string, at int64) string {
	t.Helper()
	var envelope map[string]any
	if err := json.Unmarshal(server.journal.Inspect().Envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	record := envelope["record"].(map[string]any)
	record["version"] = version
	record["state"] = state
	envelope["issued"] = at
	envelope["expires"] = at + 5
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestOperatorCommandsBindActorVersionAndDurableGrantState(t *testing.T) {
	controller := &x509.Certificate{Raw: []byte("controller-client")}
	operator := &x509.Certificate{Raw: []byte("operator-client")}
	now := int64(100)
	config := Config{JournalPath: filepath.Join(t.TempDir(), "registry.log"), DID: testDID,
		Source: "https://agents.example.com", AdminHost: "admin.example.com", Create: true,
		ClientActors: map[[32]byte]string{
			sha256.Sum256(controller.Raw): "controller", sha256.Sum256(operator.Raw): "operator",
		}, InspectorPins: map[[32]byte]struct{}{sha256.Sum256([]byte("inspector-client")): {}},
		Now: func() time.Time { return time.Unix(now, 0) }}
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	create := commandPayload(t, map[string]string{"candidate": base64.RawURLEncoding.EncodeToString(candidate(t)),
		"expected_version": "", "operation": "create"})
	if got := adminCall(server, controller, create); got.Code != http.StatusNoContent {
		t.Fatalf("create = %d: %s", got.Code, got.Body.String())
	}
	now = 101
	grant := commandPayload(t, map[string]string{"expected_version": "1", "operation": "authorize-operator",
		"target_operator": "operator", "scope": "activate"})
	if got := adminCall(server, operator, grant); got.Code != http.StatusForbidden {
		t.Fatalf("operator granted itself authority: %d", got.Code)
	}
	if got := adminCall(server, controller, grant); got.Code != http.StatusNoContent {
		t.Fatalf("grant = %d: %s", got.Code, got.Body.String())
	}
	if got := adminCall(server, controller, grant); got.Code != http.StatusConflict {
		t.Fatalf("stale grant = %d", got.Code)
	}
	state := server.journal.Inspect()
	if len(state.Grants) != 1 || state.Grants[0].Operator != "operator" || len(state.History) != 2 ||
		state.History[1].Operation != "authorize-operator" || state.History[1].Target != "operator" {
		t.Fatal("grant and record history were not committed together")
	}
	if got := publicCall(server, "https://agents.example.com/.well-known/sage/agents/billing-bot"); got.Code != http.StatusOK || !bytes.Contains(got.Body.Bytes(), []byte(`"version":"2"`)) {
		t.Fatalf("public record did not advance with grant: %d", got.Code)
	}
	now = 102
	activate := commandPayload(t, map[string]string{"candidate": nextCandidate(t, server, "3", "active", now),
		"expected_version": "2", "operation": "activate"})
	if got := adminCall(server, operator, activate); got.Code != http.StatusNoContent {
		t.Fatalf("delegated activate = %d: %s", got.Code, got.Body.String())
	}
	state = server.journal.Inspect()
	if len(state.Grants) != 0 || len(state.History) != 3 {
		t.Fatal("state transition did not retire the ineligible scope")
	}
	now = 103
	grant = commandPayload(t, map[string]string{"expected_version": "3", "operation": "authorize-operator",
		"target_operator": "operator", "scope": "update-services"})
	if got := adminCall(server, controller, grant); got.Code != http.StatusNoContent {
		t.Fatalf("active grant = %d: %s", got.Code, got.Body.String())
	}
	now = 104
	revoke := commandPayload(t, map[string]string{"expected_version": "4", "operation": "revoke-operator",
		"target_operator": "operator", "scope": "update-services"})
	if got := adminCall(server, controller, revoke); got.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d: %s", got.Code, got.Body.String())
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	config.Create = false
	restored, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	state = restored.journal.Inspect()
	if len(state.Grants) != 0 || len(state.History) != 5 || state.History[4].Operation != "revoke-operator" ||
		state.History[4].Target != "operator" || state.History[4].Scope != "update-services" {
		t.Fatal("restart lost the committed grant history")
	}
	if got := publicCall(restored, "https://agents.example.com/.well-known/sage/agents/billing-bot"); got.Code != http.StatusOK || !bytes.Contains(got.Body.Bytes(), []byte(`"version":"5"`)) {
		t.Fatalf("public record did not advance with revoke: %d", got.Code)
	}
	inspector := &x509.Certificate{Raw: []byte("inspector-client")}
	if got := inspectCall(restored, inspector); got.Code != http.StatusOK ||
		!bytes.Contains(got.Body.Bytes(), []byte(`"version":"5"`)) ||
		!bytes.Contains(got.Body.Bytes(), []byte(`"operation":"revoke-operator"`)) {
		t.Fatalf("restarted inspection = %d: %s", got.Code, got.Body.String())
	}
	if got := inspectCall(restored, controller); got.Code != http.StatusForbidden {
		t.Fatalf("writer received inspector view: %d", got.Code)
	}
	now = 105
	update := commandPayload(t, map[string]string{"candidate": nextCandidate(t, restored, "6", "active", now),
		"expected_version": "5", "operation": "update-services"})
	if got := adminCall(restored, operator, update); got.Code != http.StatusForbidden {
		t.Fatalf("revoked operator write = %d", got.Code)
	}
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}
	if got := inspectCall(restored, inspector); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed journal inspection = %d", got.Code)
	}
}

func TestAdminCommandEncodingRejectsConflicts(t *testing.T) {
	server, controller, _ := testServer(t)
	cases := []map[string]string{
		{"registry": "https://other.example.com", "did": testDID, "expected_version": "1",
			"operation": "authorize-operator", "target_operator": "operator", "scope": "activate"},
		{"registry": "https://agents.example.com", "did": "did:sage:web:other.example.com:billing-bot",
			"expected_version": "1", "operation": "authorize-operator", "target_operator": "operator", "scope": "activate"},
		{"registry": "https://agents.example.com", "did": testDID, "expected_version": "1",
			"operation": "authorize-operator", "target_operator": "operator", "scope": "activate", "candidate": "AA"},
		{"registry": "https://agents.example.com", "did": testDID, "expected_version": "1",
			"operation": "unknown", "target_operator": "operator", "scope": "activate"},
	}
	for _, fields := range cases {
		body, _ := json.Marshal(fields)
		if got := adminCall(server, controller, body); got.Code != http.StatusBadRequest {
			t.Fatalf("ambiguous command accepted: %s => %d", body, got.Code)
		}
	}
}

func TestServiceRejectsUnboundOrOverlappingPrincipals(t *testing.T) {
	writer := sha256.Sum256([]byte("writer"))
	inspector := sha256.Sum256([]byte("inspector"))
	for _, test := range []struct {
		actor  string
		reader [32]byte
	}{
		{"", inspector}, {"controller\n", inspector}, {"é", inspector},
		{string(bytes.Repeat([]byte{'a'}, 257)), inspector}, {"controller", writer},
	} {
		_, err := New(Config{JournalPath: filepath.Join(t.TempDir(), "registry.log"), DID: testDID,
			Source: "https://agents.example.com", AdminHost: "admin.example.com", Create: true,
			ClientActors:  map[[32]byte]string{writer: test.actor},
			InspectorPins: map[[32]byte]struct{}{test.reader: {}}})
		if err == nil {
			t.Fatalf("accepted invalid or overlapping principal %q", test.actor)
		}
	}
}

func TestJournalBacksAdminAndPublicHandlers(t *testing.T) {
	server, cert, now := testServer(t)
	target := "https://agents.example.com/.well-known/sage/agents/billing-bot"
	if got := publicCall(server, target); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("empty journal status = %d", got.Code)
	}
	beforeCreate := commandPayload(t, map[string]string{"expected_version": "1",
		"operation": "authorize-operator", "target_operator": "operator", "scope": "activate"})
	if got := adminCall(server, cert, beforeCreate); got.Code != http.StatusConflict {
		t.Fatalf("pre-creation grant = %d", got.Code)
	}
	payload, _ := json.Marshal(map[string]string{
		"registry": "https://agents.example.com", "did": testDID,
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
	if got := adminCall(server, cert, []byte(`{"registry":"https://agents.example.com","did":"did:sage:web:agents.example.com:billing-bot","candidate":"a","candidate":"b","expected_version":"","operation":"create"}`)); got.Code != http.StatusBadRequest {
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
