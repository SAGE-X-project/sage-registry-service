package registry

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func runtimeCertificates(t *testing.T) (tls.Certificate, tls.Certificate, tls.Certificate, tls.Certificate, *x509.CertPool, [32]byte, [32]byte, [32]byte) {
	t.Helper()
	createKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	caKey := createKey()
	window := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: window.Add(-time.Hour), NotAfter: window.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, names []string, usage x509.ExtKeyUsage) (tls.Certificate, []byte) {
		key := createKey()
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: names[0]},
			DNSNames: names, NotBefore: window.Add(-time.Hour), NotAfter: window.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}, der
	}
	server, _ := issue(2, []string{"agents.example.com", "admin.example.com"}, x509.ExtKeyUsageServerAuth)
	client, clientDER := issue(3, []string{"controller.example.com"}, x509.ExtKeyUsageClientAuth)
	operator, operatorDER := issue(4, []string{"operator.example.com"}, x509.ExtKeyUsageClientAuth)
	inspector, inspectorDER := issue(5, []string{"inspector.example.com"}, x509.ExtKeyUsageClientAuth)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return server, client, operator, inspector, roots, sha256.Sum256(clientDER),
		sha256.Sum256(operatorDER), sha256.Sum256(inspectorDER)
}

func routedClient(address string, roots *x509.CertPool, identity []tls.Certificate) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: identity, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}}
}

func TestRealTLSAdminWriteAndPublicRead(t *testing.T) {
	serverCert, clientCert, operatorCert, inspectorCert, roots, clientPin, operatorPin, inspectorPin := runtimeCertificates(t)
	config := Config{
		JournalPath: filepath.Join(t.TempDir(), "registry.log"), DID: testDID,
		Source: "https://agents.example.com", AdminHost: "admin.example.com",
		ClientActors: map[[32]byte]string{clientPin: "controller", operatorPin: "operator"}, Create: true,
		InspectorPins: map[[32]byte]struct{}{inspectorPin: {}},
		Now:           func() time.Time { return time.Unix(100, 0) },
	}
	service, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	admin := httptest.NewUnstartedServer(http.HandlerFunc(service.Admin))
	admin.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
	admin.StartTLS()
	public := httptest.NewUnstartedServer(http.HandlerFunc(service.Public))
	public.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}
	public.StartTLS()
	defer func() { admin.Close(); public.Close(); _ = service.Close() }()

	payload, _ := json.Marshal(map[string]string{
		"registry": "https://agents.example.com", "did": testDID,
		"candidate":        base64.RawURLEncoding.EncodeToString(candidate(t)),
		"expected_version": "", "operation": "create",
	})
	request, err := http.NewRequest(http.MethodPost, "https://admin.example.com/admin/registry", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	withoutCert := routedClient(admin.Listener.Addr().String(), roots, nil)
	if response, err := withoutCert.Do(request); err == nil {
		response.Body.Close()
		t.Fatal("administrator accepted a request without a client certificate")
	}
	request, err = http.NewRequest(http.MethodPost, "https://admin.example.com/admin/registry", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	withCert := routedClient(admin.Listener.Addr().String(), roots, []tls.Certificate{clientCert})
	response, err := withCert.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("administrator status = %d", response.StatusCode)
	}
	operatorClient := routedClient(admin.Listener.Addr().String(), roots, []tls.Certificate{operatorCert})
	grant := commandPayload(t, map[string]string{"expected_version": "1", "operation": "authorize-operator",
		"target_operator": "operator", "scope": "activate"})
	request, err = http.NewRequest(http.MethodPost, "https://admin.example.com/admin/registry", bytes.NewReader(grant))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err = operatorClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("operator attempted self-grant = %d", response.StatusCode)
	}
	request, err = http.NewRequest(http.MethodPost, "https://admin.example.com/admin/registry", bytes.NewReader(grant))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err = withCert.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("controller grant = %d", response.StatusCode)
	}
	activate := commandPayload(t, map[string]string{"candidate": nextCandidate(t, service, "3", "active", 100),
		"expected_version": "2", "operation": "activate"})
	request, err = http.NewRequest(http.MethodPost, "https://admin.example.com/admin/registry", bytes.NewReader(activate))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err = operatorClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delegated TLS write = %d", response.StatusCode)
	}
	inspectorClient := routedClient(admin.Listener.Addr().String(), roots, []tls.Certificate{inspectorCert})
	response, err = inspectorClient.Get("https://admin.example.com/admin/registry/inspection")
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK ||
		!bytes.Contains(inspection, []byte(`"version":"3"`)) ||
		!bytes.Contains(inspection, []byte(`"operation":"authorize-operator"`)) {
		t.Fatalf("inspector read = %d, error = %v", response.StatusCode, err)
	}
	request, err = http.NewRequest(http.MethodPost, "https://admin.example.com/admin/registry", bytes.NewReader(grant))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err = inspectorClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("inspector write = %d", response.StatusCode)
	}
	config.Now = func() time.Time { return time.Unix(101, 0) }
	service.now = config.Now
	publicClient := routedClient(public.Listener.Addr().String(), roots, nil)
	response, err = publicClient.Get("https://agents.example.com/.well-known/sage/agents/billing-bot")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("public status = %d, read error = %v", response.StatusCode, err)
	}
	var envelope struct {
		Issued  int64 `json:"issued"`
		Expires int64 `json:"expires"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Issued != 101 || envelope.Expires != 106 {
		t.Fatal("public response did not reflect the committed journal")
	}
	admin.Close()
	public.Close()
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	config.Create = false
	restored, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restored.Close() }()
	recorder := publicCall(restored, "https://agents.example.com/.well-known/sage/agents/billing-bot")
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(`"version":"3"`)) {
		t.Fatalf("restored public state = %d", recorder.Code)
	}
}
