package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/sage-x-project/sage/pkg/agent/registry010"
)

const maxAdminBody = 150000

type actorContextKey struct{}

type requestAuthority struct{}

func (requestAuthority) AuthenticatedActor(ctx context.Context) (string, error) {
	actor, ok := ctx.Value(actorContextKey{}).(string)
	if !ok || actor == "" {
		return "", registry010.ErrRejected
	}
	return actor, nil
}

func (requestAuthority) Delegated(context.Context, string, string, string, string, string) (bool, error) {
	return false, nil
}

// Config is trusted service configuration. ClientActors maps a verified mTLS
// leaf-certificate SHA-256 fingerprint to an exact controller or operator
// identifier. Grants are checked from the committed journal state.
type Config struct {
	JournalPath   string
	DID           string
	Source        string
	AdminHost     string
	ClientActors  map[[32]byte]string
	InspectorPins map[[32]byte]struct{}
	Create        bool
	Now           func() time.Time
}

// Server serves the public record and authenticated writes from one durable
// journal in the same process. Its caller must configure separate HTTPS and
// mTLS listeners and an approved public origin.
type Server struct {
	journal    *registry010.WebRegistryWriteJournal010
	did        string
	source     string
	host       string
	path       string
	admin      string
	actors     map[[32]byte]string
	inspectors map[[32]byte]struct{}
	mu         sync.Mutex
	uncertain  bool
	now        func() time.Time
}

func New(cfg Config) (*Server, error) {
	requestURL, err := registry010.WebRegistryRequestURL010(cfg.DID, []string{cfg.Source})
	if err != nil || cfg.JournalPath == "" || cfg.AdminHost == "" ||
		len(cfg.ClientActors) == 0 || len(cfg.InspectorPins) == 0 {
		return nil, registry010.ErrRejected
	}
	parsed, err := url.Parse(requestURL)
	if err != nil || parsed.Host == cfg.AdminHost {
		return nil, registry010.ErrRejected
	}
	journal, err := registry010.OpenWebRegistryWriteJournal010(
		cfg.JournalPath, cfg.DID, cfg.Source, requestAuthority{}, cfg.Create)
	if err != nil {
		return nil, err
	}
	clock := cfg.Now
	if clock == nil {
		clock = time.Now
	}
	actors := make(map[[32]byte]string, len(cfg.ClientActors))
	for pin, actor := range cfg.ClientActors {
		if !validActor(actor) {
			_ = journal.Close()
			return nil, registry010.ErrRejected
		}
		actors[pin] = actor
	}
	inspectors := make(map[[32]byte]struct{}, len(cfg.InspectorPins))
	for pin := range cfg.InspectorPins {
		if _, writer := actors[pin]; writer {
			_ = journal.Close()
			return nil, registry010.ErrRejected
		}
		inspectors[pin] = struct{}{}
	}
	return &Server{journal: journal, did: cfg.DID, source: cfg.Source,
		host: parsed.Host, path: parsed.Path, admin: cfg.AdminHost, actors: actors,
		inspectors: inspectors, now: clock}, nil
}

func validActor(actor string) bool {
	if len(actor) == 0 || len(actor) > 256 {
		return false
	}
	for index := range actor {
		if actor[index] < 0x20 || actor[index] > 0x7e {
			return false
		}
	}
	return true
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uncertain = true
	return s.journal.Close()
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func (s *Server) Public(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.TLS == nil || r.Method != http.MethodGet || r.Host != s.host ||
		r.URL.Path != s.path || r.URL.RawPath != "" || r.URL.RawQuery != "" ||
		r.ContentLength > 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		http.Error(w, "record unavailable", http.StatusNotFound)
		return
	}
	body, err := s.journal.PublicEnvelope010(s.did, s.source, s.now().Unix())
	if err != nil {
		http.Error(w, "record unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

type adminRequest struct {
	Registry        string
	DID             string
	Candidate       string
	ExpectedVersion string
	Operation       string
	TargetOperator  string
	Scope           string
}

func managementOperation(operation string) bool {
	return operation == "authorize-operator" || operation == "revoke-operator"
}

func lifecycleOperation(operation string) bool {
	switch operation {
	case "create", "activate", "add-key", "revoke-key", "update-services", "deactivate":
		return true
	}
	return false
}

func decodeAdmin(raw []byte) (adminRequest, error) {
	var result adminRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return result, registry010.ErrRejected
	}
	seen := map[string]bool{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || seen[key] {
			return result, registry010.ErrRejected
		}
		seen[key] = true
		var value string
		if decoder.Decode(&value) != nil {
			return result, registry010.ErrRejected
		}
		switch key {
		case "registry":
			result.Registry = value
		case "did":
			result.DID = value
		case "candidate":
			result.Candidate = value
		case "expected_version":
			result.ExpectedVersion = value
		case "operation":
			result.Operation = value
		case "target_operator":
			result.TargetOperator = value
		case "scope":
			result.Scope = value
		default:
			return result, registry010.ErrRejected
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') ||
		decoder.Decode(new(any)) != io.EOF || !seen["registry"] || !seen["did"] ||
		!seen["expected_version"] || !seen["operation"] {
		return result, registry010.ErrRejected
	}
	if managementOperation(result.Operation) {
		if len(seen) != 6 || !seen["target_operator"] || !seen["scope"] || seen["candidate"] {
			return result, registry010.ErrRejected
		}
	} else if !lifecycleOperation(result.Operation) || len(seen) != 5 || !seen["candidate"] ||
		seen["target_operator"] || seen["scope"] {
		return result, registry010.ErrRejected
	}
	return result, nil
}

func (s *Server) Admin(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 ||
		r.Host != s.admin || r.URL.RawPath != "" || r.URL.RawQuery != "" {
		http.Error(w, "write rejected", http.StatusForbidden)
		return
	}
	fingerprint := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	if r.Method == http.MethodGet && r.URL.Path == "/admin/registry/inspection" {
		s.inspect(w, r, fingerprint)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/admin/registry" {
		http.Error(w, "write rejected", http.StatusForbidden)
		return
	}
	actor := s.actors[fingerprint]
	if actor == "" {
		http.Error(w, "write rejected", http.StatusForbidden)
		return
	}
	if values := r.Header.Values("Content-Type"); len(values) != 1 || values[0] != "application/json" ||
		len(r.Header.Values("Content-Encoding")) != 0 || len(r.TransferEncoding) != 0 ||
		len(r.Trailer) != 0 || r.ContentLength < 0 || r.ContentLength > maxAdminBody ||
		r.Header.Get("Expect") != "" {
		http.Error(w, "write rejected", http.StatusBadRequest)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxAdminBody+1))
	if err != nil || len(raw) > maxAdminBody || int64(len(raw)) != r.ContentLength || len(r.Trailer) != 0 {
		http.Error(w, "write rejected", http.StatusBadRequest)
		return
	}
	request, err := decodeAdmin(raw)
	if err != nil || request.Registry != s.source || request.DID != s.did {
		http.Error(w, "write rejected", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uncertain {
		http.Error(w, "write rejected", http.StatusServiceUnavailable)
		return
	}
	ctx := context.WithValue(r.Context(), actorContextKey{}, actor)
	if managementOperation(request.Operation) {
		if len(s.journal.Inspect().History) == 0 {
			http.Error(w, "write rejected", http.StatusConflict)
			return
		}
		err = registry010.ApplyWebRegistryOperatorCommand010(ctx, s.journal, s.source, s.did,
			s.now().Unix(), request.ExpectedVersion, request.Operation, request.TargetOperator, request.Scope)
	} else {
		var candidate []byte
		candidate, err = base64.RawURLEncoding.Strict().DecodeString(request.Candidate)
		if err != nil || len(candidate) == 0 || len(candidate) > 69632 {
			http.Error(w, "write rejected", http.StatusBadRequest)
			return
		}
		err = registry010.ApplyWebRegistryWrite010(ctx, s.journal, s.source, s.did,
			candidate, s.now().Unix(), request.ExpectedVersion, request.Operation)
	}
	if err != nil {
		if errors.Is(err, registry010.ErrUnreachable) {
			if _, readError := s.journal.PublicEnvelope010(s.did, s.source, s.now().Unix()); readError != nil {
				s.uncertain = true
			}
		}
		status := http.StatusServiceUnavailable
		if errors.Is(err, registry010.ErrRejected) || errors.Is(err, registry010.ErrInvalidRecord010) {
			status = http.StatusForbidden
		} else if errors.Is(err, registry010.ErrStale) {
			status = http.StatusConflict
		}
		http.Error(w, "write rejected", status)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) inspect(w http.ResponseWriter, r *http.Request, pin [32]byte) {
	if _, allowed := s.inspectors[pin]; !allowed || r.ContentLength != 0 ||
		len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 ||
		len(r.Header.Values("Content-Encoding")) != 0 || r.Header.Get("Expect") != "" {
		http.Error(w, "inspection rejected", http.StatusForbidden)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uncertain {
		http.Error(w, "inspection unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, err := s.journal.PublicEnvelope010(s.did, s.source, s.now().Unix()); err != nil {
		http.Error(w, "inspection unavailable", http.StatusServiceUnavailable)
		return
	}
	state := s.journal.Inspect()
	if len(state.History) == 0 {
		http.Error(w, "inspection unavailable", http.StatusServiceUnavailable)
		return
	}
	var latest struct {
		Record struct {
			Version string `json:"version"`
		} `json:"record"`
	}
	if json.Unmarshal(state.Envelope, &latest) != nil || latest.Record.Version == "" {
		http.Error(w, "inspection unavailable", http.StatusServiceUnavailable)
		return
	}
	response, err := json.Marshal(struct {
		Registry   string                                    `json:"registry"`
		DID        string                                    `json:"did"`
		Version    string                                    `json:"version"`
		Grants     []registry010.WebRegistryOperatorGrant010 `json:"grants"`
		History    []registry010.WebRegistryHistoryEntry010  `json:"history"`
		Tombstoned bool                                      `json:"tombstoned"`
	}{s.source, s.did, latest.Record.Version, state.Grants, state.History, state.Tombstoned})
	if err != nil {
		http.Error(w, "inspection unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}
