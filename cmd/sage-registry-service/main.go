package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sage-x-project/sage-registry-service/registry"
)

type fileConfig struct {
	PublicListen   string            `json:"public_listen"`
	AdminListen    string            `json:"admin_listen"`
	PublicCertFile string            `json:"public_cert_file"`
	PublicKeyFile  string            `json:"public_key_file"`
	AdminCertFile  string            `json:"admin_cert_file"`
	AdminKeyFile   string            `json:"admin_key_file"`
	ClientCAFile   string            `json:"client_ca_file"`
	ClientActors   map[string]string `json:"client_actors"`
	JournalPath    string            `json:"journal_path"`
	DID            string            `json:"did"`
	Source         string            `json:"source"`
	AdminHost      string            `json:"admin_host"`
	Create         bool              `json:"create"`
}

func readConfig(path string) (fileConfig, error) {
	var cfg fileConfig
	file, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() > 65536 {
		return cfg, errors.New("invalid configuration size")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF {
		return cfg, errors.New("invalid configuration")
	}
	if cfg.PublicListen == "" || cfg.AdminListen == "" ||
		cfg.DID == "" || cfg.Source == "" || cfg.AdminHost == "" || len(cfg.ClientActors) == 0 ||
		!filepath.IsAbs(cfg.JournalPath) || !filepath.IsAbs(cfg.PublicCertFile) ||
		!filepath.IsAbs(cfg.PublicKeyFile) || !filepath.IsAbs(cfg.AdminCertFile) ||
		!filepath.IsAbs(cfg.AdminKeyFile) || !filepath.IsAbs(cfg.ClientCAFile) {
		return cfg, errors.New("incomplete configuration")
	}
	return cfg, nil
}

func loadCertificate(certPath, keyPath, name string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil || len(cert.Certificate) == 0 {
		return cert, errors.New("invalid TLS certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf.VerifyHostname(name) != nil {
		return cert, errors.New("TLS certificate does not match the configured host")
	}
	return cert, nil
}

func actors(values map[string]string) (map[[32]byte]string, error) {
	result := make(map[[32]byte]string, len(values))
	for text, actor := range values {
		raw, err := hex.DecodeString(text)
		if err != nil || len(raw) != 32 || actor == "" {
			return nil, errors.New("invalid client certificate mapping")
		}
		var pin [32]byte
		copy(pin[:], raw)
		if _, duplicate := result[pin]; duplicate {
			return nil, errors.New("duplicate client certificate mapping")
		}
		result[pin] = actor
	}
	return result, nil
}

func httpServer(handler http.HandlerFunc) *http.Server {
	return &http.Server{
		Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192,
		DisableGeneralOptionsHandler: true,
		TLSNextProto:                 map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
}

func run(ctx context.Context, cfg fileConfig) error {
	origin, err := url.Parse(cfg.Source)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.Port() != "" ||
		origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("invalid public source")
	}
	publicCert, err := loadCertificate(cfg.PublicCertFile, cfg.PublicKeyFile, origin.Hostname())
	if err != nil {
		return err
	}
	adminCert, err := loadCertificate(cfg.AdminCertFile, cfg.AdminKeyFile, cfg.AdminHost)
	if err != nil {
		return err
	}
	rootPEM, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return errors.New("invalid client CA")
	}
	clientActors, err := actors(cfg.ClientActors)
	if err != nil {
		return err
	}
	publicListener, err := net.Listen("tcp", cfg.PublicListen)
	if err != nil {
		return err
	}
	defer publicListener.Close()
	adminListener, err := net.Listen("tcp", cfg.AdminListen)
	if err != nil {
		return err
	}
	defer adminListener.Close()
	service, err := registry.New(registry.Config{JournalPath: cfg.JournalPath, DID: cfg.DID,
		Source: cfg.Source, AdminHost: cfg.AdminHost, ClientActors: clientActors, Create: cfg.Create})
	if err != nil {
		return err
	}
	publicServer := httpServer(service.Public)
	adminServer := httpServer(service.Admin)
	publicTLS := &tls.Config{Certificates: []tls.Certificate{publicCert}, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}}
	adminTLS := &tls.Config{Certificates: []tls.Certificate{adminCert}, MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, NextProtos: []string{"http/1.1"}}
	ready, _ := json.Marshal(map[string]string{
		"public_addr": publicListener.Addr().String(), "admin_addr": adminListener.Addr().String(),
	})
	fmt.Println(string(ready))
	serverErrors := make(chan error, 2)
	go func() { serverErrors <- publicServer.Serve(tls.NewListener(publicListener, publicTLS)) }()
	go func() { serverErrors <- adminServer.Serve(tls.NewListener(adminListener, adminTLS)) }()
	select {
	case <-ctx.Done():
	case err = <-serverErrors:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	publicError := publicServer.Shutdown(shutdown)
	adminError := adminServer.Shutdown(shutdown)
	if publicError != nil || adminError != nil {
		return errors.New("server shutdown did not complete")
	}
	if closeError := service.Close(); closeError != nil {
		return closeError
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: sage-registry-service CONFIG.json")
		os.Exit(2)
	}
	cfg, err := readConfig(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
