// Package proxy terminates TLS and forwards the resulting HTTP requests to
// an Orbitport gateway.
package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

const (
	defaultListenAddr = "127.0.0.1:8443"
	defaultTargetURL  = "http://127.0.0.1:8080"
)

// Config describes the public TLS listener and the internal Orbitport target.
type Config struct {
	ListenAddr string
	TargetURL  string
	// CurvePreferences is optional. An empty value uses Go's TLS defaults;
	// tests set it explicitly to verify classical and hybrid key exchanges.
	CurvePreferences []tls.CurveID
}

// Server is a TLS-terminating HTTP reverse proxy.
type Server struct {
	httpServer *http.Server
}

// New validates cfg and creates a proxy. The backend may use HTTP because it is
// expected to be inside the same trusted environment as the proxy.
func New(cfg Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = defaultListenAddr
	}
	if cfg.TargetURL == "" {
		cfg.TargetURL = defaultTargetURL
	}
	target, err := url.Parse(cfg.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("parse target URL: %w", err)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("target URL scheme must be http or https, got %q", target.Scheme)
	}
	if target.Host == "" {
		return nil, errors.New("target URL must include a host")
	}
	certificate, err := newEphemeralCertificate(time.Now())
	if err != nil {
		return nil, err
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target)
			request.SetXForwarded()
		},
		ErrorHandler: func(writer http.ResponseWriter, request *http.Request, proxyErr error) {
			log.Printf("TLS proxy request failed method=%s path=%s: %v", request.Method, request.URL.Path, proxyErr)
			http.Error(writer, "Orbitport gateway unavailable", http.StatusBadGateway)
		},
	}

	return &Server{
		httpServer: &http.Server{
			Addr:              cfg.ListenAddr,
			Handler:           proxy,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       90 * time.Second,
			TLSConfig: &tls.Config{
				MinVersion:       tls.VersionTLS13,
				CurvePreferences: cfg.CurvePreferences,
				Certificates:     []tls.Certificate{certificate},
			},
			ErrorLog: log.New(os.Stderr, "tlsproxy: ", log.LstdFlags),
		},
	}, nil
}

// ListenAndServe listens on the address from Config and serves HTTPS traffic.
func (s *Server) ListenAndServe() error {
	return s.httpServer.ListenAndServeTLS("", "")
}
