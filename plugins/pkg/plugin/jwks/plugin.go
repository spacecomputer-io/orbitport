// Package jwks publishes the issuer plugin's public key set over HTTP.
//
// It exists so the gateway does not have to. The gateway routes and meters the
// JSON-RPC API, and republishing another service's keys is not that job. This
// plugin holds no key material of its own. It caches whatever the issuer plugin
// returns from GetJwks and serves it verbatim.
//
// This is the only plugin that answers requests from the internet, so it serves
// one GET route, never reads a request body, and mounts nothing else on that
// port. Note that the issuer's gRPC service carries IssueToken alongside
// GetJwks and authenticates no caller, so code execution in this pod still
// reaches the mint RPC. The boundary there is network reachability, not the
// client this process holds.
package jwks

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

// Looser than the server-side cache on purpose, so a key rotation reaches
// verifiers without every one of them polling us.
const browserCacheMaxAge = 300

const unavailableBody = `{"error":"issuer_plugin_unavailable"}`

// Plugin serves GET /.well-known/jwks.json from a cached GetJwks response.
type Plugin struct {
	cfg    *jwksConfig
	client proto.IssuerPluginClient
	logger *utils.Logger

	cacheTTL time.Duration
	timeout  time.Duration

	// mu guards the cached body only. It is never held across the network call.
	mu        sync.RWMutex
	cached    string
	fetchedAt time.Time

	// refreshMu collapses concurrent refreshes into a single RPC, so a burst
	// of anonymous requests cannot fan out to the issuer.
	refreshMu sync.Mutex
}

func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(
		cfg.IssuerPlugin,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to issuer plugin: %w", err)
	}

	logger := utils.GetLogger("orbitport:jwks")
	logger.Infof(
		"publishing JWKS from %s on :%d (cache %ds)",
		cfg.IssuerPlugin, cfg.HTTPPort, cfg.CacheTTLSecs,
	)

	return &Plugin{
		cfg:      cfg,
		client:   proto.NewIssuerPluginClient(conn),
		logger:   logger,
		cacheTTL: time.Duration(cfg.CacheTTLSecs) * time.Second,
		timeout:  time.Duration(cfg.TimeoutSecs) * time.Second,
	}, nil
}

func (p *Plugin) HTTPPort() uint16 { return p.cfg.HTTPPort }

// ListenHTTP serves the key set until the listener fails. It never returns nil.
func (p *Plugin) ListenHTTP() error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", p.handleJWKS)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", p.cfg.HTTPPort),
		Handler: mux,
		// This listener faces the internet, so bound every phase of a request
		// rather than inheriting Go's unlimited defaults.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	return srv.ListenAndServe()
}

func (p *Plugin) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	body, err := p.jwks()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		p.logger.Errorf("serving JWKS failed: %v", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(unavailableBody))
		return
	}

	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", browserCacheMaxAge))
	_, _ = w.Write([]byte(body))
}

func (p *Plugin) jwks() (string, error) {
	if body, ok := p.fresh(); ok {
		return body, nil
	}
	return p.refresh()
}

func (p *Plugin) fresh() (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cached, p.cached != "" && time.Since(p.fetchedAt) < p.cacheTTL
}

// refresh fetches the key set with the RPC OUTSIDE the data lock, so a hung
// issuer plugin never serializes readers behind it.
func (p *Plugin) refresh() (string, error) {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()

	// Someone may have refreshed while we waited for the lock.
	if body, ok := p.fresh(); ok {
		return body, nil
	}

	// Deliberately not the request context. One client hanging up would
	// otherwise cancel the refresh that every other waiting request shares.
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	resp, err := p.client.GetJwks(ctx, &proto.GetJwksRequest{})
	if err != nil {
		return "", fmt.Errorf("fetching JWKS from issuer plugin: %w", err)
	}

	// Fail closed. An empty set published as a 200 would read as "this issuer
	// has no keys" and make every verifier reject every PAT.
	if resp.GetJwksJson() == "" {
		return "", fmt.Errorf("issuer plugin returned an empty JWKS")
	}

	p.mu.Lock()
	p.cached, p.fetchedAt = resp.GetJwksJson(), time.Now()
	p.mu.Unlock()

	return resp.GetJwksJson(), nil
}
