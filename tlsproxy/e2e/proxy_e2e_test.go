//go:build e2e

package e2e

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	expectedChunks          = 3
	readinessTimeout        = 60 * time.Second
	readinessRequestTimeout = 5 * time.Second
	readinessPollInterval   = 500 * time.Millisecond
)

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  ctrngResult     `json:"result"`
	Error   json.RawMessage `json:"error"`
}

type ctrngResult struct {
	Items []ctrngItem `json:"items"`
}

type ctrngItem struct {
	Value string `json:"value"`
}

func TestTLSProxyForwardsRealOrbitportRPC(t *testing.T) {
	// Docker Compose starts the real TLS proxy, gateway, and plugins.
	proxyURL, client := connectToRunningProxy(t)

	// The client calls a real Orbitport RPC through the TLS proxy.
	response := callCTRNGThroughProxy(t, client, proxyURL)
	defer response.Body.Close()

	// The response proves the request reached Orbitport over TLS 1.3.
	assertCTRNGResponse(t, response)
}

func connectToRunningProxy(t *testing.T) (string, *http.Client) {
	t.Helper()

	proxyURL := strings.TrimRight(envOrDefault("ORBITPORT_TLS_PROXY_E2E_URL", "https://localhost:9443"), "/")
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				// The transport-only milestone uses a fresh self-signed
				// certificate on every proxy start. Endpoint identity will be
				// enforced by the later attestation/PSK layer.
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
		Timeout: 30 * time.Second,
	}
	t.Cleanup(client.CloseIdleConnections)
	waitForProxyReadiness(t, client, proxyURL)

	return proxyURL, client
}

func callCTRNGThroughProxy(t *testing.T, client *http.Client, proxyURL string) *http.Response {
	t.Helper()

	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "ctrng.Get",
		"params": map[string]any{
			"chunks": expectedChunks,
		},
	})
	if err != nil {
		t.Fatalf("encode JSON-RPC request: %v", err)
	}

	request, err := http.NewRequest(
		http.MethodPost,
		proxyURL+"/api/v1/rpc",
		bytes.NewReader(payload),
	)
	if err != nil {
		t.Fatalf("create JSON-RPC request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer test_access_token")
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("call Orbitport through TLS proxy: %v", err)
	}
	return response
}

func assertCTRNGResponse(t *testing.T, response *http.Response) {
	t.Helper()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read Orbitport response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Orbitport returned %s through TLS proxy: %s", response.Status, body)
	}
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 {
		t.Fatal("request did not use TLS 1.3")
	}

	var rpc rpcResponse
	if err := json.Unmarshal(body, &rpc); err != nil {
		t.Fatalf("decode Orbitport JSON-RPC response: %v: %s", err, body)
	}
	if len(rpc.Error) != 0 && string(rpc.Error) != "null" {
		t.Fatalf("Orbitport returned JSON-RPC error: %s", rpc.Error)
	}
	if rpc.JSONRPC != "2.0" || rpc.ID != 1 {
		t.Fatalf("unexpected JSON-RPC envelope: jsonrpc=%q id=%d", rpc.JSONRPC, rpc.ID)
	}
	if len(rpc.Result.Items) != expectedChunks {
		t.Fatalf("Orbitport returned %d cTRNG items, want %d: %s", len(rpc.Result.Items), expectedChunks, body)
	}
	for index, item := range rpc.Result.Items {
		if item.Value == "" {
			t.Fatalf("Orbitport cTRNG item %d has an empty value", index)
		}
	}
}

func waitForProxyReadiness(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()

	readinessClient := *client
	readinessClient.Timeout = readinessRequestTimeout
	healthURL := baseURL + "/healthz"
	deadline := time.Now().Add(readinessTimeout)
	var lastFailure string

	for {
		response, err := readinessClient.Get(healthURL)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
			lastFailure = response.Status
		} else {
			lastFailure = err.Error()
		}

		if time.Now().After(deadline) {
			t.Fatalf("TLS proxy did not become ready within %s: %s", readinessTimeout, lastFailure)
		}
		time.Sleep(readinessPollInterval)
	}
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
