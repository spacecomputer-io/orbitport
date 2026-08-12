package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProxyForwardsHTTPWithX25519(t *testing.T) {
	t.Parallel()
	// Use the classical TLS key exchange.
	testProxyFlow(t, tls.X25519)
}

func TestProxyForwardsHTTPWithX25519MLKEM768(t *testing.T) {
	t.Parallel()
	// Use Go's hybrid post-quantum TLS key exchange.
	testProxyFlow(t, tls.X25519MLKEM768)
}

func testProxyFlow(t *testing.T, keyExchange tls.CurveID) {
	t.Helper()

	// Orbitport is represented by a plain HTTP backend.
	backendURL, requestSeen := startFakeOrbitport(t)

	// The proxy accepts TLS and forwards requests to Orbitport.
	proxyURL, client := startTestProxy(t, Config{
		TargetURL:        backendURL,
		CurvePreferences: []tls.CurveID{keyExchange},
	})

	// The client calls Orbitport through the TLS proxy.
	response, err := client.Get(proxyURL + "/healthz?source=tls-proxy-test")
	if err != nil {
		t.Fatalf("GET through TLS proxy: %v", err)
	}
	defer response.Body.Close()

	assertTLSResponse(t, response, keyExchange)
	assertForwardedRequest(t, requestSeen)
}

func startFakeOrbitport(t *testing.T) (string, <-chan *http.Request) {
	t.Helper()

	requestSeen := make(chan *http.Request, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestSeen <- request.Clone(request.Context())
		_, _ = io.WriteString(writer, `{"status":"ok"}`)
	}))
	t.Cleanup(backend.Close)

	return backend.URL, requestSeen
}

func startTestProxy(t *testing.T, config Config) (string, *http.Client) {
	t.Helper()

	server, err := New(config)
	if err != nil {
		t.Fatalf("create TLS proxy: %v", err)
	}

	testServer := httptest.NewUnstartedServer(server.httpServer.Handler)
	testServer.TLS = server.httpServer.TLSConfig
	testServer.StartTLS()
	t.Cleanup(testServer.Close)

	client := testServer.Client()
	client.Timeout = 5 * time.Second
	client.Transport.(*http.Transport).TLSClientConfig.CurvePreferences = config.CurvePreferences

	return testServer.URL, client
}

func assertTLSResponse(t *testing.T, response *http.Response, expectedKeyExchange tls.CurveID) {
	t.Helper()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: got %d, want %d", response.StatusCode, http.StatusOK)
	}
	if string(body) != `{"status":"ok"}` {
		t.Fatalf("unexpected body: got %q", body)
	}
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 {
		t.Fatal("client did not establish a TLS 1.3 connection")
	}
	if response.TLS.CurveID != expectedKeyExchange {
		t.Fatalf("unexpected TLS key exchange: got %v, want %v", response.TLS.CurveID, expectedKeyExchange)
	}
}

func assertForwardedRequest(t *testing.T, requestSeen <-chan *http.Request) {
	t.Helper()

	request := <-requestSeen
	if request.TLS != nil {
		t.Fatal("backend unexpectedly received TLS instead of internal HTTP")
	}
	if request.URL.Path != "/healthz" {
		t.Fatalf("unexpected forwarded path: %q", request.URL.Path)
	}
	if request.URL.RawQuery != "source=tls-proxy-test" {
		t.Fatalf("unexpected forwarded query: %q", request.URL.RawQuery)
	}
	if got := request.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("unexpected X-Forwarded-Proto: got %q, want https", got)
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		targetURL string
	}{
		{
			name:      "malformed target URL",
			targetURL: "://orbitport",
		},
		{
			name:      "target without host",
			targetURL: "http:///api",
		},
		{
			name:      "unsupported target scheme",
			targetURL: "ftp://orbitport:8080",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(Config{TargetURL: test.targetURL}); err == nil {
				t.Fatal("New succeeded with invalid configuration")
			}
		})
	}
}

func TestNewGeneratesFreshEphemeralServerCertificate(t *testing.T) {
	t.Parallel()

	first, err := New(Config{})
	if err != nil {
		t.Fatalf("create first TLS proxy: %v", err)
	}
	second, err := New(Config{})
	if err != nil {
		t.Fatalf("create second TLS proxy: %v", err)
	}

	firstTLSCertificate := first.httpServer.TLSConfig.Certificates[0]
	secondTLSCertificate := second.httpServer.TLSConfig.Certificates[0]
	if bytes.Equal(firstTLSCertificate.Certificate[0], secondTLSCertificate.Certificate[0]) {
		t.Fatal("two proxy starts generated the same certificate")
	}

	certificate := firstTLSCertificate.Leaf
	if certificate == nil {
		t.Fatal("generated certificate was not parsed")
	}
	if certificate.Subject.CommonName != "Orbitport TLS proxy" {
		t.Fatalf("unexpected certificate common name: %q", certificate.Subject.CommonName)
	}
	if certificate.IsCA {
		t.Fatal("generated server certificate is unexpectedly a CA")
	}
	if certificate.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatalf("unexpected certificate signature algorithm: %v", certificate.SignatureAlgorithm)
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve.Params().Name != "P-256" {
		t.Fatalf("generated certificate does not use ECDSA P-256: %T", certificate.PublicKey)
	}
	if err := certificate.VerifyHostname("localhost"); err != nil {
		t.Fatalf("generated certificate is not valid for localhost: %v", err)
	}
	if err := certificate.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("generated certificate is not valid for loopback: %v", err)
	}
	if err := certificate.CheckSignature(
		certificate.SignatureAlgorithm,
		certificate.RawTBSCertificate,
		certificate.Signature,
	); err != nil {
		t.Fatalf("generated certificate is not self-signed: %v", err)
	}
}
