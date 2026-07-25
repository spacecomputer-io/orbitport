package main

import (
	gocryptorand "crypto/rand"
	"fmt"
	"net/http"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/testutils"
)

// generateLocalRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func generateLocalRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := gocryptorand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func NewMockCrypto2API(p Profile) HttpServer {
	mux := http.NewServeMux()
	return &crypto2APIMockServer{
		mux: mux,
		p:   p,
	}
}

type crypto2APIMockServer struct {
	mux *http.ServeMux
	p   Profile
}

func (m *crypto2APIMockServer) ListenAndServe(addr string) {
	m.mux.Handle("/", m)
	_ = http.ListenAndServe(addr, m.mux)
}

func (m *crypto2APIMockServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if m.p == PROFILE_OFFLINE {
		fmt.Println("offline profile, returning 503")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	chunkBytes, err := generateLocalRandomBytes(32) // 32 bytes for the chunk
	if err != nil {
		fmt.Printf("failed to generate random chunk: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	signatureBytes, err := generateLocalRandomBytes(64) // 64 bytes for the signature
	if err != nil {
		fmt.Printf("failed to generate random signature: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp := fmt.Sprintf(`[{"chunk":"%x","signature":"%x"}]`, chunkBytes, signatureBytes)
	w.Header().Set("Content-Type", "application/json")
	_, err = fmt.Fprint(w, resp)
	if err != nil {
		fmt.Printf("failed to write response: %v", err)
		return
	}
}

func NewMockCrypto2Auth(p Profile) HttpServer {
	if p == PROFILE_OFFLINE {
		fmt.Println("offline profile, server will return 500")
		return testutils.NewMockServer(false)
	}
	return testutils.NewMockServer(true, `{"access_token": "11111111111111", "expires_in": 3600, "token_type": "Bearer"}`)
}
