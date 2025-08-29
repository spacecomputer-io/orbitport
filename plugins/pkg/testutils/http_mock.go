package testutils

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
)

func NewMockServer(rotate bool, responses ...string) *WrappedHTTPTestServer {
	mock := &mockHandler{
		rotate:    rotate,
		responses: responses,
	}

	server := httptest.NewServer(mock)
	return &WrappedHTTPTestServer{Server: server}
}

type mockHandler struct {
	rotate    bool
	responses []string
	lock      sync.Mutex
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if len(m.responses) == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp := m.responses[0]
	_, _ = fmt.Fprint(w, resp)

	m.responses = m.responses[1:]
	if m.rotate {
		m.responses = append(m.responses, resp)
	}
}

type WrappedHTTPTestServer struct {
	*httptest.Server
}

// ListenAndServe just prints the URL (since httptest.Server already runs)
func (w *WrappedHTTPTestServer) ListenAndServe(addr string) {
	fmt.Println("Mock server running at:", w.Server.URL)
	select {} // block forever for CLI
}
