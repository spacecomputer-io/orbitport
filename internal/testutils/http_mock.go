package testutils

import (
	"fmt"
	"net/http"
	"sync"
)

func NewMockServer(rotate bool, responses ...string) *mockServer {
	mux := http.NewServeMux()
	return &mockServer{
		mux:       mux,
		rotate:    rotate,
		responses: responses,
	}
}

type mockServer struct {
	mux       *http.ServeMux
	rotate    bool
	responses []string
	lock      sync.Mutex
}

func (m *mockServer) ListenAndServe(addr string) {
	m.mux.Handle("/", m)
	_ = http.ListenAndServe(addr, m.mux)
}

func (m *mockServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if len(m.responses) == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp := m.responses[0]
	fmt.Fprint(w, resp)
	m.responses = m.responses[1:]
	if m.rotate {
		m.responses = append(m.responses, resp)
	}
}
