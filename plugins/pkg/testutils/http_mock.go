package testutils

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
)

func NewMockServer(rotate bool, responses ...string) *httptest.Server {
	mock := &mockHandler{
		rotate:    rotate,
		responses: responses,
	}

	server := httptest.NewServer(mock)
	return server
}

type mockHandler struct {
	rotate    bool
	responses []string
	lock      sync.Mutex
}

type MockServer struct {
	mux       *http.ServeMux
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
