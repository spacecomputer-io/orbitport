package openbao

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type recordingLogger struct {
	debug []string
	warn  []string
}

func (l *recordingLogger) Debugf(format string, args ...interface{}) {
	l.debug = append(l.debug, fmt.Sprintf(format, args...))
}

func (l *recordingLogger) Warnf(format string, args ...interface{}) {
	l.warn = append(l.warn, fmt.Sprintf(format, args...))
}

func TestErrorStatusLogLevel(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantWarn bool
	}{
		{"missing entry or empty list", http.StatusNotFound, `{"errors":[]}`, false},
		{"routing error", http.StatusNotFound, `{"errors":["no handler for route \"x\""]}`, true},
		{"404 without error list", http.StatusNotFound, ``, true},
		{"permission denied", http.StatusForbidden, `{"errors":["permission denied"]}`, true},
		{"server error", http.StatusInternalServerError, `{"errors":[]}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			logger := &recordingLogger{}
			err := NewClient(server.Client(), logger).List(context.Background(), server.URL+"/v1/kv/metadata/x", nil)

			var statusErr *StatusError
			if !errors.As(err, &statusErr) || statusErr.StatusCode != tc.status {
				t.Fatalf("expected StatusError %d, got %v", tc.status, err)
			}
			if gotWarn := len(logger.warn) > 0; gotWarn != tc.wantWarn {
				t.Fatalf("warn logged = %v, want %v (warn=%q)", gotWarn, tc.wantWarn, logger.warn)
			}
		})
	}
}
