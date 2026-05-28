package account

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

type staticTokens struct {
	value string
	err   error
}

func (s staticTokens) token(context.Context) (string, error) { return s.value, s.err }

func newTestClient(t *testing.T, handler http.Handler) (*dashboardClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	cfg := &accountConfig{
		DashboardURL:    srv.URL,
		HTTPTimeoutSecs: 5,
	}
	return newDashboardClient(cfg, staticTokens{value: "test-token"}), srv
}

func TestDashboardClient_Hold_Success(t *testing.T) {
	var capturedAuth string
	var capturedPath string
	var capturedBody holdRequestBody

	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &capturedBody)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ledgerId":"ledger-abc","balance":42}`))
	}))
	defer srv.Close()

	ledgerID, balance, err := client.Hold(context.Background(), "client-x", 2, "trng")
	require.NoError(t, err)
	require.Equal(t, "ledger-abc", ledgerID)
	require.Equal(t, int64(42), balance)
	require.Equal(t, "Bearer test-token", capturedAuth)
	require.Equal(t, "/service/credits/hold", capturedPath)
	require.Equal(t, "client-x", capturedBody.ClientID)
	require.Equal(t, uint32(2), capturedBody.Units)
	require.Equal(t, "trng", capturedBody.Operation)
}

func TestDashboardClient_Hold_Accepts201(t *testing.T) {
	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ledgerId":"ledger-201","balance":7}`))
	}))
	defer srv.Close()

	ledgerID, balance, err := client.Hold(context.Background(), "client-x", 1, "trng")
	require.NoError(t, err)
	require.Equal(t, "ledger-201", ledgerID)
	require.Equal(t, int64(7), balance)
}

func TestDashboardClient_Release_Accepts201(t *testing.T) {
	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"balance":11}`))
	}))
	defer srv.Close()

	balance, err := client.Release(context.Background(), "ledger-abc")
	require.NoError(t, err)
	require.Equal(t, int64(11), balance)
}

func TestDashboardClient_Hold_InsufficientCredits(t *testing.T) {
	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"code":"INSUFFICIENT_CREDITS","message":"out of credits"}`))
	}))
	defer srv.Close()

	_, _, err := client.Hold(context.Background(), "client-x", 1, "trng")
	require.ErrorIs(t, err, ErrInsufficientCredits)
}

func TestDashboardClient_Hold_OtherErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"500", http.StatusInternalServerError, `{"error":"boom"}`},
		{"401", http.StatusUnauthorized, ``},
		{"422_other_code", http.StatusUnprocessableEntity, `{"code":"OTHER"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, _, err := client.Hold(context.Background(), "client-x", 1, "trng")
			require.Error(t, err)
			require.False(t, errors.Is(err, ErrInsufficientCredits))
		})
	}
}

func TestDashboardClient_Release_Success(t *testing.T) {
	var capturedPath string

	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"balance":43}`))
	}))
	defer srv.Close()

	balance, err := client.Release(context.Background(), "ledger-abc")
	require.NoError(t, err)
	require.Equal(t, int64(43), balance)
	require.Equal(t, "/service/credits/hold/ledger-abc/release", capturedPath)
}

func TestDashboardClient_Release_Error(t *testing.T) {
	client, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := client.Release(context.Background(), "ledger-abc")
	require.Error(t, err)
}

func TestDashboardClient_NoToken_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("should not reach server when token is missing")
	}))
	defer srv.Close()

	cfg := &accountConfig{DashboardURL: srv.URL, HTTPTimeoutSecs: 5}
	client := newDashboardClient(cfg, staticTokens{err: errors.New("no token")})

	_, _, err := client.Hold(context.Background(), "client-x", 1, "trng")
	require.Error(t, err)
}
