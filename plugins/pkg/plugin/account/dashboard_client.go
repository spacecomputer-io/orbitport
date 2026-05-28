package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
)

// ErrInsufficientCredits is returned by dashboardClient.Hold when the
// dashboard responds with HTTP 422 + code=INSUFFICIENT_CREDITS.
var ErrInsufficientCredits = errors.New("insufficient_credits")

// dashboardClient is a typed HTTP wrapper around the dashboard backend's
// service credit endpoints. It attaches an Auth0 M2M bearer token on every
// request and applies a per-request timeout.
type dashboardClient struct {
	baseURL    string
	httpClient *http.Client
	tokens     tokenProvider
	logger     *utils.Logger
}

// tokenProvider is the subset of tokenManager the dashboard client depends on.
// Lets tests inject a static token without standing up an Auth0 mock.
type tokenProvider interface {
	token(ctx context.Context) (string, error)
}

type holdRequestBody struct {
	ClientID  string `json:"clientId"`
	Units     uint32 `json:"units"`
	Operation string `json:"operation,omitempty"`
}

type holdResponseBody struct {
	LedgerID string `json:"ledgerId"`
	Balance  int64  `json:"balance"`
}

type releaseResponseBody struct {
	Balance int64 `json:"balance"`
}

type dashboardErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func newDashboardClient(cfg *accountConfig, tokens tokenProvider) *dashboardClient {
	return &dashboardClient{
		baseURL: strings.TrimRight(cfg.DashboardURL, "/"),
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.HTTPTimeoutSecs) * time.Second,
		},
		tokens: tokens,
		logger: utils.GetLogger("orbitport:account:dashboard"),
	}
}

// Hold posts to /service/credits/hold. Returns ErrInsufficientCredits on 422,
// or a wrapped transport error on any other non-2xx.
func (d *dashboardClient) Hold(ctx context.Context, clientID string, units uint32, operation string) (string, int64, error) {
	body, err := json.Marshal(holdRequestBody{ClientID: clientID, Units: units, Operation: operation})
	if err != nil {
		return "", 0, fmt.Errorf("marshal hold request: %w", err)
	}

	req, err := d.newRequest(ctx, http.MethodPost, "/service/credits/hold", body)
	if err != nil {
		return "", 0, err
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("dashboard hold transport error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	rawBody, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		var parsed holdResponseBody
		if err := json.Unmarshal(rawBody, &parsed); err != nil {
			return "", 0, fmt.Errorf("decode hold response: %w", err)
		}
		if parsed.LedgerID == "" {
			return "", 0, fmt.Errorf("dashboard hold response missing ledgerId")
		}
		return parsed.LedgerID, parsed.Balance, nil
	case http.StatusUnprocessableEntity:
		var parsed dashboardErrorBody
		_ = json.Unmarshal(rawBody, &parsed)
		if parsed.Code == "INSUFFICIENT_CREDITS" {
			return "", 0, ErrInsufficientCredits
		}
		return "", 0, fmt.Errorf("dashboard hold rejected (422): %s", strings.TrimSpace(string(rawBody)))
	default:
		return "", 0, fmt.Errorf("dashboard hold returned %d: %s", resp.StatusCode, strings.TrimSpace(string(rawBody)))
	}
}

// Release posts to /service/credits/hold/:ledgerId/release. 4xx responses are
// logged and returned as errors so callers can distinguish "tried" from "ok".
// The endpoint is idempotent on the backend.
func (d *dashboardClient) Release(ctx context.Context, ledgerID string) (int64, error) {
	path := "/service/credits/hold/" + ledgerID + "/release"
	req, err := d.newRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return 0, err
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("dashboard release transport error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	rawBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return 0, fmt.Errorf("dashboard release returned %d: %s", resp.StatusCode, strings.TrimSpace(string(rawBody)))
	}

	var parsed releaseResponseBody
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return 0, fmt.Errorf("decode release response: %w", err)
	}
	return parsed.Balance, nil
}

func (d *dashboardClient) newRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	var req *http.Request
	var err error
	if reader != nil {
		req, err = http.NewRequestWithContext(ctx, method, d.baseURL+path, reader)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, d.baseURL+path, http.NoBody)
	}
	if err != nil {
		return nil, fmt.Errorf("build dashboard request: %w", err)
	}

	token, err := d.tokens.token(ctx)
	if err != nil {
		return nil, fmt.Errorf("attach M2M token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}
