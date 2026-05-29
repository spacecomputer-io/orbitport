package threshold

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type OpenBaoClientConfig struct {
	BaseURL    string
	Mount      string
	HTTPClient *http.Client
	Timeout    time.Duration
}

type OpenBaoClient struct {
	baseURL    string
	mount      string
	httpClient *http.Client
}

type OpenBaoStatusError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *OpenBaoStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("openbao returned %s", e.Status)
	}
	return fmt.Sprintf("openbao returned %s: %s", e.Status, e.Body)
}

func NewOpenBaoClient(cfg OpenBaoClientConfig) *OpenBaoClient {
	mount := strings.Trim(cfg.Mount, "/")
	if mount == "" {
		mount = defaultMount
	}

	client := cfg.HTTPClient
	if client == nil {
		timeout := cfg.Timeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}

	return &OpenBaoClient{
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		mount:      mount,
		httpClient: client,
	}
}

func (c *OpenBaoClient) StartDKG(ctx context.Context, req StartDKGRequest) (*DKGStatus, error) {
	pairwiseSeeds, err := json.Marshal(req.PairwiseSeeds)
	if err != nil {
		return nil, fmt.Errorf("marshal pairwise seeds: %w", err)
	}

	body := map[string]any{
		"group":          req.GroupName,
		"session_id":     req.SessionID,
		"common_seed":    req.CommonSeed,
		"pairwise_seeds": string(pairwiseSeeds),
	}
	if req.Algorithm != "" {
		body["algorithm"] = req.Algorithm
	}
	if req.Curve != "" {
		body["curve"] = req.Curve
	}
	if req.KeyEpoch != 0 {
		body["key_epoch"] = req.KeyEpoch
	}

	var resp openBaoDataResponse[DKGStatus]
	if err := c.post(ctx, c.thresholdPath("keys", req.KeyName, "dkg", "start"), body, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *OpenBaoClient) DeliverDKG(ctx context.Context, keyName string, req DeliverDKGRequest) (*DKGStatus, error) {
	var resp openBaoDataResponse[DKGStatus]
	err := c.post(ctx, c.thresholdPath("keys", keyName, "dkg", "deliver"), map[string]any{
		"round":     req.Round,
		"from":      req.From,
		"broadcast": req.Broadcast,
		"unicast":   req.Unicast,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *OpenBaoClient) ProceedDKG(ctx context.Context, keyName string) (*DKGStatus, error) {
	var resp openBaoDataResponse[DKGStatus]
	if err := c.post(ctx, c.thresholdPath("keys", keyName, "dkg", "proceed"), map[string]any{}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *OpenBaoClient) ReadDKGStatus(ctx context.Context, keyName string) (*DKGStatus, error) {
	var resp openBaoDataResponse[DKGStatus]
	if err := c.get(ctx, c.thresholdPath("keys", keyName, "dkg", "status"), &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *OpenBaoClient) thresholdPath(parts ...string) string {
	all := append([]string{"v1", c.mount}, parts...)
	target, _ := url.JoinPath(c.baseURL, all...)
	return target
}

func (c *OpenBaoClient) post(ctx context.Context, target string, payload any, into any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal openbao payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create openbao request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, into)
}

func (c *OpenBaoClient) get(ctx context.Context, target string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("create openbao request: %w", err)
	}
	return c.do(req, into)
}

func (c *OpenBaoClient) do(req *http.Request, into any) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("openbao request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read openbao response: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return &OpenBaoStatusError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       strings.TrimSpace(string(body)),
		}
	}
	if into == nil {
		return nil
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("decode openbao response: %w", err)
	}
	return nil
}

type openBaoDataResponse[T any] struct {
	Data T `json:"data"`
}
