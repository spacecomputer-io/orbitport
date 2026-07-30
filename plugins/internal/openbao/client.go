// Package openbao provides the HTTP request plumbing shared by plugins
// that talk to an OpenBao server (kms, threshold).
package openbao

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type StatusError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("openbao returned %s", e.Status)
	}
	return fmt.Sprintf("openbao returned %s: %s", e.Status, e.Body)
}

// Logger is the subset of *utils.Logger used by the client. A nil logger
// disables request logging.
type Logger interface {
	Debugf(format string, args ...interface{})
	Warnf(format string, args ...interface{})
}

type Client struct {
	httpClient *http.Client
	logger     Logger
}

func NewClient(httpClient *http.Client, logger Logger) *Client {
	return &Client{httpClient: httpClient, logger: logger}
}

func (c *Client) Post(ctx context.Context, target string, payload any, into any) error {
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

func (c *Client) Get(ctx context.Context, target string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("create openbao request: %w", err)
	}
	return c.do(req, into)
}

func (c *Client) do(req *http.Request, into any) error {
	if c.logger != nil {
		c.logger.Debugf("OpenBao request %s %s", req.Method, req.URL.Path)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if c.logger != nil {
			c.logger.Warnf("OpenBao request failed %s %s: %v", req.Method, req.URL.Path, err)
		}
		return fmt.Errorf("openbao request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if c.logger != nil {
			c.logger.Warnf("failed reading OpenBao response body for %s %s: %v", req.Method, req.URL.Path, err)
		}
		return fmt.Errorf("read openbao response: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		if c.logger != nil {
			c.logger.Warnf("OpenBao returned %s for %s %s", resp.Status, req.Method, req.URL.Path)
		}
		return &StatusError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       strings.TrimSpace(string(body)),
		}
	}
	if into == nil {
		return nil
	}
	if err := json.Unmarshal(body, into); err != nil {
		if c.logger != nil {
			c.logger.Warnf("failed decoding OpenBao response for %s %s: %v", req.Method, req.URL.Path, err)
		}
		return fmt.Errorf("decode openbao response: %w", err)
	}
	return nil
}
