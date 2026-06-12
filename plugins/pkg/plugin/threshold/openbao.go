package threshold

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/internal/openbao"
)

type OpenBaoClientConfig struct {
	BaseURL    string
	Mount      string
	HTTPClient *http.Client
	Timeout    time.Duration
}

type OpenBaoClient struct {
	*openbao.Client
	baseURL string
	mount   string
}

type OpenBaoStatusError = openbao.StatusError

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
		Client:  openbao.NewClient(client, logger),
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		mount:   mount,
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
	if err := c.Post(ctx, c.thresholdPath("keys", req.KeyName, "dkg", "start"), body, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *OpenBaoClient) DeliverDKG(ctx context.Context, keyName string, req DeliverDKGRequest) (*DKGStatus, error) {
	var resp openBaoDataResponse[DKGStatus]
	err := c.Post(ctx, c.thresholdPath("keys", keyName, "dkg", "deliver"), map[string]any{
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
	if err := c.Post(ctx, c.thresholdPath("keys", keyName, "dkg", "proceed"), map[string]any{}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *OpenBaoClient) ReadDKGStatus(ctx context.Context, keyName string) (*DKGStatus, error) {
	var resp openBaoDataResponse[DKGStatus]
	if err := c.Get(ctx, c.thresholdPath("keys", keyName, "dkg", "status"), &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *OpenBaoClient) thresholdPath(parts ...string) string {
	all := append([]string{"v1", c.mount}, parts...)
	target, err := url.JoinPath(c.baseURL, all...)
	if err != nil {
		return strings.TrimRight(c.baseURL, "/") + "/" + strings.Join(all, "/")
	}
	return target
}

type openBaoDataResponse[T any] struct {
	Data T `json:"data"`
}
