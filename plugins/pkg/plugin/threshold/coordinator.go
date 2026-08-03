package threshold

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	defaultRetryAttempts = 3
	defaultRetryBackoff  = 100 * time.Millisecond
)

type Coordinator struct {
	seedBytes     int
	sessionSecret []byte
	retryAttempts int
	retryBackoff  time.Duration
}

type CoordinatorOption func(*Coordinator)

func NewCoordinator(options ...CoordinatorOption) *Coordinator {
	c := &Coordinator{
		seedBytes:     defaultSeedBytes,
		retryAttempts: defaultRetryAttempts,
		retryBackoff:  defaultRetryBackoff,
	}
	for _, option := range options {
		option(c)
	}
	return c
}

func WithRetryPolicy(attempts int, backoff time.Duration) CoordinatorOption {
	return func(c *Coordinator) {
		if attempts > 0 {
			c.retryAttempts = attempts
		}
		c.retryBackoff = backoff
	}
}

func WithSessionSecret(secret []byte) CoordinatorOption {
	return func(c *Coordinator) {
		if len(secret) != 0 {
			c.sessionSecret = append([]byte(nil), secret...)
		}
	}
}

func (c *Coordinator) CoordinateDKG(ctx context.Context, req DKGRequest) (*DKGResult, error) {
	bootstrap, err := c.newDKGBootstrap(req)
	if err != nil {
		return nil, err
	}

	round1, err := c.startDKG(ctx, req, req.Participants, bootstrap)
	if err != nil {
		return nil, err
	}
	if err := c.deliverRound(ctx, req.KeyName, req.Participants, round1, 1); err != nil {
		return nil, err
	}

	round2, err := c.proceedRound(ctx, req.KeyName, req.Participants, 2)
	if err != nil {
		return nil, err
	}
	if err := c.deliverRound(ctx, req.KeyName, req.Participants, round2, 2); err != nil {
		return nil, err
	}

	round3, err := c.proceedRound(ctx, req.KeyName, req.Participants, 3)
	if err != nil {
		return nil, err
	}
	if err := c.deliverRound(ctx, req.KeyName, req.Participants, round3, 3); err != nil {
		return nil, err
	}

	completed, err := c.proceedRound(ctx, req.KeyName, req.Participants, 4)
	if err != nil {
		return nil, err
	}
	var publicKey string
	for nodeID, status := range completed {
		if status.Status != keyStatusCompleted {
			return nil, fmt.Errorf("node %q completed round 4 with status %q", nodeID, status.Status)
		}
		if status.PublicKey == "" {
			return nil, fmt.Errorf("node %q completed DKG without a public key", nodeID)
		}
		if publicKey == "" {
			publicKey = status.PublicKey
		} else if status.PublicKey != publicKey {
			return nil, fmt.Errorf("node %q derived a different group public key than its peers", nodeID)
		}
	}

	return &DKGResult{
		KeyName:   req.KeyName,
		GroupName: req.GroupName,
		SessionID: req.SessionID,
		PublicKey: publicKey,
		Nodes:     completed,
	}, nil
}

type dkgBootstrap struct {
	commonSeed          string
	pairwiseSeedsByNode map[string]map[string]string
}

func (c *Coordinator) newDKGBootstrap(req DKGRequest) (*dkgBootstrap, error) {
	if len(c.sessionSecret) == 0 {
		return nil, fmt.Errorf("threshold session secret is required")
	}

	commonSeed := c.deriveSeed(req.SessionID, req.KeyName, "common")
	pairwiseSeedsByNode := make(map[string]map[string]string, len(req.Participants))
	for _, participant := range req.Participants {
		pairwiseSeedsByNode[participant.NodeID] = make(map[string]string, len(req.Participants)-1)
	}

	for i, left := range req.Participants {
		for _, right := range req.Participants[i+1:] {
			seed := c.deriveSeed(req.SessionID, req.KeyName, "pairwise:"+left.NodeID+":"+right.NodeID)
			pairwiseSeedsByNode[left.NodeID][right.NodeID] = seed
			pairwiseSeedsByNode[right.NodeID][left.NodeID] = seed
		}
	}

	return &dkgBootstrap{
		commonSeed:          commonSeed,
		pairwiseSeedsByNode: pairwiseSeedsByNode,
	}, nil
}

func (c *Coordinator) deriveSeed(sessionID, keyName, label string) string {
	mac := hmac.New(sha512.New, c.sessionSecret)
	_, _ = mac.Write([]byte("orbitport-threshold-bootstrap"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(sessionID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(keyName))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(label))
	sum := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum[:c.seedBytes])
}

func (c *Coordinator) startDKG(ctx context.Context, req DKGRequest, participants []DKGParticipant, bootstrap *dkgBootstrap) (map[string]DKGStatus, error) {
	outputs := make(map[string]DKGStatus, len(participants))
	for _, participant := range participants {
		status, err := c.callWithRetry(ctx, fmt.Sprintf("start dkg on %q", participant.NodeID), func() (*DKGStatus, error) {
			return participant.Client.StartDKG(ctx, StartDKGRequest{
				KeyName:       req.KeyName,
				GroupName:     req.GroupName,
				SessionID:     req.SessionID,
				CommonSeed:    bootstrap.commonSeed,
				PairwiseSeeds: bootstrap.pairwiseSeedsByNode[participant.NodeID],
			})
		})
		if err != nil {
			return nil, fmt.Errorf("start dkg on %q: %w", participant.NodeID, err)
		}
		if err := requireRoundOutput(participant.NodeID, status, 1); err != nil {
			return nil, err
		}
		outputs[participant.NodeID] = *status
	}
	return outputs, nil
}

func (c *Coordinator) proceedRound(ctx context.Context, keyName string, participants []DKGParticipant, round int) (map[string]DKGStatus, error) {
	outputs := make(map[string]DKGStatus, len(participants))
	for _, participant := range participants {
		status, err := c.callWithRetry(ctx, fmt.Sprintf("proceed dkg round %d on %q", round, participant.NodeID), func() (*DKGStatus, error) {
			return participant.Client.ProceedDKG(ctx, keyName, round)
		})
		if err != nil {
			return nil, fmt.Errorf("proceed dkg round %d on %q: %w", round, participant.NodeID, err)
		}
		if round < 4 {
			if err := requireRoundOutput(participant.NodeID, status, round); err != nil {
				return nil, err
			}
		}
		outputs[participant.NodeID] = *status
	}
	return outputs, nil
}

func (c *Coordinator) deliverRound(ctx context.Context, keyName string, participants []DKGParticipant, outputs map[string]DKGStatus, round int) error {
	for _, receiver := range participants {
		for _, sender := range participants {
			if sender.NodeID == receiver.NodeID {
				continue
			}

			output, ok := outputs[sender.NodeID]
			if !ok {
				return fmt.Errorf("missing round %d output for %q", round, sender.NodeID)
			}
			unicast := ""
			if round == 2 {
				unicast = output.Unicasts[receiver.NodeID]
				if unicast == "" {
					return fmt.Errorf("missing round 2 unicast from %q to %q", sender.NodeID, receiver.NodeID)
				}
			}

			if _, err := c.callWithRetry(ctx, fmt.Sprintf("deliver round %d from %q to %q", round, sender.NodeID, receiver.NodeID), func() (*DKGStatus, error) {
				return receiver.Client.DeliverDKG(ctx, keyName, DeliverDKGRequest{
					Round:     round,
					From:      sender.NodeID,
					Broadcast: output.Broadcast,
					Unicast:   unicast,
				})
			}); err != nil {
				return fmt.Errorf("deliver round %d from %q to %q: %w", round, sender.NodeID, receiver.NodeID, err)
			}
		}
	}
	return nil
}

func (c *Coordinator) callWithRetry(ctx context.Context, operation string, call func() (*DKGStatus, error)) (*DKGStatus, error) {
	attempts := c.retryAttempts
	if attempts < 1 {
		attempts = 1
	}

	for attempt := 1; ; attempt++ {
		status, err := call()
		if err == nil {
			return status, nil
		}
		if attempt >= attempts || !isRetryableOpenBaoError(err) {
			return nil, err
		}

		delay := c.retryBackoff * time.Duration(attempt)
		logger.Warnf("%s failed on attempt %d/%d: %v; retrying in %s", operation, attempt, attempts, err, delay)
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, fmt.Errorf("retry canceled: %w", ctx.Err())
			}
		}
	}
}

func isRetryableOpenBaoError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var statusErr *OpenBaoStatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode == http.StatusRequestTimeout ||
			statusErr.StatusCode == http.StatusTooManyRequests ||
			statusErr.StatusCode >= http.StatusInternalServerError
	}

	return true
}

func requireRoundOutput(nodeID string, status *DKGStatus, round int) error {
	if status == nil {
		return fmt.Errorf("node %q returned nil round %d status", nodeID, round)
	}
	if status.Round != round {
		return fmt.Errorf("node %q returned round %d, expected %d", nodeID, status.Round, round)
	}
	if status.Broadcast == "" {
		return fmt.Errorf("node %q returned empty round %d broadcast", nodeID, round)
	}
	if round == 2 && len(status.Unicasts) == 0 {
		return fmt.Errorf("node %q returned no round 2 unicasts", nodeID)
	}
	return nil
}
