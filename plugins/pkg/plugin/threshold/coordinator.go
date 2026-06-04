package threshold

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

type Coordinator struct {
	random    io.Reader
	seedBytes int
}

type CoordinatorOption func(*Coordinator)

func NewCoordinator(options ...CoordinatorOption) *Coordinator {
	c := &Coordinator{
		random:    rand.Reader,
		seedBytes: defaultSeedBytes,
	}
	for _, option := range options {
		option(c)
	}
	return c
}

func WithRandomSource(random io.Reader) CoordinatorOption {
	return func(c *Coordinator) {
		if random != nil {
			c.random = random
		}
	}
}

func (c *Coordinator) CoordinateDKG(ctx context.Context, req DKGRequest) (*DKGResult, error) {
	bootstrap, err := c.newDKGBootstrap(req.Participants)
	if err != nil {
		return nil, err
	}

	round1, err := startDKG(ctx, req, req.Participants, bootstrap)
	if err != nil {
		return nil, err
	}
	if err := deliverRound(ctx, req.KeyName, req.Participants, round1, 1); err != nil {
		return nil, err
	}

	round2, err := proceedRound(ctx, req.KeyName, req.Participants, 2)
	if err != nil {
		return nil, err
	}
	if err := deliverRound(ctx, req.KeyName, req.Participants, round2, 2); err != nil {
		return nil, err
	}

	round3, err := proceedRound(ctx, req.KeyName, req.Participants, 3)
	if err != nil {
		return nil, err
	}
	if err := deliverRound(ctx, req.KeyName, req.Participants, round3, 3); err != nil {
		return nil, err
	}

	completed, err := proceedRound(ctx, req.KeyName, req.Participants, 4)
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

func (c *Coordinator) newDKGBootstrap(participants []DKGParticipant) (*dkgBootstrap, error) {
	commonSeed, err := c.newSeed()
	if err != nil {
		return nil, fmt.Errorf("create common seed: %w", err)
	}

	pairwiseSeedsByNode := make(map[string]map[string]string, len(participants))
	for _, participant := range participants {
		pairwiseSeedsByNode[participant.NodeID] = make(map[string]string, len(participants)-1)
	}

	for i, left := range participants {
		for _, right := range participants[i+1:] {
			seed, err := c.newSeed()
			if err != nil {
				return nil, fmt.Errorf("create pairwise seed for %q/%q: %w", left.NodeID, right.NodeID, err)
			}
			pairwiseSeedsByNode[left.NodeID][right.NodeID] = seed
			pairwiseSeedsByNode[right.NodeID][left.NodeID] = seed
		}
	}

	return &dkgBootstrap{
		commonSeed:          commonSeed,
		pairwiseSeedsByNode: pairwiseSeedsByNode,
	}, nil
}

func (c *Coordinator) newSeed() (string, error) {
	seed := make([]byte, c.seedBytes)
	if _, err := io.ReadFull(c.random, seed); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(seed), nil
}

func startDKG(ctx context.Context, req DKGRequest, participants []DKGParticipant, bootstrap *dkgBootstrap) (map[string]DKGStatus, error) {
	outputs := make(map[string]DKGStatus, len(participants))
	for _, participant := range participants {
		status, err := participant.Client.StartDKG(ctx, StartDKGRequest{
			KeyName:       req.KeyName,
			GroupName:     req.GroupName,
			SessionID:     req.SessionID,
			CommonSeed:    bootstrap.commonSeed,
			PairwiseSeeds: bootstrap.pairwiseSeedsByNode[participant.NodeID],
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

func proceedRound(ctx context.Context, keyName string, participants []DKGParticipant, round int) (map[string]DKGStatus, error) {
	outputs := make(map[string]DKGStatus, len(participants))
	for _, participant := range participants {
		status, err := participant.Client.ProceedDKG(ctx, keyName)
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

func deliverRound(ctx context.Context, keyName string, participants []DKGParticipant, outputs map[string]DKGStatus, round int) error {
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

			if _, err := receiver.Client.DeliverDKG(ctx, keyName, DeliverDKGRequest{
				Round:     round,
				From:      sender.NodeID,
				Broadcast: output.Broadcast,
				Unicast:   unicast,
			}); err != nil {
				return fmt.Errorf("deliver round %d from %q to %q: %w", round, sender.NodeID, receiver.NodeID, err)
			}
		}
	}
	return nil
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
