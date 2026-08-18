package threshold

import (
	"context"
	"fmt"
	"testing"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

func TestCoordinatorCoordinatesThresholdSigning(t *testing.T) {
	nodeIDs := []string{"node-a", "node-b"}
	clients := map[string]*fakeSignClient{
		"node-a": newFakeSignClient("node-a", nodeIDs),
		"node-b": newFakeSignClient("node-b", nodeIDs),
	}
	participants := []DKGParticipant{
		{NodeID: "node-a", PartyIndex: 0, Client: clients["node-a"]},
		{NodeID: "node-b", PartyIndex: 1, Client: clients["node-b"]},
	}

	result, err := NewCoordinator(
		WithSessionSecret([]byte("test-threshold-session-secret")),
	).CoordinateSign(context.Background(), SignRequest{
		KeyName:      "key-1",
		GroupName:    "team-a",
		SessionID:    "sign-1",
		Message:      "aGVsbG8=",
		Threshold:    2,
		Participants: participants,
	})
	if err != nil {
		t.Fatalf("CoordinateSign() error = %v", err)
	}
	if result.Signature != "aggregate-signature" {
		t.Fatalf("signature = %q, want aggregate-signature", result.Signature)
	}
	if len(result.Nodes) != 2 {
		t.Fatalf("node statuses = %d, want 2", len(result.Nodes))
	}
	for nodeID, status := range result.Nodes {
		if status.Status != signStatusCompleted {
			t.Fatalf("node %s status = %q, want %q", nodeID, status.Status, signStatusCompleted)
		}
	}

	commonSeed := clients["node-a"].start.CommonSeed
	if commonSeed == "" {
		t.Fatal("expected signing common seed to be sent to node-a")
	}
	for _, client := range clients {
		if client.start.CommonSeed != commonSeed {
			t.Fatalf("node %s received different signing common seed", client.nodeID)
		}
	}

	leftStart := clients["node-a"].start
	rightStart := clients["node-b"].start
	if leftStart.PairwiseSeeds["node-b"] == "" ||
		leftStart.PairwiseSeeds["node-b"] != rightStart.PairwiseSeeds["node-a"] {
		t.Fatal("signing pairwise seed was not shared symmetrically")
	}
	for _, client := range clients {
		for round := 1; round <= 4; round++ {
			assertSignDeliveriesByRound(t, client, round, len(clients)-1)
		}
	}
}

func TestPluginCoordinateSign(t *testing.T) {
	nodeIDs := []string{"node-a", "node-b"}
	clients := map[string]*fakeSignClient{
		"node-a": newFakeSignClient("node-a", nodeIDs),
		"node-b": newFakeSignClient("node-b", nodeIDs),
	}
	plugin := newPlugin(
		&thresholdConfig{TimeoutSecs: 10, SessionSecret: "test-threshold-session-secret"},
		NewCoordinator(WithSessionSecret([]byte("test-threshold-session-secret"))),
	)
	plugin.newClient = func(member *proto.GroupMember) GroupMemberClient {
		return clients[member.NodeId]
	}

	resp, err := plugin.CoordinateSign(context.Background(), &proto.ThresholdSignRequest{
		KeyName:   "key-1",
		GroupName: "team-a",
		SessionId: "sign-1",
		Message:   "aGVsbG8=",
		Threshold: 2,
		Participants: []*proto.GroupMember{
			{NodeId: "node-b", PartyIndex: 1, OpenbaoUrl: "http://node-b"},
			{NodeId: "node-a", PartyIndex: 0, OpenbaoUrl: "http://node-a"},
		},
	})
	if err != nil {
		t.Fatalf("CoordinateSign() error = %v", err)
	}
	if resp.KeyName != "key-1" || resp.GroupName != "team-a" || resp.SessionId != "sign-1" {
		t.Fatalf("unexpected response identity: %+v", resp)
	}
	if resp.Signature != "aggregate-signature" {
		t.Fatalf("signature = %q, want aggregate-signature", resp.Signature)
	}
	if len(resp.Nodes) != 2 {
		t.Fatalf("node statuses = %d, want 2", len(resp.Nodes))
	}
}

type fakeSignClient struct {
	nodeID     string
	peers      []string
	start      StartSignRequest
	deliveries []DeliverSignRequest
}

func newFakeSignClient(nodeID string, allNodeIDs []string) *fakeSignClient {
	client := &fakeSignClient{nodeID: nodeID}
	for _, candidate := range allNodeIDs {
		if candidate != nodeID {
			client.peers = append(client.peers, candidate)
		}
	}
	return client
}

func (c *fakeSignClient) StartSign(_ context.Context, req StartSignRequest) (*SignStatus, error) {
	c.start = req
	return c.roundStatus(1), nil
}

func (c *fakeSignClient) DeliverSign(_ context.Context, _ string, req DeliverSignRequest) (*SignStatus, error) {
	c.deliveries = append(c.deliveries, req)
	return &SignStatus{
		Name:      "key-1",
		SessionID: "sign-1",
		NodeID:    c.nodeID,
		Status:    fmt.Sprintf("sign_waiting_round_%d_inputs", req.Round),
	}, nil
}

func (c *fakeSignClient) ProceedSign(_ context.Context, _ string, round int) (*SignStatus, error) {
	if round == 5 {
		return &SignStatus{
			Name:             "key-1",
			SessionID:        "sign-1",
			NodeID:           c.nodeID,
			Status:           signStatusCompleted,
			Round:            5,
			PartialSignature: "partial:" + c.nodeID,
		}, nil
	}
	return c.roundStatus(round), nil
}

func (c *fakeSignClient) ReadSignStatus(context.Context, string) (*SignStatus, error) {
	return nil, nil
}

func (c *fakeSignClient) AggregateSign(_ context.Context, _ string, message string, partialSignatures map[string]string) (*SignStatus, error) {
	if message != "aGVsbG8=" || len(partialSignatures) != 2 {
		return nil, fmt.Errorf("unexpected aggregate request")
	}
	return &SignStatus{Status: signStatusCompleted, Signature: "aggregate-signature"}, nil
}

func (c *fakeSignClient) roundStatus(round int) *SignStatus {
	unicasts := make(map[string]string, len(c.peers))
	for _, peer := range c.peers {
		unicasts[peer] = fmt.Sprintf("sign-unicast:%d:%s:%s", round, c.nodeID, peer)
	}
	status := &SignStatus{
		Name:      "key-1",
		SessionID: "sign-1",
		NodeID:    c.nodeID,
		Status:    fmt.Sprintf("sign_waiting_round_%d_inputs", round),
		Round:     round,
		Unicasts:  unicasts,
	}
	if round >= 3 {
		status.Broadcast = fmt.Sprintf("sign-broadcast:%d:%s", round, c.nodeID)
	}
	return status
}

func assertSignDeliveriesByRound(t *testing.T, client *fakeSignClient, round, want int) {
	t.Helper()

	count := 0
	for _, delivery := range client.deliveries {
		if delivery.Round != round {
			continue
		}
		count++
		wantUnicast := fmt.Sprintf("sign-unicast:%d:%s:%s", round, delivery.From, client.nodeID)
		if delivery.Unicast != wantUnicast {
			t.Fatalf("%s round %d unicast = %q, want %q", client.nodeID, round, delivery.Unicast, wantUnicast)
		}
	}
	if count != want {
		t.Fatalf("%s round %d deliveries = %d, want %d", client.nodeID, round, count, want)
	}
}

func (*fakeSignClient) StartDKG(context.Context, StartDKGRequest) (*DKGStatus, error) {
	return nil, fmt.Errorf("unexpected DKG call")
}

func (*fakeSignClient) DeliverDKG(context.Context, string, DeliverDKGRequest) (*DKGStatus, error) {
	return nil, fmt.Errorf("unexpected DKG call")
}

func (*fakeSignClient) ProceedDKG(context.Context, string, int) (*DKGStatus, error) {
	return nil, fmt.Errorf("unexpected DKG call")
}

func (*fakeSignClient) ReadDKGStatus(context.Context, string) (*DKGStatus, error) {
	return nil, fmt.Errorf("unexpected DKG call")
}
