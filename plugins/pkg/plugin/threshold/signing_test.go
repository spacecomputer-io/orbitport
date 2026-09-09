package threshold

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

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
	const clientID = "client-a"
	scopedKeyName := tenantScopedKeyName(clientID, "key-1")
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
		ClientId:  clientID,
		Participants: []*proto.GroupMember{
			{NodeId: "node-b", PartyIndex: 1, OpenbaoUrl: "http://node-b"},
			{NodeId: "node-a", PartyIndex: 0, OpenbaoUrl: "http://node-a"},
		},
	})
	if err != nil {
		t.Fatalf("CoordinateSign() error = %v", err)
	}
	if resp.KeyName != scopedKeyName || resp.GroupName != "team-a" || resp.SessionId != "sign-1" {
		t.Fatalf("unexpected response identity: %+v", resp)
	}
	for nodeID, client := range clients {
		if client.start.KeyName != scopedKeyName {
			t.Fatalf("node %s key name = %q, want %q", nodeID, client.start.KeyName, scopedKeyName)
		}
		if client.start.GroupName != "team-a" {
			t.Fatalf("node %s group name = %q, want team-a", nodeID, client.start.GroupName)
		}
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
	readDKG    func(context.Context, string) (*DKGStatus, error)
	startErr   error
	lastStatus *SignStatus
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
	if c.startErr != nil {
		return nil, c.startErr
	}
	c.start = req
	c.peers = nil
	for _, nodeID := range req.Participants {
		if nodeID != c.nodeID {
			c.peers = append(c.peers, nodeID)
		}
	}
	c.lastStatus = c.roundStatus(1)
	return c.lastStatus, nil
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
		c.lastStatus = &SignStatus{
			Name:             c.start.KeyName,
			SessionID:        c.start.SessionID,
			NodeID:           c.nodeID,
			Status:           signStatusCompleted,
			Round:            5,
			PartialSignature: "partial:" + c.nodeID,
		}
		return c.lastStatus, nil
	}
	c.lastStatus = c.roundStatus(round)
	return c.lastStatus, nil
}

func (c *fakeSignClient) ReadSignStatus(_ context.Context, keyName string) (*SignStatus, error) {
	if keyName != c.start.KeyName || c.lastStatus == nil {
		return nil, fmt.Errorf("unknown signing key %q", keyName)
	}
	return c.lastStatus, nil
}

func (c *fakeSignClient) AggregateSign(_ context.Context, _ string, message string, partialSignatures map[string]string) (*SignStatus, error) {
	if message != c.start.Message || len(partialSignatures) != len(c.start.Participants) {
		return nil, fmt.Errorf("unexpected aggregate request")
	}
	for _, nodeID := range c.start.Participants {
		if partialSignatures[nodeID] != "partial:"+nodeID {
			return nil, fmt.Errorf("unexpected partial signature for %s", nodeID)
		}
	}
	return &SignStatus{Status: signStatusCompleted, Signature: "aggregate-signature"}, nil
}

func (c *fakeSignClient) roundStatus(round int) *SignStatus {
	unicasts := make(map[string]string, len(c.peers))
	for _, peer := range c.peers {
		unicasts[peer] = fmt.Sprintf("sign-unicast:%d:%s:%s", round, c.nodeID, peer)
	}
	status := &SignStatus{
		Name:      c.start.KeyName,
		SessionID: c.start.SessionID,
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
		wantBroadcast := ""
		if round >= 3 {
			wantBroadcast = fmt.Sprintf("sign-broadcast:%d:%s", round, delivery.From)
		}
		if delivery.Broadcast != wantBroadcast {
			t.Fatalf("%s round %d broadcast = %q, want %q", client.nodeID, round, delivery.Broadcast, wantBroadcast)
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

func (c *fakeSignClient) ReadDKGStatus(ctx context.Context, keyName string) (*DKGStatus, error) {
	if c.readDKG != nil {
		return c.readDKG(ctx, keyName)
	}
	return &DKGStatus{
		Name: keyName, Group: "team-a", NodeID: c.nodeID,
		Status: keyStatusCompleted, PublicKey: "group-public-key",
	}, nil
}

func (n *fakeThresholdNode) handleSignStart(w http.ResponseWriter, r *http.Request) {
	if n.consumeFailure(w, "sign/start") {
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "expected JSON POST", http.StatusBadRequest)
		return
	}

	var body struct {
		Group         string `json:"group"`
		SessionID     string `json:"session_id"`
		Message       string `json:"message"`
		Participants  string `json:"participants"`
		CommonSeed    string `json:"common_seed"`
		PairwiseSeeds string `json:"pairwise_seeds"`
	}
	mustDecodeJSON(r, &body)
	req := StartSignRequest{
		KeyName: n.keyName, GroupName: body.Group, SessionID: body.SessionID,
		Message: body.Message, CommonSeed: body.CommonSeed,
	}
	if err := json.Unmarshal([]byte(body.Participants), &req.Participants); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal([]byte(body.PairwiseSeeds), &req.PairwiseSeeds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	status, err := n.sign.StartSign(r.Context(), req)
	writeSignResponse(w, status, err)
}

func (n *fakeThresholdNode) handleSignDeliver(w http.ResponseWriter, r *http.Request) {
	if n.consumeFailure(w, "sign/deliver") {
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "expected JSON POST", http.StatusBadRequest)
		return
	}

	var req DeliverSignRequest
	mustDecodeJSON(r, &req)

	n.mu.Lock()
	defer n.mu.Unlock()
	status, err := n.sign.DeliverSign(r.Context(), n.keyName, req)
	writeSignResponse(w, status, err)
}

func (n *fakeThresholdNode) handleSignProceed(w http.ResponseWriter, r *http.Request) {
	if n.consumeFailure(w, "sign/proceed") {
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "expected JSON POST", http.StatusBadRequest)
		return
	}

	var req struct {
		Round int `json:"round"`
	}
	mustDecodeJSON(r, &req)

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.sign.lastStatus == nil || req.Round != n.sign.lastStatus.Round+1 {
		http.Error(w, fmt.Sprintf("unexpected signing round %d", req.Round), http.StatusBadRequest)
		return
	}
	status, err := n.sign.ProceedSign(r.Context(), n.keyName, req.Round)
	writeSignResponse(w, status, err)
}

func (n *fakeThresholdNode) handleSignStatus(w http.ResponseWriter, r *http.Request) {
	if n.consumeFailure(w, "sign/status") {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	status, err := n.sign.ReadSignStatus(r.Context(), n.keyName)
	writeSignResponse(w, status, err)
}

func (n *fakeThresholdNode) handleSignAggregate(w http.ResponseWriter, r *http.Request) {
	if n.consumeFailure(w, "sign/aggregate") {
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "expected JSON POST", http.StatusBadRequest)
		return
	}

	var req struct {
		Message           string `json:"message"`
		PartialSignatures string `json:"partial_signatures"`
	}
	mustDecodeJSON(r, &req)
	var partials map[string]string
	if err := json.Unmarshal([]byte(req.PartialSignatures), &partials); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	status, err := n.sign.AggregateSign(r.Context(), n.keyName, req.Message, partials)
	writeSignResponse(w, status, err)
}

func writeSignResponse(w http.ResponseWriter, status *SignStatus, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeOpenBaoResponse(w, status)
}

func TestPluginCoordinatesOpenBaoSigning(t *testing.T) {
	for _, unavailableFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("unavailable_first=%t", unavailableFirst), func(t *testing.T) {
			const clientID = "client-a"
			keyName := tenantScopedKeyName(clientID, "key-1")
			nodeIDs := []string{"node-a", "node-b", "node-c"}
			nodes := make(map[string]*fakeThresholdNode, len(nodeIDs))
			var members []*proto.GroupMember
			for i, nodeID := range nodeIDs {
				node := newFakeThresholdNode(t, nodeID, nodeIDs)
				node.keyName = keyName
				nodes[nodeID] = node
				members = append(members, &proto.GroupMember{
					NodeId: nodeID, PartyIndex: int32(i), OpenbaoUrl: node.server.URL, Mount: "threshold",
				})
			}
			prepareFakeThresholdNodes(t, nodes, newTestGroupConfig())
			plugin := newPlugin(
				&thresholdConfig{TimeoutSecs: 10},
				NewCoordinator(WithSessionSecret([]byte("test-threshold-session-secret")), WithRetryPolicy(2, 0)),
			)
			if _, err := plugin.CoordinateDkg(context.Background(), &proto.DkgRequest{
				KeyName: "key-1", GroupName: "team-a", SessionId: "dkg-1",
				Threshold: 2, ClientId: clientID, Participants: members,
			}); err != nil {
				t.Fatalf("CoordinateDkg() error = %v", err)
			}

			selected := nodeIDs[:2]
			if unavailableFirst {
				nodes["node-a"].failNext("status", 2)
				selected = nodeIDs[1:]
			}
			// Exercise retries through the real HTTP client for every signing write.
			nodes[selected[0]].failNext("sign/start", 1)
			nodes[selected[1]].failNext("sign/deliver", 1)
			nodes[selected[0]].failNext("sign/proceed", 1)
			nodes[selected[0]].failNext("sign/aggregate", 1)
			resp, err := plugin.CoordinateSign(context.Background(), &proto.ThresholdSignRequest{
				KeyName: "key-1", GroupName: "team-a", SessionId: "sign-1", Message: "aGVsbG8=",
				Threshold: 2, ClientId: clientID, Participants: members,
			})
			if err != nil {
				t.Fatalf("CoordinateSign() error = %v", err)
			}
			if resp.Signature != "aggregate-signature" || resp.KeyName != keyName ||
				resp.GroupName != "team-a" || resp.SessionId != "sign-1" || len(resp.Nodes) != 2 {
				t.Fatalf("unexpected signing response: %+v", resp)
			}
			for i, nodeID := range selected {
				node := nodes[nodeID]
				if resp.Nodes[i].NodeId != nodeID || resp.Nodes[i].Status != signStatusCompleted {
					t.Fatalf("unexpected selected node status: %+v", resp.Nodes[i])
				}
				start := node.sign.start
				if start.KeyName != keyName || start.GroupName != "team-a" || start.SessionID != "sign-1" ||
					start.Message != "aGVsbG8=" || !reflect.DeepEqual(start.Participants, selected) {
					t.Fatalf("unexpected HTTP signing start on %s: %+v", nodeID, start)
				}
				peerID := selected[1-i]
				if start.CommonSeed == "" || start.CommonSeed != nodes[peerID].sign.start.CommonSeed ||
					len(start.PairwiseSeeds) != 1 || start.PairwiseSeeds[peerID] == "" ||
					start.PairwiseSeeds[peerID] != nodes[peerID].sign.start.PairwiseSeeds[nodeID] {
					t.Fatalf("incorrect signing bootstrap on %s", nodeID)
				}
				for round := 1; round <= 4; round++ {
					assertSignDeliveriesByRound(t, node.sign, round, 1)
				}
				status, err := node.client.ReadSignStatus(context.Background(), keyName)
				if err != nil {
					t.Fatalf("ReadSignStatus() error = %v", err)
				}
				if status.Name != keyName || status.SessionID != "sign-1" || status.NodeID != nodeID ||
					status.Status != signStatusCompleted || status.PartialSignature != "partial:"+nodeID {
					t.Fatalf("unexpected HTTP signing status: %+v", status)
				}
			}
			for _, nodeID := range nodeIDs {
				if nodeID != selected[0] && nodeID != selected[1] && nodes[nodeID].sign.start.SessionID != "" {
					t.Fatalf("unselected node %s started signing", nodeID)
				}
			}
		})
	}
}

func TestCoordinatorSelectsAvailableSigningQuorum(t *testing.T) {
	for _, scenario := range []string{"unavailable", "unresponsive", "incomplete", "wrong key", "wrong group", "wrong node", "no public key", "different public key", "insufficient quorum", "canceled", "failure after selection"} {
		t.Run(scenario, func(t *testing.T) {
			nodeIDs := []string{"node-a", "node-b", "node-c"}
			clients := make(map[string]*fakeSignClient)
			var participants []DKGParticipant
			for i, nodeID := range nodeIDs {
				clients[nodeID] = newFakeSignClient(nodeID, nodeIDs)
				participants = append(participants, DKGParticipant{NodeID: nodeID, PartyIndex: i, Client: clients[nodeID]})
			}
			ctx := context.Background()
			wantError := ""
			switch scenario {
			case "unavailable", "insufficient quorum":
				clients["node-a"].readDKG = func(context.Context, string) (*DKGStatus, error) {
					return nil, &OpenBaoStatusError{StatusCode: http.StatusServiceUnavailable}
				}
				if scenario == "insufficient quorum" {
					clients["node-b"].readDKG = clients["node-a"].readDKG
					wantError = "only 1 signing participants"
				}
			case "unresponsive":
				clients["node-a"].readDKG = func(ctx context.Context, _ string) (*DKGStatus, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				wantError = "context canceled"
			case "failure after selection":
				clients["node-b"].startErr = &OpenBaoStatusError{StatusCode: http.StatusServiceUnavailable}
				wantError = "start signing on"
			default:
				status, _ := clients["node-a"].ReadDKGStatus(ctx, "key-1")
				switch scenario {
				case "incomplete":
					status.Status = "waiting_round_1"
				case "wrong key":
					status.Name = "another-key"
				case "wrong group":
					status.Group = "another-group"
				case "wrong node":
					status.NodeID = "another-node"
				case "no public key":
					status.PublicKey = ""
				case "different public key":
					status.PublicKey = "another-public-key"
					wantError = "different group public key"
				}
				clients["node-a"].readDKG = func(context.Context, string) (*DKGStatus, error) { return status, nil }
			}

			result, err := NewCoordinator(
				WithSessionSecret([]byte("test-threshold-session-secret")), WithRetryPolicy(2, 0),
			).CoordinateSign(ctx, SignRequest{
				KeyName: "key-1", GroupName: "team-a", SessionID: "sign-1", Message: "aGVsbG8=",
				Threshold: 2, Participants: participants,
			})
			if wantError != "" {
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("CoordinateSign() error = %v, want %q", err, wantError)
				}
				for nodeID, client := range clients {
					if scenario == "failure after selection" && nodeID == "node-a" {
						continue
					}
					if client.start.SessionID != "" {
						t.Fatalf("unexpected signing start on %s", nodeID)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("CoordinateSign() error = %v", err)
			}
			if len(result.Nodes) != 2 || result.Signature != "aggregate-signature" {
				t.Fatalf("unexpected signing result: %+v", result)
			}
			if _, exists := result.Nodes["node-a"]; exists || clients["node-a"].start.SessionID != "" {
				t.Fatal("unavailable node-a was selected")
			}
			for _, nodeID := range nodeIDs[1:] {
				if !reflect.DeepEqual(clients[nodeID].start.Participants, nodeIDs[1:]) {
					t.Fatalf("unexpected quorum on %s: %v", nodeID, clients[nodeID].start.Participants)
				}
			}
		})
	}
}

func TestCallWithRetry(t *testing.T) {
	for _, scenario := range []string{"transient", "permanent", "exhausted", "canceled before call", "canceled during backoff"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			coordinator := NewCoordinator(WithRetryPolicy(3, 0))
			wantCalls := 1
			wantCode := http.StatusBadRequest
			wantCanceled := false
			switch scenario {
			case "transient", "exhausted":
				wantCalls = 3
				wantCode = http.StatusServiceUnavailable
			case "canceled before call":
				cancel()
				wantCalls = 0
				wantCanceled = true
			case "canceled during backoff":
				coordinator.retryBackoff = time.Hour
				wantCode = http.StatusServiceUnavailable
				wantCanceled = true
			}
			calls := 0
			result, err := callWithRetry(ctx, coordinator, "test", func() (*SignStatus, error) {
				calls++
				if scenario == "transient" && calls == 3 {
					return &SignStatus{Status: signStatusCompleted}, nil
				}
				if scenario == "canceled during backoff" {
					cancel()
				}
				return nil, &OpenBaoStatusError{StatusCode: wantCode}
			})
			if calls != wantCalls {
				t.Fatalf("calls = %d, want %d", calls, wantCalls)
			}
			if scenario == "transient" {
				if err != nil || result == nil || result.Status != signStatusCompleted {
					t.Fatalf("result = %+v, error = %v", result, err)
				}
			} else if wantCanceled {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("error = %v, want context.Canceled", err)
				}
			} else {
				var statusErr *OpenBaoStatusError
				if !errors.As(err, &statusErr) || statusErr.StatusCode != wantCode {
					t.Fatalf("error = %v, want HTTP %d", err, wantCode)
				}
			}
		})
	}
}
