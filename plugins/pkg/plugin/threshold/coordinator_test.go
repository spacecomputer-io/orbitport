package threshold

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestCoordinatorCoordinatesOpenBaoDKGTwoOfThree(t *testing.T) {
	nodeIDs := []string{"node-a", "node-b", "node-c"}
	nodes := make(map[string]*fakeThresholdNode, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		nodes[nodeID] = newFakeThresholdNode(t, nodeID, nodeIDs)
	}

	prepareFakeThresholdNodes(t, nodes, newTestGroupConfig())

	participants := []DKGParticipant{
		{NodeID: "node-a", PartyIndex: 0, Client: nodes["node-a"].client},
		{NodeID: "node-b", PartyIndex: 1, Client: nodes["node-b"].client},
		{NodeID: "node-c", PartyIndex: 2, Client: nodes["node-c"].client},
	}
	coordinator := NewCoordinator(WithSessionSecret([]byte("test-threshold-session-secret")))
	result, err := coordinator.CoordinateDKG(context.Background(), DKGRequest{
		KeyName:      "key-1",
		GroupName:    "team-a",
		SessionID:    "dkg-1",
		Threshold:    2,
		Participants: participants,
	})
	if err != nil {
		t.Fatalf("CoordinateDKG() error = %v", err)
	}
	if result.KeyName != "key-1" || result.GroupName != "team-a" || result.SessionID != "dkg-1" {
		t.Fatalf("unexpected result identity: %+v", result)
	}
	if len(result.Nodes) != 3 {
		t.Fatalf("expected 3 node statuses, got %d", len(result.Nodes))
	}
	for nodeID, status := range result.Nodes {
		if status.Status != keyStatusCompleted {
			t.Fatalf("node %s status = %q, want %q", nodeID, status.Status, keyStatusCompleted)
		}
	}

	commonSeed := nodes["node-a"].commonSeed
	if commonSeed == "" {
		t.Fatal("expected common seed to be sent to node-a")
	}
	for _, node := range nodes {
		if !node.nodeConfigWritten {
			t.Fatalf("node config was not written for %s", node.nodeID)
		}
		if !node.groupWritten {
			t.Fatalf("group was not written for %s", node.nodeID)
		}
		if node.commonSeed != commonSeed {
			t.Fatalf("node %s received different common seed", node.nodeID)
		}
		assertDeliveriesByRound(t, node, 1, 2)
		assertDeliveriesByRound(t, node, 2, 2)
		assertDeliveriesByRound(t, node, 3, 2)
	}

	assertPairwiseSeed(t, nodes, "node-a", "node-b")
	assertPairwiseSeed(t, nodes, "node-a", "node-c")
	assertPairwiseSeed(t, nodes, "node-b", "node-c")
	assertRound2Unicasts(t, nodes)
}

func TestCoordinatorBootstrapIsDeterministicForSameSession(t *testing.T) {
	participants := []DKGParticipant{
		{NodeID: "node-a", PartyIndex: 0},
		{NodeID: "node-b", PartyIndex: 1},
		{NodeID: "node-c", PartyIndex: 2},
	}
	req := DKGRequest{
		KeyName:      "key-1",
		GroupName:    "team-a",
		SessionID:    "dkg-1",
		Threshold:    2,
		Participants: participants,
	}
	coordinator := NewCoordinator(WithSessionSecret([]byte("test-threshold-session-secret")))

	first, err := coordinator.newDKGBootstrap(req)
	if err != nil {
		t.Fatalf("newDKGBootstrap() first error = %v", err)
	}
	second, err := coordinator.newDKGBootstrap(req)
	if err != nil {
		t.Fatalf("newDKGBootstrap() second error = %v", err)
	}
	if first.commonSeed != second.commonSeed {
		t.Fatalf("common seed changed for same session")
	}
	for _, participant := range participants {
		if !reflect.DeepEqual(first.pairwiseSeedsByNode[participant.NodeID], second.pairwiseSeedsByNode[participant.NodeID]) {
			t.Fatalf("pairwise seeds changed for %s", participant.NodeID)
		}
	}

	req.SessionID = "dkg-2"
	third, err := coordinator.newDKGBootstrap(req)
	if err != nil {
		t.Fatalf("newDKGBootstrap() third error = %v", err)
	}
	if first.commonSeed == third.commonSeed {
		t.Fatalf("common seed should differ across sessions")
	}
}

func TestCoordinatorRetriesTransientOpenBaoDKGCalls(t *testing.T) {
	nodeIDs := []string{"node-a", "node-b", "node-c"}
	nodes := make(map[string]*fakeThresholdNode, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		nodes[nodeID] = newFakeThresholdNode(t, nodeID, nodeIDs)
	}

	prepareFakeThresholdNodes(t, nodes, newTestGroupConfig())
	nodes["node-a"].failNext("start", 1)
	nodes["node-b"].failNext("deliver", 1)
	nodes["node-c"].failNext("proceed", 1)

	participants := []DKGParticipant{
		{NodeID: "node-a", PartyIndex: 0, Client: nodes["node-a"].client},
		{NodeID: "node-b", PartyIndex: 1, Client: nodes["node-b"].client},
		{NodeID: "node-c", PartyIndex: 2, Client: nodes["node-c"].client},
	}
	coordinator := NewCoordinator(
		WithSessionSecret([]byte("test-threshold-session-secret")),
		WithRetryPolicy(2, 0),
	)
	result, err := coordinator.CoordinateDKG(context.Background(), DKGRequest{
		KeyName:      "key-1",
		GroupName:    "team-a",
		SessionID:    "dkg-1",
		Threshold:    2,
		Participants: participants,
	})
	if err != nil {
		t.Fatalf("CoordinateDKG() error = %v", err)
	}
	for nodeID, status := range result.Nodes {
		if status.Status != keyStatusCompleted {
			t.Fatalf("node %s status = %q, want %q", nodeID, status.Status, keyStatusCompleted)
		}
	}
}

type testGroupParticipant struct {
	NodeID     string `json:"node_id"`
	PartyIndex int    `json:"party_index"`
}

type testGroupConfig struct {
	Name         string
	Threshold    int
	Participants []testGroupParticipant
}

func newTestGroupConfig() testGroupConfig {
	return testGroupConfig{
		Name:      "team-a",
		Threshold: 2,
		Participants: []testGroupParticipant{
			{NodeID: "node-a", PartyIndex: 0},
			{NodeID: "node-b", PartyIndex: 1},
			{NodeID: "node-c", PartyIndex: 2},
		},
	}
}

func prepareFakeThresholdNodes(t *testing.T, nodes map[string]*fakeThresholdNode, group testGroupConfig) {
	t.Helper()

	participants, err := json.Marshal(group.Participants)
	if err != nil {
		t.Fatalf("marshal group participants: %v", err)
	}

	for _, participant := range group.Participants {
		node := nodes[participant.NodeID]
		if node == nil {
			t.Fatalf("missing fake node %q", participant.NodeID)
		}
		if err := node.client.Post(context.Background(), node.client.thresholdPath("config", "node"), map[string]any{
			"node_id": participant.NodeID,
		}, nil); err != nil {
			t.Fatalf("write node config for %q: %v", participant.NodeID, err)
		}
		if err := node.client.Post(context.Background(), node.client.thresholdPath("groups", group.Name), map[string]any{
			"threshold":    group.Threshold,
			"participants": string(participants),
		}, nil); err != nil {
			t.Fatalf("write group %q on %q: %v", group.Name, participant.NodeID, err)
		}
	}
}

type fakeThresholdNode struct {
	nodeID  string
	keyName string
	peers   []string
	client  *OpenBaoClient
	server  *httptest.Server

	mu                sync.Mutex
	nodeConfigWritten bool
	groupWritten      bool
	commonSeed        string
	pairwiseSeeds     map[string]string
	proceedCalls      int
	deliveries        []DeliverDKGRequest
	failures          map[string]int
}

func newFakeThresholdNode(t *testing.T, nodeID string, allNodeIDs []string) *fakeThresholdNode {
	t.Helper()

	node := &fakeThresholdNode{
		nodeID:        nodeID,
		keyName:       "key-1",
		pairwiseSeeds: make(map[string]string),
		failures:      make(map[string]int),
	}
	for _, peer := range allNodeIDs {
		if peer != nodeID {
			node.peers = append(node.peers, peer)
		}
	}

	node.server = httptest.NewServer(http.HandlerFunc(node.handle))
	t.Cleanup(node.server.Close)
	node.client = NewOpenBaoClient(OpenBaoClientConfig{
		BaseURL: node.server.URL,
		Mount:   "threshold",
	})
	return node
}

func (n *fakeThresholdNode) handle(w http.ResponseWriter, r *http.Request) {
	keyPath := "/v1/threshold/keys/" + n.keyName
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/threshold/config/node":
		n.handleWriteNodeConfig(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/threshold/groups/"):
		n.handleWriteGroup(w, r)
	case r.Method == http.MethodPost && r.URL.Path == keyPath+"/dkg/start":
		n.handleStart(w, r)
	case r.Method == http.MethodPost && r.URL.Path == keyPath+"/dkg/deliver":
		n.handleDeliver(w, r)
	case r.Method == http.MethodPost && r.URL.Path == keyPath+"/dkg/proceed":
		n.handleProceed(w, r)
	case r.Method == http.MethodGet && r.URL.Path == keyPath+"/dkg/status":
		writeOpenBaoData(w, n.status(0, "", nil))
	default:
		http.Error(w, fmt.Sprintf("unexpected request %s %s", r.Method, r.URL.Path), http.StatusNotFound)
	}
}

func (n *fakeThresholdNode) handleWriteNodeConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID string `json:"node_id"`
	}
	mustDecodeJSON(r, &req)
	if req.NodeID != n.nodeID {
		http.Error(w, "node_id does not match fake node", http.StatusBadRequest)
		return
	}

	n.mu.Lock()
	n.nodeConfigWritten = true
	n.mu.Unlock()
	writeOpenBaoData(w, map[string]any{"node_id": n.nodeID})
}

func (n *fakeThresholdNode) handleWriteGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Threshold    int    `json:"threshold"`
		Participants string `json:"participants"`
	}
	mustDecodeJSON(r, &req)

	var participants []testGroupParticipant
	if err := json.Unmarshal([]byte(req.Participants), &participants); err != nil {
		http.Error(w, "invalid participants JSON", http.StatusBadRequest)
		return
	}
	if req.Threshold != 2 || len(participants) != 3 {
		http.Error(w, "unexpected group shape", http.StatusBadRequest)
		return
	}
	for i, participant := range participants {
		if participant.PartyIndex != i {
			http.Error(w, "participants must be sorted by party_index", http.StatusBadRequest)
			return
		}
	}

	n.mu.Lock()
	n.groupWritten = true
	n.mu.Unlock()
	writeOpenBaoData(w, map[string]any{"name": "team-a", "threshold": 2})
}

func (n *fakeThresholdNode) handleStart(w http.ResponseWriter, r *http.Request) {
	if n.consumeFailure(w, "start") {
		return
	}

	var req struct {
		Group         string `json:"group"`
		SessionID     string `json:"session_id"`
		CommonSeed    string `json:"common_seed"`
		PairwiseSeeds string `json:"pairwise_seeds"`
	}
	mustDecodeJSON(r, &req)
	if req.Group != "team-a" || req.SessionID != "dkg-1" {
		http.Error(w, "unexpected dkg start identity", http.StatusBadRequest)
		return
	}

	var pairwiseSeeds map[string]string
	if err := json.Unmarshal([]byte(req.PairwiseSeeds), &pairwiseSeeds); err != nil {
		http.Error(w, "invalid pairwise seeds JSON", http.StatusBadRequest)
		return
	}
	if len(pairwiseSeeds) != len(n.peers) {
		http.Error(w, "unexpected pairwise seed count", http.StatusBadRequest)
		return
	}

	n.mu.Lock()
	n.commonSeed = req.CommonSeed
	n.pairwiseSeeds = pairwiseSeeds
	n.mu.Unlock()
	writeOpenBaoData(w, n.status(1, "round1:"+n.nodeID, nil))
}

func (n *fakeThresholdNode) handleDeliver(w http.ResponseWriter, r *http.Request) {
	if n.consumeFailure(w, "deliver") {
		return
	}

	var req DeliverDKGRequest
	mustDecodeJSON(r, &req)
	if req.Broadcast == "" {
		http.Error(w, "broadcast is required", http.StatusBadRequest)
		return
	}

	n.mu.Lock()
	n.deliveries = append(n.deliveries, req)
	n.mu.Unlock()
	writeOpenBaoData(w, n.status(0, "", nil))
}

func (n *fakeThresholdNode) handleProceed(w http.ResponseWriter, r *http.Request) {
	if n.consumeFailure(w, "proceed") {
		return
	}

	var req struct {
		Round int `json:"round"`
	}
	mustDecodeJSON(r, &req)

	n.mu.Lock()
	n.proceedCalls++
	call := n.proceedCalls
	n.mu.Unlock()

	expectedRound := call + 1
	if req.Round != expectedRound {
		http.Error(w, fmt.Sprintf("proceed round = %d, want %d", req.Round, expectedRound), http.StatusBadRequest)
		return
	}

	switch call {
	case 1:
		if !n.hasDeliveriesForRound(1) {
			http.Error(w, "round 1 deliveries missing", http.StatusBadRequest)
			return
		}
		writeOpenBaoData(w, n.status(2, "round2:"+n.nodeID, n.round2Unicasts()))
	case 2:
		if !n.hasDeliveriesForRound(2) {
			http.Error(w, "round 2 deliveries missing", http.StatusBadRequest)
			return
		}
		writeOpenBaoData(w, n.status(3, "round3:"+n.nodeID, nil))
	case 3:
		if !n.hasDeliveriesForRound(3) {
			http.Error(w, "round 3 deliveries missing", http.StatusBadRequest)
			return
		}
		writeOpenBaoData(w, DKGStatus{
			Name:      n.keyName,
			Group:     "team-a",
			SessionID: "dkg-1",
			NodeID:    n.nodeID,
			Status:    keyStatusCompleted,
			Round:     4,
			PublicKey: "AmNvb3JkaW5hdGVkLWdyb3VwLXB1YmxpYy1rZXk=",
		})
	default:
		http.Error(w, "too many proceed calls", http.StatusBadRequest)
	}
}

func (n *fakeThresholdNode) failNext(operation string, count int) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.failures[operation] += count
}

func (n *fakeThresholdNode) consumeFailure(w http.ResponseWriter, operation string) bool {
	n.mu.Lock()
	remaining := n.failures[operation]
	if remaining > 0 {
		n.failures[operation] = remaining - 1
	}
	n.mu.Unlock()

	if remaining == 0 {
		return false
	}
	http.Error(w, "transient "+operation+" failure", http.StatusInternalServerError)
	return true
}

func (n *fakeThresholdNode) status(round int, broadcast string, unicasts map[string]string) DKGStatus {
	return DKGStatus{
		Name:      n.keyName,
		Group:     "team-a",
		SessionID: "dkg-1",
		NodeID:    n.nodeID,
		Status:    fmt.Sprintf("waiting_round_%d", round),
		Round:     round,
		Broadcast: broadcast,
		Unicasts:  unicasts,
	}
}

func (n *fakeThresholdNode) round2Unicasts() map[string]string {
	unicasts := make(map[string]string, len(n.peers))
	for _, peer := range n.peers {
		unicasts[peer] = fmt.Sprintf("unicast:%s:%s", n.nodeID, peer)
	}
	return unicasts
}

func (n *fakeThresholdNode) hasDeliveriesForRound(round int) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	seen := make(map[string]struct{}, len(n.peers))
	for _, delivery := range n.deliveries {
		if delivery.Round == round {
			seen[delivery.From] = struct{}{}
		}
	}
	return len(seen) == len(n.peers)
}

func mustDecodeJSON(r *http.Request, into any) {
	defer func() {
		_ = r.Body.Close()
	}()
	if err := json.NewDecoder(r.Body).Decode(into); err != nil {
		panic(err)
	}
}

func writeOpenBaoData(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func assertPairwiseSeed(t *testing.T, nodes map[string]*fakeThresholdNode, left, right string) {
	t.Helper()

	leftSeed := nodes[left].pairwiseSeeds[right]
	rightSeed := nodes[right].pairwiseSeeds[left]
	if leftSeed == "" || rightSeed == "" {
		t.Fatalf("missing pairwise seed for %s/%s", left, right)
	}
	if leftSeed != rightSeed {
		t.Fatalf("pairwise seed mismatch for %s/%s", left, right)
	}
}

func assertDeliveriesByRound(t *testing.T, node *fakeThresholdNode, round, want int) {
	t.Helper()

	node.mu.Lock()
	defer node.mu.Unlock()

	got := 0
	for _, delivery := range node.deliveries {
		if delivery.Round == round {
			got++
		}
	}
	if got != want {
		t.Fatalf("node %s round %d deliveries = %d, want %d", node.nodeID, round, got, want)
	}
}

func assertRound2Unicasts(t *testing.T, nodes map[string]*fakeThresholdNode) {
	t.Helper()

	for receiverID, receiver := range nodes {
		receiver.mu.Lock()
		deliveries := append([]DeliverDKGRequest(nil), receiver.deliveries...)
		receiver.mu.Unlock()

		for _, delivery := range deliveries {
			if delivery.Round != 2 {
				continue
			}
			want := fmt.Sprintf("unicast:%s:%s", delivery.From, receiverID)
			if delivery.Unicast != want {
				t.Fatalf("round 2 unicast from %s to %s = %q, want %q", delivery.From, receiverID, delivery.Unicast, want)
			}
		}
	}
}
