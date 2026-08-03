package threshold

import (
	"context"
	"testing"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPluginCoordinateDkg(t *testing.T) {
	nodeIDs := []string{"node-a", "node-b", "node-c"}
	nodes := make(map[string]*fakeThresholdNode, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		nodes[nodeID] = newFakeThresholdNode(t, nodeID, nodeIDs)
	}
	prepareFakeThresholdNodes(t, nodes, newTestGroupConfig())

	plugin := newPlugin(
		&thresholdConfig{TimeoutSecs: 10, SessionSecret: "test-threshold-session-secret"},
		NewCoordinator(WithSessionSecret([]byte("test-threshold-session-secret"))),
	)
	resp, err := plugin.CoordinateDkg(context.Background(), &proto.DkgRequest{
		KeyName:   "key-1",
		GroupName: "team-a",
		SessionId: "dkg-1",
		Threshold: 2,
		Participants: []*proto.GroupMember{
			{NodeId: "node-a", PartyIndex: 0, OpenbaoUrl: nodes["node-a"].server.URL, Mount: "threshold"},
			{NodeId: "node-b", PartyIndex: 1, OpenbaoUrl: nodes["node-b"].server.URL, Mount: "threshold"},
			{NodeId: "node-c", PartyIndex: 2, OpenbaoUrl: nodes["node-c"].server.URL, Mount: "threshold"},
		},
	})
	if err != nil {
		t.Fatalf("CoordinateDkg() error = %v", err)
	}
	if resp.KeyName != "key-1" || resp.GroupName != "team-a" || resp.SessionId != "dkg-1" {
		t.Fatalf("unexpected response identity: %+v", resp)
	}
	if len(resp.Nodes) != 3 {
		t.Fatalf("expected 3 node statuses, got %d", len(resp.Nodes))
	}
	for _, node := range resp.Nodes {
		if node.Status != keyStatusCompleted {
			t.Fatalf("node %s status = %q, want %q", node.NodeId, node.Status, keyStatusCompleted)
		}
	}
}

func TestPluginCoordinateDkgRejectsInvalidRequest(t *testing.T) {
	plugin := newPlugin(
		&thresholdConfig{TimeoutSecs: 10, SessionSecret: "test-threshold-session-secret"},
		NewCoordinator(WithSessionSecret([]byte("test-threshold-session-secret"))),
	)

	_, err := plugin.CoordinateDkg(context.Background(), &proto.DkgRequest{
		KeyName:   "key-1",
		GroupName: "team-a",
		SessionId: "dkg-1",
		Threshold: 2,
		Participants: []*proto.GroupMember{
			{NodeId: "node-a", PartyIndex: 0, OpenbaoUrl: "http://node-a"},
		},
	})
	if err == nil {
		t.Fatal("expected CoordinateDkg to reject invalid request")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestPluginCoordinateDkgHonorsTimeout(t *testing.T) {
	plugin := newPlugin(
		&thresholdConfig{TimeoutSecs: 1, SessionSecret: "test-threshold-session-secret"},
		NewCoordinator(WithSessionSecret([]byte("test-threshold-session-secret"))),
	)
	plugin.timeout = time.Nanosecond

	_, err := plugin.CoordinateDkg(context.Background(), &proto.DkgRequest{
		KeyName:   "key-1",
		GroupName: "team-a",
		SessionId: "dkg-1",
		Threshold: 2,
		Participants: []*proto.GroupMember{
			{NodeId: "node-a", PartyIndex: 0, OpenbaoUrl: "http://127.0.0.1:1"},
			{NodeId: "node-b", PartyIndex: 1, OpenbaoUrl: "http://127.0.0.1:1"},
		},
	})
	if err == nil {
		t.Fatal("expected CoordinateDkg to fail after context timeout")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", status.Code(err))
	}
}
