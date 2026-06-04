package threshold

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Plugin struct {
	proto.UnimplementedThresholdPluginServer

	timeout     time.Duration
	coordinator *Coordinator
	newClient   func(node *proto.ThresholdNode) ThresholdNodeClient
}

var logger = utils.GetLogger("orbitport:threshold")

func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()
	logger.Infof("creating Threshold plugin with timeout_secs=%d", cfg.TimeoutSecs)
	return newPlugin(cfg, NewCoordinator()), nil
}

func newPlugin(cfg *thresholdConfig, coordinator *Coordinator) *Plugin {
	timeout := time.Duration(cfg.TimeoutSecs) * time.Second
	return &Plugin{
		timeout:     timeout,
		coordinator: coordinator,
		newClient: func(node *proto.ThresholdNode) ThresholdNodeClient {
			return NewOpenBaoClient(OpenBaoClientConfig{
				BaseURL: node.OpenbaoUrl,
				Mount:   node.Mount,
				Timeout: timeout,
			})
		},
	}
}

func (p *Plugin) CoordinateDkg(ctx context.Context, req *proto.CoordinateDkgRequest) (*proto.CoordinateDkgResponse, error) {
	dkgRequest, err := p.dkgRequestFromProto(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	callCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	result, err := p.coordinator.CoordinateDKG(callCtx, dkgRequest)
	if err != nil {
		logger.Warnf("CoordinateDkg failed for key=%s group=%s session=%s: %v", dkgRequest.KeyName, dkgRequest.GroupName, dkgRequest.SessionID, err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	nodes := make([]*proto.DkgNodeStatus, 0, len(result.Nodes))
	for nodeID, node := range result.Nodes {
		nodes = append(nodes, &proto.DkgNodeStatus{
			NodeId:      nodeID,
			Status:      node.Status,
			Round:       int32(node.Round),
			NextRound:   int32(node.NextRound),
			PendingFrom: node.PendingFrom,
		})
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].NodeId < nodes[j].NodeId
	})

	return &proto.CoordinateDkgResponse{
		KeyName:   result.KeyName,
		GroupName: result.GroupName,
		SessionId: result.SessionID,
		PublicKey: result.PublicKey,
		Nodes:     nodes,
	}, nil
}

func (p *Plugin) dkgRequestFromProto(req *proto.CoordinateDkgRequest) (DKGRequest, error) {
	if req == nil {
		return DKGRequest{}, fmt.Errorf("request is required")
	}

	dkgRequest := DKGRequest{
		KeyName:   strings.TrimSpace(req.KeyName),
		GroupName: strings.TrimSpace(req.GroupName),
		SessionID: strings.TrimSpace(req.SessionId),
		Threshold: int(req.Threshold),
	}
	if dkgRequest.KeyName == "" {
		return DKGRequest{}, fmt.Errorf("key_name is required")
	}
	if dkgRequest.GroupName == "" {
		return DKGRequest{}, fmt.Errorf("group_name is required")
	}
	if dkgRequest.SessionID == "" {
		return DKGRequest{}, fmt.Errorf("session_id is required")
	}
	if len(req.Participants) < 2 {
		return DKGRequest{}, fmt.Errorf("dkg requires at least two participants")
	}
	if req.Threshold < 2 || int(req.Threshold) > len(req.Participants) {
		return DKGRequest{}, fmt.Errorf("threshold must be between 2 and participant count")
	}

	seenNodeIDs := make(map[string]struct{}, len(req.Participants))
	seenPartyIndexes := make(map[int32]struct{}, len(req.Participants))
	for _, participant := range req.Participants {
		if participant == nil {
			return DKGRequest{}, fmt.Errorf("participant is required")
		}

		nodeID := strings.TrimSpace(participant.NodeId)
		if nodeID == "" {
			return DKGRequest{}, fmt.Errorf("participant node_id is required")
		}
		openBaoURL := strings.TrimSpace(participant.OpenbaoUrl)
		if openBaoURL == "" {
			return DKGRequest{}, fmt.Errorf("participant %q openbao_url is required", nodeID)
		}
		if _, exists := seenNodeIDs[nodeID]; exists {
			return DKGRequest{}, fmt.Errorf("duplicate participant node_id %q", nodeID)
		}
		seenNodeIDs[nodeID] = struct{}{}

		if participant.PartyIndex < 0 || int(participant.PartyIndex) >= len(req.Participants) {
			return DKGRequest{}, fmt.Errorf("participant %q party_index %d out of range", nodeID, participant.PartyIndex)
		}
		if _, exists := seenPartyIndexes[participant.PartyIndex]; exists {
			return DKGRequest{}, fmt.Errorf("duplicate participant party_index %d", participant.PartyIndex)
		}
		seenPartyIndexes[participant.PartyIndex] = struct{}{}

		normalizedNode := &proto.ThresholdNode{
			NodeId:     nodeID,
			PartyIndex: participant.PartyIndex,
			OpenbaoUrl: openBaoURL,
			Mount:      strings.TrimSpace(participant.Mount),
		}
		dkgRequest.Participants = append(dkgRequest.Participants, DKGParticipant{
			NodeID:     nodeID,
			PartyIndex: int(participant.PartyIndex),
			Client:     p.newClient(normalizedNode),
		})
	}

	sort.Slice(dkgRequest.Participants, func(i, j int) bool {
		return dkgRequest.Participants[i].PartyIndex < dkgRequest.Participants[j].PartyIndex
	})
	return dkgRequest, nil
}
