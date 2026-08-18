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
	newClient   func(member *proto.GroupMember) GroupMemberClient
}

var logger = utils.GetLogger("orbitport:threshold")

func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()
	sessionSecret := strings.TrimSpace(cfg.SessionSecret)
	if sessionSecret == "" {
		return nil, fmt.Errorf("ORBITPORT_THRESHOLD_SESSION_SECRET is required")
	}
	retryBackoff := time.Duration(cfg.RetryBackoffMillis) * time.Millisecond
	logger.Infof(
		"creating Threshold plugin with timeout_secs=%d retry_attempts=%d retry_backoff_ms=%d",
		cfg.TimeoutSecs,
		cfg.RetryAttempts,
		cfg.RetryBackoffMillis,
	)
	return newPlugin(cfg, NewCoordinator(
		WithSessionSecret([]byte(sessionSecret)),
		WithRetryPolicy(cfg.RetryAttempts, retryBackoff),
	)), nil
}

func newPlugin(cfg *thresholdConfig, coordinator *Coordinator) *Plugin {
	timeout := time.Duration(cfg.TimeoutSecs) * time.Second
	return &Plugin{
		timeout:     timeout,
		coordinator: coordinator,
		newClient: func(member *proto.GroupMember) GroupMemberClient {
			return NewOpenBaoClient(OpenBaoClientConfig{
				BaseURL: member.OpenbaoUrl,
				Mount:   member.Mount,
				Timeout: timeout,
			})
		},
	}
}

func (p *Plugin) CoordinateDkg(ctx context.Context, req *proto.DkgRequest) (*proto.DkgResponse, error) {
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
			PendingFrom: node.PendingFrom,
		})
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].NodeId < nodes[j].NodeId
	})

	return &proto.DkgResponse{
		KeyName:   result.KeyName,
		GroupName: result.GroupName,
		SessionId: result.SessionID,
		PublicKey: result.PublicKey,
		Nodes:     nodes,
	}, nil
}

func (p *Plugin) CoordinateSign(ctx context.Context, req *proto.ThresholdSignRequest) (*proto.ThresholdSignResponse, error) {
	signRequest, err := p.signRequestFromProto(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	callCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	result, err := p.coordinator.CoordinateSign(callCtx, signRequest)
	if err != nil {
		logger.Warnf(
			"CoordinateSign failed for key=%s group=%s session=%s: %v",
			signRequest.KeyName,
			signRequest.GroupName,
			signRequest.SessionID,
			err,
		)
		return nil, status.Error(codes.Internal, err.Error())
	}

	nodes := make([]*proto.SignNodeStatus, 0, len(result.Nodes))
	for nodeID, node := range result.Nodes {
		nodes = append(nodes, &proto.SignNodeStatus{
			NodeId:      nodeID,
			Status:      node.Status,
			Round:       int32(node.Round),
			PendingFrom: node.PendingFrom,
		})
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].NodeId < nodes[j].NodeId
	})

	return &proto.ThresholdSignResponse{
		KeyName:   result.KeyName,
		GroupName: result.GroupName,
		SessionId: result.SessionID,
		Signature: result.Signature,
		Nodes:     nodes,
	}, nil
}

func (p *Plugin) dkgRequestFromProto(req *proto.DkgRequest) (DKGRequest, error) {
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

		normalizedMember := &proto.GroupMember{
			NodeId:     nodeID,
			PartyIndex: participant.PartyIndex,
			OpenbaoUrl: openBaoURL,
			Mount:      strings.TrimSpace(participant.Mount),
		}
		dkgRequest.Participants = append(dkgRequest.Participants, DKGParticipant{
			NodeID:     nodeID,
			PartyIndex: int(participant.PartyIndex),
			Client:     p.newClient(normalizedMember),
		})
	}

	sort.Slice(dkgRequest.Participants, func(i, j int) bool {
		return dkgRequest.Participants[i].PartyIndex < dkgRequest.Participants[j].PartyIndex
	})
	return dkgRequest, nil
}

func (p *Plugin) signRequestFromProto(req *proto.ThresholdSignRequest) (SignRequest, error) {
	if req == nil {
		return SignRequest{}, fmt.Errorf("request is required")
	}

	signRequest := SignRequest{
		KeyName:   strings.TrimSpace(req.KeyName),
		GroupName: strings.TrimSpace(req.GroupName),
		SessionID: strings.TrimSpace(req.SessionId),
		Message:   strings.TrimSpace(req.Message),
		Threshold: int(req.Threshold),
	}
	if signRequest.KeyName == "" {
		return SignRequest{}, fmt.Errorf("key_name is required")
	}
	if signRequest.GroupName == "" {
		return SignRequest{}, fmt.Errorf("group_name is required")
	}
	if signRequest.SessionID == "" {
		return SignRequest{}, fmt.Errorf("session_id is required")
	}
	if signRequest.Message == "" {
		return SignRequest{}, fmt.Errorf("message is required")
	}
	if req.Threshold < 2 {
		return SignRequest{}, fmt.Errorf("threshold must be at least 2")
	}
	if len(req.Participants) < int(req.Threshold) {
		return SignRequest{}, fmt.Errorf("signing requires at least threshold participants")
	}

	seenNodeIDs := make(map[string]struct{}, len(req.Participants))
	seenPartyIndexes := make(map[int32]struct{}, len(req.Participants))
	for _, participant := range req.Participants {
		if participant == nil {
			return SignRequest{}, fmt.Errorf("participant is required")
		}

		nodeID := strings.TrimSpace(participant.NodeId)
		if nodeID == "" {
			return SignRequest{}, fmt.Errorf("participant node_id is required")
		}
		openBaoURL := strings.TrimSpace(participant.OpenbaoUrl)
		if openBaoURL == "" {
			return SignRequest{}, fmt.Errorf("participant %q openbao_url is required", nodeID)
		}
		if _, exists := seenNodeIDs[nodeID]; exists {
			return SignRequest{}, fmt.Errorf("duplicate participant node_id %q", nodeID)
		}
		seenNodeIDs[nodeID] = struct{}{}

		if participant.PartyIndex < 0 {
			return SignRequest{}, fmt.Errorf("participant %q party_index %d out of range", nodeID, participant.PartyIndex)
		}
		if _, exists := seenPartyIndexes[participant.PartyIndex]; exists {
			return SignRequest{}, fmt.Errorf("duplicate participant party_index %d", participant.PartyIndex)
		}
		seenPartyIndexes[participant.PartyIndex] = struct{}{}

		normalizedMember := &proto.GroupMember{
			NodeId:     nodeID,
			PartyIndex: participant.PartyIndex,
			OpenbaoUrl: openBaoURL,
			Mount:      strings.TrimSpace(participant.Mount),
		}
		signRequest.Participants = append(signRequest.Participants, DKGParticipant{
			NodeID:     nodeID,
			PartyIndex: int(participant.PartyIndex),
			Client:     p.newClient(normalizedMember),
		})
	}

	sort.Slice(signRequest.Participants, func(i, j int) bool {
		return signRequest.Participants[i].PartyIndex < signRequest.Participants[j].PartyIndex
	})
	return signRequest, nil
}
