package threshold

import "context"

const (
	defaultMount     = "threshold"
	defaultSeedBytes = 32

	keyStatusCompleted = "dkg_completed"
)

type DKGParticipant struct {
	NodeID     string
	PartyIndex int
	Client     ThresholdNodeClient
}

type DKGRequest struct {
	KeyName      string
	GroupName    string
	SessionID    string
	Threshold    int
	Participants []DKGParticipant
}

type DKGResult struct {
	KeyName   string
	GroupName string
	SessionID string
	PublicKey string
	Nodes     map[string]DKGStatus
}

type StartDKGRequest struct {
	KeyName       string
	GroupName     string
	SessionID     string
	CommonSeed    string
	PairwiseSeeds map[string]string
	Algorithm     string
	Curve         string
	KeyEpoch      int
}

type DeliverDKGRequest struct {
	Round     int    `json:"round"`
	From      string `json:"from"`
	Broadcast string `json:"broadcast"`
	Unicast   string `json:"unicast"`
}

type DKGStatus struct {
	Name        string            `json:"name"`
	Group       string            `json:"group"`
	SessionID   string            `json:"session_id"`
	NodeID      string            `json:"node_id"`
	Status      string            `json:"status"`
	Round       int               `json:"round,omitempty"`
	NextRound   int               `json:"next_round"`
	Broadcast   string            `json:"broadcast,omitempty"`
	Unicasts    map[string]string `json:"unicasts,omitempty"`
	PendingFrom []string          `json:"pending_from,omitempty"`
	PublicKey   string            `json:"public_key,omitempty"`
}

type ThresholdNodeClient interface {
	StartDKG(ctx context.Context, req StartDKGRequest) (*DKGStatus, error)
	DeliverDKG(ctx context.Context, keyName string, req DeliverDKGRequest) (*DKGStatus, error)
	ProceedDKG(ctx context.Context, keyName string) (*DKGStatus, error)
	ReadDKGStatus(ctx context.Context, keyName string) (*DKGStatus, error)
}
