package threshold

import "context"

const (
	defaultMount     = "threshold"
	defaultSeedBytes = 32

	keyStatusCompleted  = "dkg_completed"
	signStatusCompleted = "sign_completed"
)

type DKGParticipant struct {
	NodeID     string
	PartyIndex int
	Client     GroupMemberClient
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

type SignRequest struct {
	KeyName      string
	GroupName    string
	SessionID    string
	Message      string
	Threshold    int
	Participants []DKGParticipant
}

type SignResult struct {
	KeyName   string
	GroupName string
	SessionID string
	Signature string
	Nodes     map[string]SignStatus
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

type StartSignRequest struct {
	KeyName       string
	SessionID     string
	Message       string
	Participants  []string
	CommonSeed    string
	PairwiseSeeds map[string]string
}

type DeliverSignRequest struct {
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
	Broadcast   string            `json:"broadcast,omitempty"`
	Unicasts    map[string]string `json:"unicasts,omitempty"`
	PendingFrom []string          `json:"pending_from,omitempty"`
	PublicKey   string            `json:"public_key,omitempty"`
}

type SignStatus struct {
	Name             string            `json:"name"`
	SessionID        string            `json:"session_id"`
	NodeID           string            `json:"node_id"`
	Status           string            `json:"status"`
	Round            int               `json:"round,omitempty"`
	Broadcast        string            `json:"broadcast,omitempty"`
	Unicasts         map[string]string `json:"unicasts,omitempty"`
	PendingFrom      []string          `json:"pending_from,omitempty"`
	PartialSignature string            `json:"partial_signature,omitempty"`
	Signature        string            `json:"signature,omitempty"`
}

type GroupMemberClient interface {
	StartDKG(ctx context.Context, req StartDKGRequest) (*DKGStatus, error)
	DeliverDKG(ctx context.Context, keyName string, req DeliverDKGRequest) (*DKGStatus, error)
	ProceedDKG(ctx context.Context, keyName string, round int) (*DKGStatus, error)
	ReadDKGStatus(ctx context.Context, keyName string) (*DKGStatus, error)
	StartSign(ctx context.Context, req StartSignRequest) (*SignStatus, error)
	DeliverSign(ctx context.Context, keyName string, req DeliverSignRequest) (*SignStatus, error)
	ProceedSign(ctx context.Context, keyName string, round int) (*SignStatus, error)
	ReadSignStatus(ctx context.Context, keyName string) (*SignStatus, error)
	AggregateSign(ctx context.Context, keyName, message string, partialSignatures map[string]string) (*SignStatus, error)
}
