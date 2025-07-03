package beacon

import (
	"encoding/json"
	"fmt"
	"time"
)

type Registry struct {
	Beacons []BeaconMetadata `json:"beacons"`
}

func (r *Registry) Marshal() ([]byte, error) {
	return json.Marshal(r.Beacons)
}

func (r *Registry) Unmarshal(data []byte) error {
	return json.Unmarshal(data, &r.Beacons)
}

type Block struct {
	Link string `json:"previous"`
	Data []byte `json:"data"`
}

func (b *Block) Marshal() ([]byte, error) {
	return json.Marshal(b)
}

func (b *Block) Unmarshal(data []byte) error {
	return json.Unmarshal(data, b)
}

type BeaconMetadata struct {
	Name      string        `json:"name"`
	PublicKey string        `json:"public_key"`
	Version   string        `json:"version"`
	Encoding  string        `json:"encoding"`
	BatchSize uint64        `json:"batch_size"`
	Interval  time.Duration `json:"interval"`
}

func (b *BeaconMetadata) Marshal() ([]byte, error) {
	return json.Marshal(b)
}

func (b *BeaconMetadata) Unmarshal(data []byte) error {
	return json.Unmarshal(data, b)
}

type BeaconPayload struct {
	Sequence  uint64   `json:"sequence"`
	Timestamp int64    `json:"timestamp"`
	CTRNG     []string `json:"ctrng"`
}

func (b *BeaconPayload) Marshal() ([]byte, error) {
	return json.Marshal(b)
}

func (b *BeaconPayload) Unmarshal(data []byte) error {
	return json.Unmarshal(data, b)
}

func UnmarshalBeaconBlock[T BeaconMetadata | BeaconPayload](data []byte) (*T, error) {
	var block T
	if err := json.Unmarshal(data, &block); err != nil {
		return nil, fmt.Errorf("failed to unmarshal beacon block: %w", err)
	}
	return &block, nil
}
