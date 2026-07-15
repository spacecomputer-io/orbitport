package beacon

import (
	"context"
	"errors"
	"fmt"
	"testing"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeIpfsPluginClient struct {
	keyInfoResponse *proto.KeyInfoResponse
	keyInfoErr      error
	getResponse     *proto.GetResponse
	getErr          error
	addResponses    []*proto.AddResponse
	addRequests     [][]byte
	publishRequests []*proto.PublishRequest
}

func (f *fakeIpfsPluginClient) Add(ctx context.Context, in *proto.AddRequest, opts ...grpc.CallOption) (*proto.AddResponse, error) {
	data := append([]byte(nil), in.GetData()...)
	f.addRequests = append(f.addRequests, data)
	respIndex := len(f.addRequests) - 1
	if respIndex < len(f.addResponses) {
		return f.addResponses[respIndex], nil
	}
	return &proto.AddResponse{Cid: fmt.Sprintf("bafyfake%d", respIndex)}, nil
}

func (f *fakeIpfsPluginClient) Get(ctx context.Context, in *proto.GetRequest, opts ...grpc.CallOption) (*proto.GetResponse, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getResponse != nil {
		return f.getResponse, nil
	}
	return nil, errors.New("unexpected Get call")
}

func (f *fakeIpfsPluginClient) Publish(ctx context.Context, in *proto.PublishRequest, opts ...grpc.CallOption) (*proto.PublishResponse, error) {
	req := &proto.PublishRequest{
		Cid:         in.GetCid(),
		PublishName: in.GetPublishName(),
	}
	f.publishRequests = append(f.publishRequests, req)

	switch in.GetPublishName() {
	case "randomness-beacon-dev1.0":
		return &proto.PublishResponse{IpnsName: "k2k4r8fakebeacon"}, nil
	case "orbitport-registry":
		return &proto.PublishResponse{IpnsName: "k2k4r8fakeregistry"}, nil
	default:
		return &proto.PublishResponse{IpnsName: "k2k4r8other"}, nil
	}
}

func (f *fakeIpfsPluginClient) Delete(ctx context.Context, in *proto.DeleteRequest, opts ...grpc.CallOption) (*proto.DeleteResponse, error) {
	return &proto.DeleteResponse{Success: true}, nil
}

func (f *fakeIpfsPluginClient) KeyInfo(ctx context.Context, in *proto.KeyInfoRequest, opts ...grpc.CallOption) (*proto.KeyInfoResponse, error) {
	if f.keyInfoErr != nil {
		return nil, f.keyInfoErr
	}
	if f.keyInfoResponse != nil {
		return f.keyInfoResponse, nil
	}
	return &proto.KeyInfoResponse{}, nil
}

func TestLoadRegistryInitializesWhenKeyExistsButRegistryHeadIsMissing(t *testing.T) {
	client := &fakeIpfsPluginClient{
		keyInfoResponse: &proto.KeyInfoResponse{IpnsName: "/ipns/k2k4r8existingregistry"},
		getErr:          status.Error(codes.NotFound, `ipns record not published for "/ipns/k2k4r8existingregistry"`),
		addResponses: []*proto.AddResponse{
			{Cid: "bafytempgenesis"},
			{Cid: "bafyfinalgenesis"},
			{Cid: "bafyregistry"},
		},
	}

	cfg := Config{
		BeaconRegistry:           "orbitport-registry",
		DefaultBeaconName:        "randomness-beacon-dev1.0",
		BeaconMsg:                "test-beacon",
		BeaconInterval:           10,
		RegistryRetrievalTimeout: 1,
	}

	reg, err := loadRegistryWithClient(context.Background(), cfg, client)
	if err != nil {
		t.Fatalf("loadRegistryWithClient returned error: %v", err)
	}

	if len(reg.Beacons) != 1 {
		t.Fatalf("expected exactly one beacon in returned registry, got %d", len(reg.Beacons))
	}

	meta := reg.Beacons[0]
	if meta.Name != cfg.DefaultBeaconName {
		t.Fatalf("expected beacon %q, got %q", cfg.DefaultBeaconName, meta.Name)
	}
	if meta.PublicKey != "k2k4r8fakebeacon" {
		t.Fatalf("expected published beacon key to be preserved, got %q", meta.PublicKey)
	}

	if len(client.publishRequests) != 3 {
		t.Fatalf("expected 3 publish operations (temp, final, registry), got %d", len(client.publishRequests))
	}
	if got := client.publishRequests[len(client.publishRequests)-1].GetPublishName(); got != cfg.BeaconRegistry {
		t.Fatalf("expected final publish to target registry alias %q, got %q", cfg.BeaconRegistry, got)
	}

	if len(client.addRequests) != 3 {
		t.Fatalf("expected 3 add operations (temp, final, registry), got %d", len(client.addRequests))
	}

	var publishedRegistry Registry
	if err := publishedRegistry.Unmarshal(client.addRequests[len(client.addRequests)-1]); err != nil {
		t.Fatalf("expected final registry payload to be valid JSON, got %v", err)
	}
	if len(publishedRegistry.Beacons) != 1 {
		t.Fatalf("expected published registry to contain one beacon, got %d", len(publishedRegistry.Beacons))
	}
	if publishedRegistry.Beacons[0].Name != cfg.DefaultBeaconName {
		t.Fatalf("expected published registry beacon name %q, got %q", cfg.DefaultBeaconName, publishedRegistry.Beacons[0].Name)
	}
}
