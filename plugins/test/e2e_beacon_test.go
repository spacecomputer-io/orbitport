//go:build e2e

package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	beaconpkg "github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/beacon"
	"github.com/spacecomputer-io/orbitport/plugins/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const registryAlias = "orbitport-dev-registry"
const defaultBeacon = "randomness-beacon-dev1.0"
const ipfsAddress = "localhost:50002"
const ctrngAddress = "localhost:50001"
const masterseedAddress = "localhost:50003"

func requireE2EProfile(t *testing.T, expected string) {
	t.Helper()
	got := os.Getenv("E2E_PROFILE")
	if got != expected {
		t.Skipf("skipping beacon e2e: require E2E_PROFILE=%s, got %q", expected, got)
	}
}

func newIpfsClient(t *testing.T) (*grpc.ClientConn, proto.IpfsPluginClient) {
	t.Helper()

	conn, err := grpc.NewClient(ipfsAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial ipfs plugin at %s: %v", ipfsAddress, err)
	}
	return conn, proto.NewIpfsPluginClient(conn)
}

// waitForBeaconSequence waits until the beacon head has sequence >= minSeq.
func waitForBeaconSequence(t *testing.T, client proto.IpfsPluginClient, beaconKey string, minSeq uint64, timeout time.Duration) (seq uint64, cid string, payload *beaconpkg.BeaconPayload) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var lastSeq uint64
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("timeout waiting for beacon %s to reach sequence >= %d (last=%d)", beaconKey, minSeq, lastSeq)
		default:
		}

		callCtx, callCancel := context.WithTimeout(ctx, 5*time.Second)
		resp, err := client.Get(callCtx, &proto.GetRequest{
			Key:       beaconKey,
			Namespace: "ipns",
		})
		callCancel()
		if err != nil {
			// retry on transient errors on startup
			time.Sleep(2 * time.Second)
			continue
		}

		block, err := beaconpkg.UnmarshalBeaconBlock(resp.GetData())
		if err != nil || block == nil || block.Data == nil {
			t.Logf("beacon %v: failed to unmarshal block: %v", beaconKey, err)
			time.Sleep(2 * time.Second)
			continue
		}

		lastSeq = block.Data.Sequence
		if lastSeq >= minSeq {
			return lastSeq, resp.GetPath(), block.Data
		}

		time.Sleep(2 * time.Second)
	}
}

func TestBeaconRegistryCreated(t *testing.T) {
	requireE2EProfile(t, "happy")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := beaconpkg.Config{
		IPFSPlugin:        ipfsAddress,
		CTRNGPlugin:       ctrngAddress,
		MasterSeedPlugin:  masterseedAddress,
		BeaconRegistry:    registryAlias,
		DefaultBeaconName: defaultBeacon,
		BeaconMsg:         "Rm9ydHVuZQrotKLlr4wK157Xltec",
		BeaconInterval:    10,
		IPFSAddress:       "http://localhost:5001",
	}

	// Force creation / upsert of registry via beacon logic
	reg, err := beaconpkg.E2ELoadRegistry(ctx, cfg)
	if err != nil {
		t.Fatalf("loadRegistry(%s) failed: %v", registryAlias, err)
	}
	if len(reg.Beacons) == 0 {
		t.Fatalf("loadRegistry returned empty registry")
	}

	t.Logf("reg is %+v", reg)

	// inspect via IPFS plugin
	conn, ipfs := newIpfsClient(t)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("failed to close ipfs client conn: %v", err)
		}
	}()

	getCtx, getCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer getCancel()

	// using the alias here, IPFS plugin will normalize it.
	getResp, err := ipfs.Get(getCtx, &proto.GetRequest{
		Key:       registryAlias,
		Namespace: "ipns",
	})
	if err != nil {
		t.Fatalf("Get(%s, ipns) failed after loadRegistry: %v", registryAlias, err)
	}

	var regFromIpfs beaconpkg.Registry
	if err := regFromIpfs.Unmarshal(getResp.GetData()); err != nil {
		t.Fatalf("failed to unmarshal registry from IPFS: %v", err)
	}
	if len(regFromIpfs.Beacons) == 0 {
		t.Fatalf("registry %s from IPFS is empty", registryAlias)
	}

	// Ensure default beacon is present
	found := false
	for _, b := range regFromIpfs.Beacons {
		if b.Name == defaultBeacon {
			found = true
			if b.PublicKey == "" {
				t.Fatalf("beacon %s in registry has empty PublicKey", defaultBeacon)
			}
			break
		}
	}
	if !found {
		t.Fatalf("default beacon %s not found in registry %s", defaultBeacon, registryAlias)
	}
}

// TestBeaconProducesBlocks ensures that the beacon chain is being extended over time:
// - read the genesis/head
// - after waiting > interval, sequence number increases and the link changes.
func TestBeaconProducesBlocks(t *testing.T) {
	requireE2EProfile(t, "happy")

	conn, ipfs := newIpfsClient(t)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("failed to close ipfs client conn: %v", err)
		}
	}()

	// Wait for initial head (genesis) with sequence >= 0.
	seq0, cid0, payload0 := waitForBeaconSequence(t, ipfs, defaultBeacon, 0, 2*time.Minute)
	t.Logf("Initial beacon head: seq=%d, cid=%s, ts=%d", seq0, cid0, payload0.Timestamp)

	// Wait for sequence to advance.
	seq1, cid1, payload1 := waitForBeaconSequence(t, ipfs, defaultBeacon, seq0+1, 3*time.Minute)
	t.Logf("Updated beacon head: seq=%d, cid=%s, ts=%d", seq1, cid1, payload1.Timestamp)

	if seq1 <= seq0 {
		t.Fatalf("expected beacon sequence to increase, got old=%d, new=%d", seq0, seq1)
	}
	if cid1 == cid0 {
		t.Fatalf("expected head CID to change when sequence advances, old=%s, new=%s", cid0, cid1)
	}
	if len(payload1.CTRNG) == 0 {
		t.Fatalf("expected non-empty CTRNG slice in new beacon payload")
	}
}

// TestBeaconResumesFromRegistry ensures that loadRegistry() reuses an existing
// beacon from the registry instead of creating a new one, i.e., "resume" behavior.
func TestBeaconResumesFromRegistry(t *testing.T) {
	requireE2EProfile(t, "happy")

	// This test calls loadRegistry directly using a Config that points to the
	// real ipfs plugin and existing registry.
	conn, ipfs := newIpfsClient(t)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("failed to close ipfs client conn: %v", err)
		}
	}()

	// Sanity: registry already exists and contains the beacon (rely on previous test).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ki, err := ipfs.KeyInfo(ctx, &proto.KeyInfoRequest{PublishName: registryAlias})
	if err != nil || ki == nil || ki.IpnsName == "" {
		t.Fatalf("expected registry %s to exist before resume test, got KeyInfo error=%v, IpnsName=%s", registryAlias, err, ki.GetIpnsName())
	}

	// Fetch current head block to capture the current sequence.
	seqBefore, _, _ := waitForBeaconSequence(t, ipfs, defaultBeacon, 0, 2*time.Minute)
	t.Logf("Sequence before calling loadRegistry: %d", seqBefore)

	// Now call loadRegistry with a Config that points to the live plugin-ipfs.
	cfg := beaconpkg.Config{
		IPFSPlugin:        ipfsAddress,
		CTRNGPlugin:       ctrngAddress,
		MasterSeedPlugin:  masterseedAddress,
		BeaconRegistry:    registryAlias,
		DefaultBeaconName: defaultBeacon,
		BeaconMsg:         "Rm9ydHVuZQrotKLlr4wK157Xltec",
		BeaconInterval:    10,
		IPFSAddress:       "http://localhost:5001",
	}

	reg, err := beaconpkg.E2ELoadRegistry(ctx, cfg)
	if err != nil {
		t.Fatalf("loadRegistry failed: %v", err)
	}
	if reg == nil || len(reg.Beacons) == 0 {
		t.Fatalf("loadRegistry returned empty registry")
	}
	if reg.Beacons[0].Name != defaultBeacon {
		t.Fatalf("expected registry beacon name %s, got %s", defaultBeacon, reg.Beacons[0].Name)
	}
	if reg.Beacons[0].PublicKey == "" {
		t.Fatalf("registry beacon has empty PublicKey after resume")
	}

	// Confirm that after calling loadRegistry, the beacon still advances
	// from the previous sequence (i.e., we didn't create a second beacon).
	seqAfter, _, _ := waitForBeaconSequence(t, ipfs, defaultBeacon, seqBefore+1, 3*time.Minute)
	if seqAfter <= seqBefore {
		t.Fatalf("expected sequence to continue increasing from existing beacon, before=%d, after=%d", seqBefore, seqAfter)
	}
}
