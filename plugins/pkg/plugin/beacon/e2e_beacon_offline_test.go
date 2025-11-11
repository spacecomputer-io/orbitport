package beacon

import (
	"testing"
	"time"
)

// TestBeaconProducesBlocksOffline ensures that with the "offline" profile
// (Aptos Orbital unavailable), the beacon still produces blocks by
// falling back to the MasterSeed plugin.
func TestBeaconProducesBlocksOffline(t *testing.T) {
	requireE2EProfile(t, "offline")

	conn, ipfs := newIpfsClient(t)
	defer conn.Close()

	// Wait for initial head (sequence >= 0).
	seq0, cid0, payload0 := waitForBeaconSequence(t, ipfs, defaultBeacon, 0, 2*time.Minute)
	t.Logf("[offline] initial beacon head: seq=%d, cid=%s, ts=%d", seq0, cid0, payload0.Timestamp)

	// Wait for sequence to advance.
	seq1, cid1, payload1 := waitForBeaconSequence(t, ipfs, defaultBeacon, seq0+1, 3*time.Minute)
	t.Logf("[offline] updated beacon head: seq=%d, cid=%s, ts=%d", seq1, cid1, payload1.Timestamp)

	if seq1 <= seq0 {
		t.Fatalf("[offline] expected beacon sequence to increase, got old=%d, new=%d", seq0, seq1)
	}
	if cid1 == cid0 {
		t.Fatalf("[offline] expected head CID to change when sequence advances, old=%s, new=%s", cid0, cid1)
	}
	if len(payload1.CTRNG) == 0 {
		t.Fatalf("[offline] expected non-empty CTRNG slice in new beacon payload")
	}
}
