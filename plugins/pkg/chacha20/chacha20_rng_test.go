package chacha20

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func fixedSeed0123() [32]byte {
	var s [32]byte
	for i := 0; i < 32; i++ {
		s[i] = byte(i)
	}
	return s
}

func readBytes(t *testing.T, r *ChaCha20Rng, n int) []byte {
	t.Helper()
	out := make([]byte, n)
	r.FillBytes(out)
	return out
}

func discardNaive(t *testing.T, r *ChaCha20Rng, n uint64) {
	t.Helper()
	if n == 0 {
		return
	}
	tmp := make([]byte, 1024)
	remaining := n
	for remaining > 0 {
		take := uint64(len(tmp))
		if remaining < take {
			take = remaining
		}
		r.FillBytes(tmp[:take])
		remaining -= take
	}
}

func TestNew_InitialState(t *testing.T) {
	seed := fixedSeed0123()
	r := New(seed)

	// ChaCha "expand 32-byte k"
	require.Equal(t, uint32(0x61707865), r.state[0])
	require.Equal(t, uint32(0x3320646e), r.state[1])
	require.Equal(t, uint32(0x79622d32), r.state[2])
	require.Equal(t, uint32(0x6b206574), r.state[3])

	// Key words should be LE u32s of the seed
	for i := 0; i < 8; i++ {
		want := binary.LittleEndian.Uint32(seed[i*4 : (i+1)*4])
		require.Equal(t, want, r.state[4+i], "key word %d mismatch", i)
	}

	// Counter + stream id start at 0
	require.Equal(t, uint32(0), r.state[12])
	require.Equal(t, uint32(0), r.state[13])
	require.Equal(t, uint32(0), r.state[14])
	require.Equal(t, uint32(0), r.state[15])

	// Buffer initially "empty" (forces refill on first FillBytes)
	require.Equal(t, 64, r.bufPos)
	require.Equal(t, uint64(0), r.Counter())
}

func TestFillBytes_DeterministicSameSeed(t *testing.T) {
	seed := fixedSeed0123()
	r1 := New(seed)
	r2 := New(seed)

	a := readBytes(t, r1, 4096)
	b := readBytes(t, r2, 4096)

	require.Equal(t, a, b)
}

func TestFillBytes_BufferingIsConsistentAcrossCalls(t *testing.T) {
	seed := fixedSeed0123()

	// Read 80 bytes in one shot
	rOne := New(seed)
	want := readBytes(t, rOne, 80)

	// Read 30 then 50 bytes
	rTwo := New(seed)
	p1 := readBytes(t, rTwo, 30)
	p2 := readBytes(t, rTwo, 50)

	got := append(p1, p2...)
	require.Equal(t, want, got)
}

func TestCounter_IncrementsPerGeneratedBlock(t *testing.T) {
	seed := fixedSeed0123()
	r := New(seed)

	// Before any output: still at counter 0
	require.Equal(t, uint64(0), r.Counter())

	// First FillBytes triggers a block generation, which increments counter after producing block 0.
	_ = readBytes(t, r, 1)
	require.Equal(t, uint64(1), r.Counter())

	// Still within same generated block, counter should remain 1.
	_ = readBytes(t, r, 63)
	require.Equal(t, uint64(1), r.Counter())

	// Next byte forces next block generation (block 1), counter increments to 2.
	_ = readBytes(t, r, 1)
	require.Equal(t, uint64(2), r.Counter())
}

func TestSetCounter_MatchesStreamAtBlockBoundary(t *testing.T) {
	seed := fixedSeed0123()

	// Generate 2 blocks from baseline RNG (128 bytes)
	base := New(seed)
	stream := readBytes(t, base, 128)

	// Jump to counter=1: the next block produced should be block 1
	jumped := New(seed)
	jumped.SetCounter(1)

	block1 := readBytes(t, jumped, 64)
	require.Equal(t, stream[64:128], block1, "SetCounter(1) should align with stream at byte offset 64")
}

func TestDiscardBytesFast_EquivalentToNaive_SmallWithinBuffer(t *testing.T) {
	seed := fixedSeed0123()

	fast := New(seed)
	slow := New(seed)

	// Bring both to same internal point: consume 10 bytes
	a1 := readBytes(t, fast, 10)
	a2 := readBytes(t, slow, 10)
	require.Equal(t, a1, a2)

	// Now discard 5 bytes using two methods
	fast.DiscardBytesFast(5)
	discardNaive(t, slow, 5)

	// Next bytes must match
	gotFast := readBytes(t, fast, 256)
	gotSlow := readBytes(t, slow, 256)
	require.Equal(t, gotSlow, gotFast)
}

func TestDiscardBytesFast_EquivalentToNaive_CrossesBlocks(t *testing.T) {
	seed := fixedSeed0123()

	fast := New(seed)
	slow := New(seed)

	// Large discard that crosses many 64-byte blocks
	const skip = uint64(10_000)
	fast.DiscardBytesFast(skip)
	discardNaive(t, slow, skip)

	gotFast := readBytes(t, fast, 512)
	gotSlow := readBytes(t, slow, 512)
	require.Equal(t, gotSlow, gotFast)
}

func TestDiscardBytesFast_BlockAlignedSkip(t *testing.T) {
	seed := fixedSeed0123()

	// Baseline: read 3 blocks (192 bytes)
	base := New(seed)
	stream := readBytes(t, base, 192)

	// Skip exactly 64 bytes => should land at offset 64 (block 1 start)
	r := New(seed)
	r.DiscardBytesFast(64)
	out := readBytes(t, r, 128)
	require.True(t, bytes.Equal(stream[64:192], out), "block-aligned skip should match stream slice")
}
