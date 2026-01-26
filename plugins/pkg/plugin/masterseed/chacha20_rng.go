/*
Implementation of a rand_chacha compatible ChaCha20 RNG core, which follows
Bernstein's chacha design (256 bit key, 64-bit block counter, 64-bit stream id).
State begins with the constant "expand 32-byte k" and uses the classic 16×u32 state layout.

Reasoning: Rust rand_chacha and go x/crypto/chacha20 are not the same construction.
- We want to match Rust rand_chacha's ChaCha20Rng for deterministic output
- rand_chacha uses a 64-bit counter & 64-bit stream id (nonce) both starting at 0
- golang.org/x/crypto/chacha20 targets 96-bit nonce APIs which do not align with rand_chacha's state layout.

Implementation includes:
- State initialization with 16-word ChaCha state:
	- state[0..3]  : constant "expand 32-byte k"
	- state[4..11] : key words derived from 32-byte seed (little-endian u32)
	- state[12..13]: 64-bit block counter (little-endian as two u32 words), starts at 0
	- state[14..15]: 64-bit stream id (nonce) (little-endian as two u32 words), starts at 0
- Block generation with ChaCha20 block function
*/

package masterseed

import "encoding/binary"

type ChaCha20Rng struct {
	state  [16]uint32
	buf    [64]byte
	bufPos int
}

func NewChaCha20Rng(seed [32]byte) *ChaCha20Rng {
	var r ChaCha20Rng

	r.state[0] = 0x61707865
	r.state[1] = 0x3320646e
	r.state[2] = 0x79622d32
	r.state[3] = 0x6b206574

	// Key: 32 bytes => 8 u32 words, little-endian
	for i := 0; i < 8; i++ {
		r.state[4+i] = binary.LittleEndian.Uint32(seed[i*4 : (i+1)*4])
	}

	// Counter: 64-bit (two u32 words). Starts at 0.
	r.state[12] = 0
	r.state[13] = 0

	// Stream ID: 64-bit (two u32 words). Starts at 0.
	r.state[14] = 0
	r.state[15] = 0

	// Buffer starts empty, first FillBytes triggers a block generation.
	r.bufPos = len(r.buf)

	return &r
}

// FillBytes fills dst with deterministic bytes from ChaCha20 keystream.
// Matches Rust rand_chacha concept. Same keystream, different buffering size.
func (r *ChaCha20Rng) FillBytes(dst []byte) {
	for len(dst) > 0 {
		if r.bufPos == len(r.buf) {
			r.refillBlock()
		}

		n := len(r.buf) - r.bufPos
		if n > len(dst) {
			n = len(dst)
		}

		copy(dst[:n], r.buf[r.bufPos:r.bufPos+n])
		r.bufPos += n
		dst = dst[n:]
	}
}

// refillBlock generates the next 64-byte ChaCha keystream block into r.buf,
// resets bufpos and increments the blocker counter.
func (r *ChaCha20Rng) refillBlock() {
	x := r.state
	for i := 0; i < 10; i++ {
		quarterRound(&x, 0, 4, 8, 12)
		quarterRound(&x, 1, 5, 9, 13)
		quarterRound(&x, 2, 6, 10, 14)
		quarterRound(&x, 3, 7, 11, 15)

		quarterRound(&x, 0, 5, 10, 15)
		quarterRound(&x, 1, 6, 11, 12)
		quarterRound(&x, 2, 7, 8, 13)
		quarterRound(&x, 3, 4, 9, 14)
	}

	// Feed-forward: add original state (mod 2^32)
	for i := 0; i < 16; i++ {
		x[i] += r.state[i]
	}

	// Serialize to bytes, little-endian u32 words
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(r.buf[i*4:i*4+4], x[i])
	}

	// Consume from beginning of buffer
	r.bufPos = 0

	// Increment the 64-bit counter (state[12] is low word, state[13] is high word)
	r.incrementCounter()
}

// incrementCounter increments the 64-bit block counter in the ChaCha state.
// Every 64 bytes produced corresponds to one ChaCha block, so increment the
// counter once per block.
func (r *ChaCha20Rng) incrementCounter() {
	r.state[12]++
	if r.state[12] == 0 {
		// carry
		r.state[13]++
	}
}

// quarterRound applies ChaCha's quarter round function to four state words.
// The sequence of operations and rotation amounts are defined by the ChaCha spec.
// Applying quarter rounds in the specified column/diagonal schedule for 20 rounds
// yields a pseudorandom keystream block when serialized.
func quarterRound(x *[16]uint32, a, b, c, d int) {
	x[a] += x[b]
	x[d] ^= x[a]
	x[d] = rotl32(x[d], 16)

	x[c] += x[d]
	x[b] ^= x[c]
	x[b] = rotl32(x[b], 12)

	x[a] += x[b]
	x[d] ^= x[a]
	x[d] = rotl32(x[d], 8)

	x[c] += x[d]
	x[b] ^= x[c]
	x[b] = rotl32(x[b], 7)
}

// rotl32 rotates v left by n bits, where n is in [0,31].
// ChaCha depends on fixed-distance rotations (16, 12, 8, 7). Rotations provide
// diffusion without relying on S-boxes or multiplication, which is why ChaCha
// is often described as ARX (Add-Rotate-Xor).
func rotl32(v uint32, n uint) uint32 {
	return (v << n) | (v >> (32 - n))
}

func FromSeed(seed [32]byte) *ChaCha20Rng {
	return NewChaCha20Rng(seed)
}
