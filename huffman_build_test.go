package zxc

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

// TestHuffmanVsRef holds the decoder to the former one (refTree.decodeRef)
// and to the walk (refTree.decodeWalk) on random codes of every shape and
// on random tables, mostly invalid: the trees must be accepted or rejected
// alike, and on random sections, valid ones and the same corrupted,
// truncated or replaced by noise, the decoders must agree on the output or
// on the rejection.
func TestHuffmanVsRef(t *testing.T) {
	r := rand.New(rand.NewPCG(49, 50))
	var hd hufDecoder
	var tree hufTree
	for iter := range 20000 {
		var lens [hufNumSymbols]uint8
		if iter%10 == 9 {
			for i := range lens {
				if r.IntN(4) == 0 {
					lens[i] = uint8(r.IntN(16))
				}
			}
		} else {
			maxLen := 1 + r.IntN(hufMaxLen)
			k := 1 + r.IntN(min(hufNumSymbols, 1<<maxLen))
			lens = randomLengths(r, k, maxLen)
		}
		var ref refTree
		ea, eb := tree.build(&lens), ref.buildTrie(&lens)
		if (ea == nil) != (eb == nil) {
			t.Fatalf("iter %d: build: %v, buildTrie: %v", iter, ea, eb)
		}
		if ea != nil {
			continue
		}
		n := 1 + r.IntN(2000)
		if iter%4 == 0 {
			n = 1 + r.IntN(40)
		}
		body := encodePivCo(&ref, randomData(r, &lens, n))
		switch r.IntN(4) {
		case 1:
			for range 1 + r.IntN(4) {
				if len(body) > 0 {
					body[r.IntN(len(body))] ^= byte(1 + r.IntN(255))
				}
			}
		case 2:
			body = body[:r.IntN(len(body)+1)]
		case 3:
			body = make([]byte, r.IntN(len(body)+8))
			for i := range body {
				body[i] = byte(r.Uint32())
			}
		}
		if iter%2 == 0 {
			// Readable bytes past the section, as in a block: the
			// assembly decoder, where there is one, takes the section.
			body = append(body, make([]byte, 64)...)[:len(body)]
		}
		a := make([]byte, n+wildPad)
		b := make([]byte, n+wildPad)
		w := make([]byte, n)
		errA := hd.decode(&tree, body, n, a)
		errB := ref.decodeRef(body, n, b)
		errW := ref.decodeWalk(body, n, w)
		if (errA == nil) != (errB == nil) || (errA == nil) != (errW == nil) {
			t.Fatalf("iter %d: decode: %v, decodeRef: %v, decodeWalk: %v", iter, errA, errB, errW)
		}
		if errA == nil && (!bytes.Equal(a[:n], b[:n]) || !bytes.Equal(a[:n], w)) {
			t.Fatalf("iter %d: n %d: the decoders disagree", iter, n)
		}
	}
}

// TestPopcountBits holds popcountBits to a bit-by-bit count, padding bits
// of the last byte set, for every length up to a few blocks of 32 bytes.
func TestPopcountBits(t *testing.T) {
	r := rand.New(rand.NewPCG(47, 48))
	for c := 0; c < 1200; c++ {
		b := make([]byte, (c+7)/8+r.IntN(4))
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		want := 0
		for k := range c {
			want += int(b[k>>3] >> (k & 7) & 1)
		}
		if got := popcountBits(b, c); got != want {
			t.Fatalf("c %d: popcountBits %d, want %d", c, got, want)
		}
	}
}
