//go:build !purego && (amd64 || arm64)

package zxc

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

// maxFlatDepth returns the depth of the deepest flat root of t.
func maxFlatDepth(t *hufTree) int {
	m := 0
	for i := range t.base[t.maxDepth+1] {
		if d := int(t.flat[i]); d != hufCovered && d > m {
			m = d
		}
	}
	return m
}

// TestHufDecodeAsm holds the whole-section assembly decoder to the
// reference decoder on random valid sections followed by readable bytes,
// as in a block, and checks that it takes them: all but those with a flat
// root of depth 7 or 8, which it hands back.
func TestHufDecodeAsm(t *testing.T) {
	if !haveHufDecodeAsm {
		t.Skip("no whole-section assembly decoder here")
	}
	r := rand.New(rand.NewPCG(53, 54))
	var hd hufDecoder
	var tree hufTree
	taken, eligible := 0, 0
	for iter := range 20000 {
		maxLen := 1 + r.IntN(hufMaxLen)
		k := 1 + r.IntN(min(hufNumSymbols, 1<<maxLen))
		lens := randomLengths(r, k, maxLen)
		if err := tree.build(&lens); err != nil {
			t.Fatal(err)
		}
		var ref refTree
		if err := ref.buildTrie(&lens); err != nil {
			t.Fatal(err)
		}
		n := 1 + r.IntN(3000)
		if iter%4 == 0 {
			n = 1 + r.IntN(40)
		}
		body := encodePivCo(&ref, randomData(r, &lens, n))
		body = append(body, make([]byte, 64)...)[:len(body)]
		a := make([]byte, n+wildPad)
		b := make([]byte, n+wildPad)
		ok := hd.decodeFast(&tree, body, n, a)
		if maxFlatDepth(&tree) <= 6 {
			eligible++
			if ok {
				taken++
			}
		}
		if !ok {
			continue
		}
		if err := ref.decodeRef(body, n, b); err != nil {
			t.Fatalf("iter %d: decodeRef: %v", iter, err)
		}
		if !bytes.Equal(a[:n], b[:n]) {
			for i := range n {
				if a[i] != b[i] {
					t.Fatalf("iter %d: n %d: decodeFast differs at %d", iter, n, i)
				}
			}
		}
	}
	t.Logf("%d of %d eligible sections taken by the assembly", taken, eligible)
	if taken < eligible*9/10 {
		t.Fatalf("the assembly took only %d of %d eligible sections", taken, eligible)
	}
}
