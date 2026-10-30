package zxc

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

// mergeRef is merge without its assembly steps: the steps of 8 symbols
// and the tail only.
func mergeRef(dst, ch []byte, lo, nl int, run []byte) {
	l, r := lo, lo+nl
	k := 0
	for ; k+8 <= len(dst); k += 8 {
		x := run[k>>3]
		var w [16]byte
		binary.LittleEndian.PutUint64(w[:8], binary.LittleEndian.Uint64(ch[l:]))
		binary.LittleEndian.PutUint64(w[8:], binary.LittleEndian.Uint64(ch[r:]))
		for j := range 8 {
			dst[k+j] = w[mergeIdx[x][j]&15]
		}
		p := int(mergeOnes[x])
		l += 8 - p
		r += p
	}
	for ; k < len(dst); k++ {
		if run[k>>3]>>(k&7)&1 != 0 {
			dst[k] = ch[r]
			r++
		} else {
			dst[k] = ch[l]
			l++
		}
	}
}

// TestMergeKernel holds merge, assembly steps included where there are
// some, to mergeRef on random bits and lengths, with the child sequences
// at random positions and either the level buffers' wildPad bytes of slack
// behind them or only the 8 the steps of 8 need: then the assembly must
// stop early and leave the rest to the Go code.
func TestMergeKernel(t *testing.T) {
	r := rand.New(rand.NewPCG(41, 42))
	for iter := range 20000 {
		n := r.IntN(300)
		switch iter % 4 {
		case 0:
			n = r.IntN(40)
		case 1:
			n = 16 + r.IntN(112) // around rounds of one, two and four steps
		}
		run := make([]byte, (n+7)/8)
		for i := range run {
			run[i] = byte(r.Uint32())
		}
		switch r.IntN(4) {
		case 0:
			clear(run) // all left
		case 1:
			for i := range run {
				run[i] = 0xFF // all right
			}
		}
		ones := 0
		for k := range n {
			ones += int(run[k>>3] >> (k & 7) & 1)
		}
		lo := r.IntN(24)
		slack := wildPad
		if iter%2 == 0 {
			slack = 8
		}
		ch := make([]byte, lo+n+slack)
		for i := range ch {
			ch[i] = byte(r.Uint32())
		}
		a := make([]byte, n)
		b := make([]byte, n)
		merge(a, ch, lo, n-ones, run)
		mergeRef(b, ch, lo, n-ones, run)
		if !bytes.Equal(a, b) {
			t.Fatalf("iter %d: n %d, lo %d, slack %d: merge and mergeRef disagree", iter, n, lo, slack)
		}
	}
}

// unpackFlatRef is unpackFlat without its assembly steps.
func unpackFlatRef(dst, run []byte, D uint8, fb *[hufNumSymbols]uint8, base int) {
	for k := range dst {
		bit := k * int(D)
		var code int
		for j := range int(D) {
			b := bit + j
			if b>>3 < len(run) {
				code |= int(run[b>>3]>>(b&7)&1) << j
			}
		}
		dst[k] = fb[(base+code)&255]
	}
}

// TestFlatKernel holds unpackFlat, assembly steps included where there are
// some, to unpackFlatRef for every depth, on random codes, tables at
// random places in the table buffer and runs either exactly as long as
// their codes or followed by more bytes.
func TestFlatKernel(t *testing.T) {
	r := rand.New(rand.NewPCG(43, 44))
	for iter := range 20000 {
		D := uint8(2 + iter%7) // 2 to 8
		n := r.IntN(400)
		if iter%5 == 0 {
			n = r.IntN(48)
		}
		var fb [hufNumSymbols]uint8
		for i := range fb {
			fb[i] = byte(r.Uint32())
		}
		base := r.IntN(hufNumSymbols - 1<<D + 1)
		run := make([]byte, (n*int(D)+7)/8+r.IntN(3)*r.IntN(20))
		for i := range run {
			run[i] = byte(r.Uint32())
		}
		a := make([]byte, n)
		b := make([]byte, n)
		unpackFlat(a, run, D, &fb, base)
		unpackFlatRef(b, run, D, &fb, base)
		if !bytes.Equal(a, b) {
			t.Fatalf("iter %d: D %d, n %d, run %d bytes: unpackFlat and unpackFlatRef disagree", iter, D, n, len(run))
		}
	}
}
