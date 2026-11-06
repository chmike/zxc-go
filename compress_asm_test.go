//go:build !purego && (arm64 || amd64)

package zxc

import (
	"bytes"
	"math/rand/v2"
	"testing"
	"unsafe"
)

// TestEncStateLayout checks the field offsets the assembly uses.
func TestEncStateLayout(t *testing.T) {
	var st encState
	for _, f := range []struct {
		name      string
		got, want uintptr
	}{
		{"ip", unsafe.Offsetof(st.ip), 8},
		{"limit", unsafe.Offsetof(st.limit), 24},
		{"head", unsafe.Offsetof(st.head), 32},
		{"epochMark", unsafe.Offsetof(st.epochMark), 56},
		{"minOffset", unsafe.Offsetof(st.minOffset), 72},
		{"stepShift", unsafe.Offsetof(st.stepShift), 96},
		{"lits", unsafe.Offsetof(st.lits), 104},
		{"extras", unsafe.Offsetof(st.extras), 120},
		{"anchor", unsafe.Offsetof(st.anchor), 128},
		{"offs", unsafe.Offsetof(st.offs), 136},
		{"maxOff", unsafe.Offsetof(st.maxOff), 144},
		{"depth", unsafe.Offsetof(st.depth), 152},
		{"lazyAtt", unsafe.Offsetof(st.lazyAtt), 160},
		{"lazyLen", unsafe.Offsetof(st.lazyLen), 168},
		{"level", unsafe.Offsetof(st.level), 176},
		{"scratch", unsafe.Offsetof(st.scratch), 184},
		{"optState.dp", unsafe.Offsetof(optState{}.dp), 72},
		{"optState.litCost", unsafe.Offsetof(optState{}.litCost), 96},
		{"optState.prevLen", unsafe.Offsetof(optState{}.prevLen), 144},
		{"splitState.side", unsafe.Offsetof(splitState{}.side), 24},
		{"splitState.n", unsafe.Offsetof(splitState{}.n), 48},
		{"splitState.split", unsafe.Offsetof(splitState{}.split), 72},
	} {
		if f.got != f.want {
			t.Errorf("encState.%s at %d, the assembly expects %d", f.name, f.got, f.want)
		}
	}
}

// encodeBlockBoth encodes blk, after the dictionary content dict, with the
// assembly parsers and with the Go ones, and returns both blocks.
func encodeBlockBoth(blk, dict []byte, level int) (asm, ref []byte) {
	opts := []Option{WithLevel(level), WithBlockSize(2 << 20)}
	if len(dict) > 0 {
		d, err := NewRawDictionary(dict)
		if err != nil {
			panic(err)
		}
		opts = append(opts, WithDictionary(d))
	}
	cfg := newConfig(opts)
	a, g := newEncoder(cfg), newEncoder(cfg)
	g.noAsm = true
	return a.appendBlock(nil, blk, 0), g.appendBlock(nil, blk, 0)
}

// FuzzEncAsm requires the same block from the assembly parsers as from the
// Go ones, with or without a dictionary.
func FuzzEncAsm(f *testing.F) {
	f.Add([]byte("Hello ZXC, Hello ZXC, Hello ZXC\n"), []byte{}, uint8(0))
	f.Add(bytes.Repeat([]byte("abcdefgh"), 100), []byte("abcdefghabcdefgh"), uint8(1))
	f.Fuzz(func(t *testing.T, blk, dict []byte, level uint8) {
		if len(blk) == 0 || len(blk) > 2<<20 || len(dict) > 1<<16 {
			return
		}
		l := 1 + int(level)%7
		a, g := encodeBlockBoth(blk, dict, l)
		if !bytes.Equal(a, g) {
			t.Fatalf("level %d, %d bytes, dictionary %d: assembly and Go blocks differ", l, len(blk), len(dict))
		}
	})
}

// TestEncAsmInputs runs FuzzEncAsm's comparison on the test inputs, whole
// and in many sizes, and on blocks ending at a guard page.
func TestEncAsmInputs(t *testing.T) {
	in := testInputs()
	for name, src := range in {
		if len(src) == 0 {
			continue
		}
		for _, n := range []int{len(src), 9, 10, 17, 33, 100, 1000, 4096, 70000} {
			blk := src[:min(n, len(src))]
			for l := 1; l <= 7; l++ {
				for _, dict := range [][]byte{nil, in["text"][:3000]} {
					a, g := encodeBlockBoth(blk, dict, l)
					if !bytes.Equal(a, g) {
						t.Fatalf("%s, %d bytes, level %d, dictionary %d: assembly and Go blocks differ", name, len(blk), l, len(dict))
					}
					gb := guarded(t, len(blk))
					copy(gb, blk)
					if a2, _ := encodeBlockBoth(gb, dict, l); !bytes.Equal(a2, a) {
						t.Fatalf("%s, %d bytes, level %d: differs at a guard page", name, len(blk), l)
					}
				}
			}
		}
	}
}

// TestRLEAsm holds rleFast to rleSize and appendRLE on literals made of
// runs and copies of every length around the format's limits, also ending
// at a guard page.
func TestRLEAsm(t *testing.T) {
	r := rand.New(rand.NewPCG(61, 62))
	for iter := range 4000 {
		var lits []byte
		for len(lits) < 1+r.IntN(3000) {
			switch r.IntN(3) {
			case 0:
				lits = append(lits, bytes.Repeat([]byte{byte(r.IntN(4))}, 1+r.IntN(300))...)
			case 1:
				for range 1 + r.IntN(200) {
					lits = append(lits, byte(r.Uint32()))
				}
			default:
				lits = append(lits, bytes.Repeat([]byte{byte(r.IntN(4))}, []int{1, 2, 3, 4, 5, 130, 131, 132, 134, 135, 262, 265}[r.IntN(12)])...)
			}
		}
		if iter%2 == 0 {
			g := guarded(t, len(lits))
			copy(g, lits)
			lits = g
		}
		want := appendRLE([]byte("x"), lits)
		n, got := rleFast([]byte("x"), lits, true)
		if !bytes.Equal(got, want) || n != len(want)-1 || n != rleSize(lits) {
			t.Fatalf("iter %d, %d literals: rleFast differs from appendRLE", iter, len(lits))
		}
		if m, _ := rleFast(nil, lits, false); m != n {
			t.Fatalf("iter %d: size only %d, written %d", iter, m, n)
		}
	}
}
