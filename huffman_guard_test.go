//go:build (linux || darwin) && !purego && (amd64 || arm64)

package zxc

import (
	"bytes"
	"math/rand/v2"
	"os"
	"syscall"
	"testing"
)

// guarded returns a buffer of n bytes that ends right before a page the
// process may not touch: an assembly read of a single byte past its end
// faults, where the other tests would only see the right output, the
// stray bytes being never selected.
func guarded(t *testing.T, n int) []byte {
	t.Helper()
	page := os.Getpagesize()
	size := (n+page-1)/page*page + page
	mem, err := syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { syscall.Munmap(mem) })
	if err := syscall.Mprotect(mem[size-page:], syscall.PROT_NONE); err != nil {
		t.Skip(err)
	}
	return mem[size-page-n : size-page : size-page]
}

// TestKernelBounds runs merge and unpackFlat with their inputs ending at a
// guard page: the child sequences with only the 8 bytes of slack the steps
// of 8 need, the flat runs exactly as long as their codes.
func TestKernelBounds(t *testing.T) {
	r := rand.New(rand.NewPCG(51, 52))
	for iter := range 3000 {
		n := 1 + r.IntN(300)
		run := make([]byte, (n+7)/8)
		for i := range run {
			run[i] = byte(r.Uint32())
		}
		if r.IntN(3) == 0 {
			for i := range run {
				run[i] = 0xFF // the right sequence runs to the end
			}
		}
		ones := 0
		for k := range n {
			ones += int(run[k>>3] >> (k & 7) & 1)
		}
		lo := r.IntN(24)
		ch := guarded(t, lo+n+8)
		for i := range ch {
			ch[i] = byte(r.Uint32())
		}
		a, b := make([]byte, n), make([]byte, n)
		merge(a, ch, lo, n-ones, run)
		mergeRef(b, ch, lo, n-ones, run)
		if !bytes.Equal(a, b) {
			t.Fatalf("iter %d: merge and mergeRef disagree", iter)
		}

		D := uint8(2 + iter%5) // the depths of the assembly
		var fb [hufNumSymbols]uint8
		for i := range fb {
			fb[i] = byte(r.Uint32())
		}
		base := r.IntN(hufNumSymbols - 1<<D + 1)
		code := guarded(t, (n*int(D)+7)/8)
		for i := range code {
			code[i] = byte(r.Uint32())
		}
		unpackFlat(a, code, D, &fb, base)
		unpackFlatRef(b, code, D, &fb, base)
		if !bytes.Equal(a, b) {
			t.Fatalf("iter %d: unpackFlat and unpackFlatRef disagree", iter)
		}
	}
}

// TestHufDecodeBounds runs decode on valid sections that end right before
// a guard page, with no readable byte past them: the assembly decoder must
// hand them back, or decode them, without reading past.
func TestHufDecodeBounds(t *testing.T) {
	r := rand.New(rand.NewPCG(55, 56))
	var hd hufDecoder
	var tree hufTree
	for iter := range 2000 {
		maxLen := 1 + r.IntN(hufMaxLen)
		k := 1 + r.IntN(min(hufNumSymbols, 1<<maxLen))
		lens := randomLengths(r, k, maxLen)
		if err := tree.build(&lens); err != nil {
			t.Fatal(err)
		}
		ref := newRefTree(t, &lens)
		n := 1 + r.IntN(2000)
		data := randomData(r, &lens, n)
		enc := encodePivCo(ref, data)
		body := guarded(t, len(enc))
		copy(body, enc)
		out := make([]byte, n+wildPad)
		if err := hd.decode(&tree, body, n, out); err != nil || !bytes.Equal(out[:n], data) {
			t.Fatalf("iter %d: decode: %v, or a wrong output", iter, err)
		}
	}
}
