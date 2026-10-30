//go:build !purego && (amd64 || arm64)

package zxc

import (
	"testing"
	"unsafe"
)

// TestPakStateLayout checks the field offsets pak_amd64.s and pak_arm64.s use.
func TestPakStateLayout(t *testing.T) {
	var s pakState
	got := []uintptr{
		unsafe.Offsetof(s.out), unsafe.Offsetof(s.lits), unsafe.Offsetof(s.seqs),
		unsafe.Offsetof(s.ext), unsafe.Offsetof(s.nSeq), unsafe.Offsetof(s.nExt),
		unsafe.Offsetof(s.i), unsafe.Offsetof(s.d), unsafe.Offsetof(s.l),
		unsafe.Offsetof(s.e), unsafe.Offsetof(s.limit), unsafe.Offsetof(s.litEnd),
	}
	for k, off := range got {
		if off != uintptr(8*k) {
			t.Fatalf("field %d at offset %d, the assembly expects %d", k, off, 8*k)
		}
	}
}

// TestSplStateLayout checks the field offsets the SPL assembly uses.
func TestSplStateLayout(t *testing.T) {
	var s splState
	got := []uintptr{
		unsafe.Offsetof(s.out), unsafe.Offsetof(s.lits), unsafe.Offsetof(s.toks),
		unsafe.Offsetof(s.ext), unsafe.Offsetof(s.offs), unsafe.Offsetof(s.nTok),
		unsafe.Offsetof(s.nExt), unsafe.Offsetof(s.i), unsafe.Offsetof(s.d),
		unsafe.Offsetof(s.l), unsafe.Offsetof(s.e), unsafe.Offsetof(s.limit),
		unsafe.Offsetof(s.litEnd), unsafe.Offsetof(s.w),
	}
	for k, off := range got {
		if off != uintptr(8*k) {
			t.Fatalf("field %d at offset %d, the assembly expects %d", k, off, 8*k)
		}
	}
}

// TestHufStateLayout checks the field offsets huffman_arm64.s uses.
func TestHufStateLayout(t *testing.T) {
	var st hufState
	for _, f := range []struct {
		name      string
		got, want uintptr
	}{
		{"body", unsafe.Offsetof(st.body), 0},
		{"bodyLen", unsafe.Offsetof(st.bodyLen), 8},
		{"bodyCap", unsafe.Offsetof(st.bodyCap), 16},
		{"n", unsafe.Offsetof(st.n), 24},
		{"out", unsafe.Offsetof(st.out), 32},
		{"tmp", unsafe.Offsetof(st.tmp), 40},
		{"count", unsafe.Offsetof(st.count), 48},
		{"runs", unsafe.Offsetof(st.runs), 56},
		{"base", unsafe.Offsetof(st.base), 64},
		{"leafBase", unsafe.Offsetof(st.leafBase), 72},
		{"code", unsafe.Offsetof(st.code), 80},
		{"flat", unsafe.Offsetof(st.flat), 88},
		{"syms", unsafe.Offsetof(st.syms), 96},
		{"maxDepth", unsafe.Offsetof(st.maxDepth), 104},
		{"scratch", unsafe.Offsetof(st.scratch), 112},
		{"hufMergeTab.idxB", unsafe.Offsetof(hufMergeTab.idxB), 2048},
		{"hufMergeTab.ones", unsafe.Offsetof(hufMergeTab.ones), 20480},
		{"hufFlatConst", unsafe.Sizeof(hufFlatConst{}), 96},
	} {
		if f.got != f.want {
			t.Errorf("%s at %d, the assembly expects %d", f.name, f.got, f.want)
		}
	}
}
