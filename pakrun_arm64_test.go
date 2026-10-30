//go:build zxcunsafe && !purego

package zxc

import (
	"testing"
	"unsafe"
)

// TestPakStateLayout checks the field offsets pak_arm64.s uses.
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
			t.Fatalf("field %d at offset %d, pak_arm64.s expects %d", k, off, 8*k)
		}
	}
}
