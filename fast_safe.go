//go:build purego

package zxc

import "encoding/binary"

// Fast paths of the PAK and SPL decoders, bounds-checked version, selected
// with -tags purego: no assembly, no unsafe, every access checked by Go.
// The default build uses fast_unsafe.go and the assembly loops, which do
// the same work without Go's bounds checks.
//
// Each function decodes sequences while they fit the fast path described
// at lzOutput.emit, and returns the index of the first sequence it did not
// take with the updated output and literal positions. They make no call,
// so the compiler can keep the whole loop state in registers.

// unsafeFastPath reports which version of the fast paths is compiled in.
const unsafeFastPath = false

// pakRun runs the PAK fast path from sequence byte offset i, extras
// position e, and returns the new sequence offset, output and literal
// positions, and extras position. Here the fast path reads no varint, so e
// comes back unchanged.
func pakRun(o *lzOutput, seqs, extras []byte, i, e int) (int, int, int, int) {
	i, d, l := pakFast(o, seqs, i)
	return i, d, l, e
}

// splRun runs the SPL fast path for offsets of width w bytes from
// sequence i, extras position e, and returns the new sequence index,
// output and literal positions, and extras position. Here the fast path
// reads no varint, so e comes back unchanged.
func splRun(o *lzOutput, tokens, offs, extras []byte, w, i, e int) (int, int, int, int) {
	var d, l int
	if w == 1 {
		i, d, l = splFast8(o, tokens, offs, i)
	} else {
		i, d, l = splFast16(o, tokens, offs, i)
	}
	return i, d, l, e
}

func pakFast(o *lzOutput, seqs []byte, i int) (int, int, int) {
	out, lits := o.out, o.lits
	limit, litEnd := o.limit, o.litEnd
	d, l := o.d, o.l
	for ; i+4 <= len(seqs); i += 4 {
		s := binary.LittleEndian.Uint32(seqs[i:])
		ll := int(s >> 24)
		ml := int(s>>16&0xFF) + minMatch
		off := int(s&0xFFFF) + 1
		if ll > 32 || ml > 32 || off < 32 ||
			ll+ml > limit-d || ll > litEnd-l || off > d+ll {
			break
		}
		copy32(out[d:], lits[l:])
		d += ll
		l += ll
		copy32(out[d:], out[d-off:])
		d += ml
	}
	return i, d, l
}

// splFast8 and splFast16 handle 1- and 2-byte offsets. Inline lengths
// only: ll <= 14, ml <= 19.
func splFast8(o *lzOutput, tokens, offs []byte, i int) (int, int, int) {
	out, lits := o.out, o.lits
	limit, litEnd := o.limit, o.litEnd
	d, l := o.d, o.l
	offs = offs[:len(tokens)]
	for ; i < len(tokens); i++ {
		t := tokens[i]
		ll := int(t >> 4)
		ml := int(t&splTokenMask) + minMatch
		off := int(offs[i]) + 1
		if ll == splTokenMask || ml == splTokenMask+minMatch || off < 32 ||
			ll+ml > limit-d || ll > litEnd-l || off > d+ll {
			break
		}
		copy16(out[d:], lits[l:])
		d += ll
		l += ll
		copy24(out[d:], out[d-off:])
		d += ml
	}
	return i, d, l
}

func splFast16(o *lzOutput, tokens, offs []byte, i int) (int, int, int) {
	out, lits := o.out, o.lits
	limit, litEnd := o.limit, o.litEnd
	d, l := o.d, o.l
	offs = offs[:2*len(tokens)]
	for ; i < len(tokens); i++ {
		t := tokens[i]
		ll := int(t >> 4)
		ml := int(t&splTokenMask) + minMatch
		off := int(binary.LittleEndian.Uint16(offs[2*i:])) + 1
		if ll == splTokenMask || ml == splTokenMask+minMatch || off < 32 ||
			ll+ml > limit-d || ll > litEnd-l || off > d+ll {
			break
		}
		copy16(out[d:], lits[l:])
		d += ll
		l += ll
		copy24(out[d:], out[d-off:])
		d += ml
	}
	return i, d, l
}
