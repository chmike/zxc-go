//go:build !purego

package zxc

import (
	"encoding/binary"
	"unsafe"
)

// Fast paths of the PAK and SPL decoders, unchecked version: the default
// build. Same logic as fast_safe.go (-tags purego), but the memory accesses
// go through unsafe pointers, without Go's bounds checks.
//
// Why this is sound: the fast-path condition of each sequence is exactly
// the bounds check of its copies, given the invariants newLZOutput and the
// block decoders establish before any fast path runs:
//   - len(o.out)  >= o.limit  + wildPad  (output window padding)
//   - len(o.lits) >= o.litEnd + wildPad  (literal slack, § 5.2, or RLE
//     scratch padding)
//   - len(offs) >= len(tokens) * offset width, and len(seqs) is a multiple
//     of 4, by the section sizes checked in decodePAK and decodeSPL.
// With d+ll+ml <= limit, l+ll <= litEnd and 32 <= off <= d+ll, every read
// and write below lies inside those slices. A bug in those invariants would
// corrupt memory instead of panicking: keep the tests passing with both
// builds (go test ./... and go test -tags purego ./...).

// unsafeFastPath reports which version of the fast paths is compiled in.
const unsafeFastPath = true

// pakFast takes every PAK sequence whose lengths fit the sequence word, so
// it only stops on a varint, on a sequence that does not fit the block or
// the literals, or on an offset reaching before the window: the rarer
// cases emit handles with its errors.
//
// Proof of its accesses. The entry test makes the two invariants local:
//
//	len(out)  >= limit + wildPad    len(lits) >= litEnd + wildPad
//
// A sequence that passes the break test has ll <= 254, ml <= 259 (no
// varint), d+ll+ml <= limit, l+ll <= litEnd and 1 <= off <= d+ll. Copies
// run in 32-byte steps, so each one passes its length by at most 31 bytes:
//   - literals write out[d, d+ll+31] and read lits[l, l+ll+31], inside
//     since d+ll+31 <= limit+31 and l+ll+31 <= litEnd+31;
//   - with d' = d+ll, the match writes out[d', d'+ml+31], inside since
//     d'+ml+31 <= limit+31, and reads out[d'-off, d'-off+ml+31], which
//     starts at 0 or after (off <= d') and ends before its writes do;
//   - with off >= 32 each 32-byte read ends at or before the write it
//     feeds, so it reads bytes already decoded; with off < 32 the match
//     goes through copyMatch, which is bounds-checked.
//
// The sequence word itself is read at seqs[i, i+3], i < len(seqs) &^ 3.
func pakFast(o *lzOutput, seqs []byte, i int) (int, int, int) {
	limit, litEnd := o.limit, o.litEnd
	d, l := o.d, o.l
	if i < 0 || limit < 0 || litEnd < 0 || d < 0 || l < 0 ||
		len(o.out) < limit+wildPad || len(o.lits) < litEnd+wildPad {
		panic("zxc: pakFast invariants violated")
	}
	ob := unsafe.Pointer(unsafe.SliceData(o.out))
	lb := unsafe.Pointer(unsafe.SliceData(o.lits))
	sb := unsafe.Pointer(unsafe.SliceData(seqs))
	n := len(seqs) &^ 3
	for ; i < n; i += 4 {
		s := le32p(unsafe.Add(sb, i))
		ll := int(s >> 24)
		mb := int(s >> 16 & 0xFF)
		off := int(s&0xFFFF) + 1
		ml := mb + minMatch
		if ll == pakLenMask || mb == pakLenMask || off > d+ll ||
			ll+ml > limit-d || ll > litEnd-l {
			break
		}
		move32(unsafe.Add(ob, d), unsafe.Add(lb, l))
		for k := 32; k < ll; k += 32 {
			move32(unsafe.Add(ob, d+k), unsafe.Add(lb, l+k))
		}
		d += ll
		l += ll
		if off >= 32 {
			move32(unsafe.Add(ob, d), unsafe.Add(ob, d-off))
			for k := 32; k < ml; k += 32 {
				move32(unsafe.Add(ob, d+k), unsafe.Add(ob, d-off+k))
			}
		} else {
			copyMatch(o.out, d, off, ml)
		}
		d += ml
	}
	return i, d, l
}

func splFast8(o *lzOutput, tokens, offs []byte, i int) (int, int, int) {
	limit, litEnd := o.limit, o.litEnd
	d, l := o.d, o.l
	ob := unsafe.Pointer(unsafe.SliceData(o.out))
	lb := unsafe.Pointer(unsafe.SliceData(o.lits))
	tb := unsafe.Pointer(unsafe.SliceData(tokens))
	fb := unsafe.Pointer(unsafe.SliceData(offs[:len(tokens)]))
	n := len(tokens)
	for ; i < n; i++ {
		t := *(*byte)(unsafe.Add(tb, i))
		ll := int(t >> 4)
		ml := int(t&splTokenMask) + minMatch
		off := int(*(*byte)(unsafe.Add(fb, i))) + 1
		if ll == splTokenMask || ml == splTokenMask+minMatch || off < 32 ||
			ll+ml > limit-d || ll > litEnd-l || off > d+ll {
			break
		}
		move16(unsafe.Add(ob, d), unsafe.Add(lb, l))
		d += ll
		l += ll
		move24(unsafe.Add(ob, d), unsafe.Add(ob, d-off))
		d += ml
	}
	return i, d, l
}

func splFast16(o *lzOutput, tokens, offs []byte, i int) (int, int, int) {
	limit, litEnd := o.limit, o.litEnd
	d, l := o.d, o.l
	ob := unsafe.Pointer(unsafe.SliceData(o.out))
	lb := unsafe.Pointer(unsafe.SliceData(o.lits))
	tb := unsafe.Pointer(unsafe.SliceData(tokens))
	fb := unsafe.Pointer(unsafe.SliceData(offs[:2*len(tokens)]))
	n := len(tokens)
	for ; i < n; i++ {
		t := *(*byte)(unsafe.Add(tb, i))
		ll := int(t >> 4)
		ml := int(t&splTokenMask) + minMatch
		off := int(le16p(unsafe.Add(fb, 2*i))) + 1
		if ll == splTokenMask || ml == splTokenMask+minMatch || off < 32 ||
			ll+ml > limit-d || ll > litEnd-l || off > d+ll {
			break
		}
		move16(unsafe.Add(ob, d), unsafe.Add(lb, l))
		d += ll
		l += ll
		move24(unsafe.Add(ob, d), unsafe.Add(ob, d-off))
		d += ml
	}
	return i, d, l
}

// le16p and le32p load little-endian integers; on little-endian targets
// the compiler reduces them to a single load. The moves below copy raw
// bytes, so the file is correct on any byte order.
func le16p(p unsafe.Pointer) uint16 { return binary.LittleEndian.Uint16((*[2]byte)(p)[:]) }
func le32p(p unsafe.Pointer) uint32 { return binary.LittleEndian.Uint32((*[4]byte)(p)[:]) }

// move16, move24 and move32 copy 16, 24 or 32 bytes, loads before stores.
func move16(d, s unsafe.Pointer) {
	a, b := *(*uint64)(s), *(*uint64)(unsafe.Add(s, 8))
	*(*uint64)(d), *(*uint64)(unsafe.Add(d, 8)) = a, b
}

func move24(d, s unsafe.Pointer) {
	a, b, c := *(*uint64)(s), *(*uint64)(unsafe.Add(s, 8)), *(*uint64)(unsafe.Add(s, 16))
	*(*uint64)(d), *(*uint64)(unsafe.Add(d, 8)), *(*uint64)(unsafe.Add(d, 16)) = a, b, c
}

func move32(d, s unsafe.Pointer) {
	a, b := *(*uint64)(s), *(*uint64)(unsafe.Add(s, 8))
	c, e := *(*uint64)(unsafe.Add(s, 16)), *(*uint64)(unsafe.Add(s, 24))
	*(*uint64)(d), *(*uint64)(unsafe.Add(d, 8)) = a, b
	*(*uint64)(unsafe.Add(d, 16)), *(*uint64)(unsafe.Add(d, 24)) = c, e
}
