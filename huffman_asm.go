//go:build !purego && (amd64 || arm64)

package zxc

import "unsafe"

// Assembly kernels of the Huffman decoder (huffman_amd64.s,
// huffman_arm64.s). They run where the PAK loop does: on amd64 they need
// SSSE3, as pak_amd64.s.
var haveHufAsm = havePakAsm

// hufIdxA and hufIdxB drive the 16-symbol merge step of hufMergeAsm. The
// step loads the next 16 symbols of the left sequence and of the right one
// as a 32-byte table, left in bytes 0-15 and right in 16-31, and picks its
// 16 outputs from it with one table lookup (TBL on arm64, two PSHUFB on
// amd64). Output j < 8 takes byte hufIdxA[b0][j], b0 being the first byte
// of control bits; output 8+j takes byte hufIdxB[p][b1][j], b1 being the
// second byte and p the number of 1 bits of b0, which says how far each
// sequence has already moved in the first half. A 0 bit takes the next
// left symbol, a 1 bit the next right one, LSB first.
var hufIdxA [256][8]uint8
var hufIdxB [9][256][8]uint8

// hufFlat holds, for each flat depth D from 2 to 6, the constants of the
// 16-symbol step of hufFlatAsm. A step reads the 2D bytes holding its 16
// codes as a 16-byte vector raw; code j sits at bit jD, in the 16-bit
// window of raw bytes jD/8 and jD/8+1, shifted by sh = jD%8. Codes 8-15
// sit D bytes after codes 0-7, with the same shifts.
//   - idxA, idxB: the raw bytes of the windows of codes 0-7 and 8-15, as
//     8 little-endian 16-bit lanes;
//   - shr, mask (arm64): -sh per 16-bit lane for USHL, then 2^D-1 per byte
//     once the lanes are narrowed to bytes;
//   - mul, cnt (amd64): 2^(16-D-sh) per lane for PMULLW, then a shift right
//     by 16-D, which keeps exactly the D bits of the code.
type hufFlatConst struct {
	idxA, idxB, shr, mask, mul, cnt [16]byte
}

var hufFlat [7]hufFlatConst

func init() {
	for D := 2; D <= 6; D++ {
		c := &hufFlat[D]
		for j := range 8 {
			b, sh := j*D/8, j*D%8
			c.idxA[2*j], c.idxA[2*j+1] = byte(b), byte(b+1)
			c.idxB[2*j], c.idxB[2*j+1] = byte(b+D), byte(b+D+1)
			c.shr[2*j], c.shr[2*j+1] = byte(-sh), 0xFF
			if sh == 0 {
				c.shr[2*j+1] = 0
			}
			m := 1 << (16 - D - sh)
			c.mul[2*j], c.mul[2*j+1] = byte(m), byte(m>>8)
		}
		for j := range 16 {
			c.mask[j] = byte(1<<D - 1)
		}
		c.cnt[0] = byte(16 - D)
	}
}

func init() {
	// idx fills the 8 indices of control byte b when the left sequence has
	// already moved by l symbols and the right one by r-16.
	idx := func(t *[8]uint8, b, l, r int) {
		for j := range 8 {
			if b>>j&1 != 0 {
				t[j] = uint8(r)
				r++
			} else {
				t[j] = uint8(l)
				l++
			}
		}
	}
	for b := range 256 {
		idx(&hufIdxA[b], b, 0, 16)
		for p := range 9 {
			idx(&hufIdxB[p][b], b, 8-p, 16+p)
		}
	}
}

// hufMergeAsm runs the merge of merge (huffman.go) 16 symbols at a time:
// while k+16 <= n, l <= max and r <= max, it writes dst[k:k+16] from the
// 16 symbols at ch[l:] and the 16 at ch[r:], as the control bits
// run[k/8], run[k/8+1] say, and moves l and r past the symbols taken. It
// returns k, l and r for the Go code to finish.
//
//go:noescape
func hufMergeAsm(dst *byte, n int, ch *byte, l, r, max int, run *byte) (k, lo, ro int)

// mergeFast runs hufMergeAsm for merge, from left position l and right
// position r in ch, and returns the number of symbols written and the new
// positions.
//
// Proof of the accesses of hufMergeAsm. It reads ch[l, l+16) and
// ch[r, r+16) only after testing l <= max and r <= max, max = len(ch)-16,
// with l, r >= 0 checked here; a round of s steps (s = 2 or 4), which
// reads up to 16(s-1) bytes further on each side, runs only after testing
// l <= max-16(s-1) and r <= max-16(s-1), and not at all when that bound is
// negative; it writes dst[k, k+16) and reads run[k/8]
// and run[k/8+1] only with k+16 <= n = len(dst), so k/8+1 <= (n-1)/8 <
// len(run) by the test below. It needs no relation between the bits and
// the sequence lengths: whatever the bits, it stops before a read leaves
// ch.
func mergeFast(dst, ch []byte, l, r int, run []byte) (int, int, int) {
	n := len(dst)
	if n < 16 || len(ch) < 16 || l < 0 || r < 0 || len(run) < (n+7)/8 {
		panic("zxc: mergeFast invariants violated")
	}
	return hufMergeAsm(&dst[0], n, &ch[0], l, r, len(ch)-16, &run[0])
}

// hufFlatAsm runs unpackFlat (huffman.go) 16 symbols at a time for a flat
// root of depth D, 2 <= D <= 6: while k+16 <= n and the 16 bytes at
// run[2D*k/16:] lie within the runLen bytes of run, it decodes the 16
// codes there into dst[k:k+16] through tbl, the code -> symbol table, and
// returns k for the Go code to finish.
//
//go:noescape
func hufFlatAsm(dst *byte, n int, run *byte, runLen int, c *hufFlatConst, tbl *[64]byte, D int) (k int)

// flatFast runs hufFlatAsm for unpackFlat, with tbl the 2^D entries of the
// flat root's table, and returns the number of symbols decoded.
//
// Proof of the accesses of hufFlatAsm. It reads run[o, o+16), o = 2D*k/16,
// only after testing o+16 <= runLen = len(run); it writes dst[k, k+16)
// only with k+16 <= n = len(dst). Its table lookups index the 64 bytes of
// t with codes below 2^D <= 64: on arm64 the codes are masked to D bits, on
// amd64 the multiply and shift leave exactly D bits, and a lookup past the
// table registers gives 0 on either.
func flatFast(dst, run []byte, D uint8, tbl []byte) int {
	n := len(dst)
	if D < 2 || D > 6 || n < 16 || len(tbl) != 1<<D {
		panic("zxc: flatFast invariants violated")
	}
	if len(run) < 16 {
		return 0
	}
	var t [64]byte
	copy(t[:], tbl)
	return hufFlatAsm(&dst[0], n, &run[0], len(run), &hufFlat[D], &t, int(D))
}

// hufMergeTab holds the tables of the merge step of hufDecodeAsm at fixed
// offsets from one base: hufIdxA at 0, hufIdxB at 2048, the bit counts of
// mergeOnes at 20480.
var hufMergeTab struct {
	idxA [256][8]uint8
	idxB [9][256][8]uint8
	ones [256]uint8
}

func init() {
	hufMergeTab.idxA, hufMergeTab.idxB, hufMergeTab.ones = hufIdxA, hufIdxB, mergeOnes
}

// hufState is what hufDecodeAsm reads: the section, the buffers and the
// tree, and room for its own use. TestHufStateLayout checks the offsets
// the assembly uses.
type hufState struct {
	body     unsafe.Pointer // 0: the runs of the section
	bodyLen  int            // 8
	bodyCap  int            // 16: bytes readable from body
	n        int            // 24: symbols
	out      unsafe.Pointer // 32: n + wildPad bytes
	tmp      unsafe.Pointer // 40: n + wildPad bytes
	count    unsafe.Pointer // 48: hufDecoder.count
	runs     unsafe.Pointer // 56: hufDecoder.runs
	base     unsafe.Pointer // 64: hufTree.base
	leafBase unsafe.Pointer // 72: hufTree.leafBase
	code     unsafe.Pointer // 80: hufTree.code
	flat     unsafe.Pointer // 88: hufTree.flat
	syms     unsafe.Pointer // 96: hufTree.syms
	maxDepth int            // 104
	scratch  [8]int         // 112: the assembly's spills
}

// decodeFast decodes a section with hufDecodeAsm, and reports whether it
// did; when not, the Go decoder takes the section.
//
// The assembly runs the two passes of decode, kernels included, and
// finishes every node in assembly: the last step of a node, which may be
// partial, writes a whole step (16 bytes, 32 for a leaf run); the bytes
// past the node belong to the nodes after it in the same depth, written
// after it, or to the slack of the level buffer. It hands the section
// back (returns nonzero) on a malformed section, a flat root of depth 7
// or 8, or any of the tests below failing.
//
// Proof of its accesses. On entry: t is a tree built by build (so its
// depth ranges, leaf ranges and codes are consistent, maxDepth <= 11 and
// at most 512 nodes and slot), len(out), len(tmp) >= n + wildPad, and
// body has bodyCap readable bytes. Then:
//   - counts: cnt[0] = n; a node's children get c-ones and ones, or 0, with
//     ones the 1 bits among its c bits, so the counts of a depth add up to
//     at most n; the assembly also tests off+c <= n before writing a node;
//   - tree arrays: indices are within the depth ranges of t, the children
//     of depth d's internal nodes within depth d+1 (or the slot after the
//     last node, for the lone-symbol root), syms indices below 256, plus
//     at most 64 table bytes from a flat root's first leaf, within syms'
//     512 bytes;
//   - section reads: pass 1 tests that every run lies within bodyLen, and
//     reads the last word of a run only after testing it lies within
//     bodyCap; pass 2 reads a node's run in steps of 16 symbols, at most
//     16 bytes past its end for a flat root and 1 for a bitmap node, after
//     testing the last read lies within bodyCap;
//   - level reads: a merge step reads 16 bytes at its left and right
//     positions in the child level after testing both are at most
//     n + wildPad - 16 from its start;
//   - level writes: a node writes from off to off + c + 31 at most, with
//     off + c <= n, within the n + wildPad bytes of the level buffer.
func (hd *hufDecoder) decodeFast(t *hufTree, body []byte, n int, out []byte) bool {
	if !haveHufDecodeAsm || n <= 0 || cap(body) == 0 || len(out) < n+wildPad ||
		t.maxDepth < 1 || t.maxDepth > hufMaxLen || t.base[t.maxDepth+1] > hufMaxNodes {
		return false
	}
	hd.tmp = grow(hd.tmp, n+wildPad)
	st := hufState{
		body:     unsafe.Pointer(unsafe.SliceData(body[:cap(body)])),
		bodyLen:  len(body),
		bodyCap:  cap(body),
		n:        n,
		out:      unsafe.Pointer(unsafe.SliceData(out)),
		tmp:      unsafe.Pointer(unsafe.SliceData(hd.tmp)),
		count:    unsafe.Pointer(&hd.count[0]),
		runs:     unsafe.Pointer(&hd.runs[0]),
		base:     unsafe.Pointer(&t.base[0]),
		leafBase: unsafe.Pointer(&t.leafBase[0]),
		code:     unsafe.Pointer(&t.code[0]),
		flat:     unsafe.Pointer(&t.flat[0]),
		syms:     unsafe.Pointer(&t.syms[0]),
		maxDepth: t.maxDepth,
	}
	return hufDecodeAsm(&st) == 0
}
