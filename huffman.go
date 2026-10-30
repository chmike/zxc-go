package zxc

import (
	"encoding/binary"
	"math/bits"
)

// PivCo-Huffman sections (§ 5.2.1): a length-limited canonical Huffman code
// whose bits are stored grouped by node of the code tree instead of symbol
// after symbol. The layout and the merge-based decode are from
// Żukowski, "PivCo-Huffman" (2026); this implementation is independent.
//
// A section is: the 128-byte table of 256 four-bit code lengths (absent
// for literal encoding 3, whose table comes from the dictionary), then one
// bit run per emitting node of the tree, in BFS order. Each run is
// LSB-first within bytes and padded to a byte boundary.
//
//   - A bitmap node holds one bit per symbol routed through it, in symbol
//     order: 0 = left child, 1 = right child.
//   - A flat root, the top of a maximal perfect subtree of depth D >= 2,
//     holds D bits per symbol routed through it: bit j is the branch taken
//     at relative depth j. Its descendants emit nothing.
//
// No size is stored: the root handles n symbols, a bitmap node's popcount
// is its right child's count, a flat root with c symbols takes
// ceil(c*D/8) bytes.

const (
	hufMaxLen     = 11 // longest code (level 7; levels <= 6 stop at 8)
	hufNumSymbols = 256
)

// hufMaxNodes bounds the nodes of a code tree: a complete code of 256
// symbols has 511, the lone-symbol code 2.
const hufMaxNodes = 2*hufNumSymbols - 1

// hufCovered marks, in hufTree.flat, a node strictly inside a flat root:
// it emits no run and is routed no symbol.
const hufCovered = 0x80

// hufTree is a validated canonical code tree, held level by level as the
// two decoder passes walk it, with no structure per node. Its storage is
// reused when it is rebuilt for another table.
//
// Nodes are numbered in BFS order, the wire order of the runs: depth d has
// the nodes base[d] to base[d+1]-1, first its leaves, then its internal
// nodes, the j-th of which has its children at positions 2j and 2j+1 of
// depth d+1. The first node of depth d has code value code[d], the next
// ones the values after it. The leaves of depth d have the symbols
// syms[leafBase[d]:leafBase[d+1]], in position order, except under a flat
// root, whose 2^D leaves are stored in packed-code order: the 2^D symbols
// from leafBase[d+D] + code[d]<<D... are then the root's code -> symbol
// table (see flatSyms).
type hufTree struct {
	maxDepth int
	base     [hufMaxLen + 2]int
	leafBase [hufMaxLen + 2]int
	code     [hufMaxLen + 1]int

	// flat[i] is, for an internal node i, 0 for a bitmap node, D for a
	// flat root of depth D, or hufCovered.
	flat [hufMaxNodes]uint8

	// syms has room past the 256 for the absent symbols while sorting.
	syms [2 * hufNumSymbols]uint8

	height [hufMaxNodes]uint8 // perfect-subtree heights, while building
}

// leaves returns the number of leaves of depth d.
func (t *hufTree) leaves(d int) int { return t.leafBase[d+1] - t.leafBase[d] }

// symTable returns the 256 symbol slots, as unpackFlat takes them.
func (t *hufTree) symTable() *[hufNumSymbols]uint8 {
	return (*[hufNumSymbols]uint8)(t.syms[:hufNumSymbols])
}

// flatSyms returns where, in syms, the code -> symbol table of the flat
// root at position p of depth d starts: its leaves are, at depth d+D, the
// nodes of code values c<<D to c<<D + 2^D - 1, c its own value, all leaves
// of that depth.
func (t *hufTree) flatSyms(d, p, D int) int {
	return t.leafBase[d+D] + (t.code[d]+p)<<D - t.code[d+D]
}

// unpackLengths expands the 128-byte table into 256 code lengths.
func unpackLengths(table []byte) (lens [hufNumSymbols]uint8) {
	for i, b := range table[:hufTableSize] {
		lens[2*i] = b & 15
		lens[2*i+1] = b >> 4
	}
	return lens
}

// buildHufTree validates code lengths and builds a new canonical tree.
func buildHufTree(lens *[hufNumSymbols]uint8) (*hufTree, error) {
	t := new(hufTree)
	if err := t.build(lens); err != nil {
		return nil, err
	}
	return t, nil
}

// build validates code lengths (§ 5.2.1, "Decoder validation
// requirements") and rebuilds t as their canonical tree.
//
// It runs once per Huffman section, so it works from the number of codes
// of each length: no search, and no test per node where a range of nodes
// is known to be all leaves or all internal.
func (t *hufTree) build(lens *[hufNumSymbols]uint8) error {
	// Lengths are 4-bit fields: count all 16 values, absent symbols in
	// count[0], and test the out-of-range ones afterwards. Each quarter of
	// the symbols has its own counts, so that the increments of a run of
	// equal lengths do not wait on each other.
	var q [4][16]int
	for i := range hufNumSymbols / 4 {
		q[0][lens[i]&15]++
		q[1][lens[i+64]&15]++
		q[2][lens[i+128]&15]++
		q[3][lens[i+192]&15]++
	}
	var all [16]int
	for l := range all {
		all[l] = q[0][l] + q[1][l] + q[2][l] + q[3][l]
	}
	for l := hufMaxLen + 1; l < 16; l++ {
		if all[l] != 0 {
			return corruptf("Huffman code length %d > %d", l, hufMaxLen)
		}
	}
	var count [hufMaxLen + 1]int
	copy(count[1:], all[1:hufMaxLen+1])
	present := hufNumSymbols - all[0]
	maxLen := 0
	for l := hufMaxLen; l > 0; l-- {
		if count[l] != 0 {
			maxLen = l
			break
		}
	}
	switch {
	case present == 0:
		return corruptf("Huffman table without symbols")
	case present == 1:
		// The lone symbol is pinned at length 1: the root's left child.
		if count[1] != 1 {
			return corruptf("lone Huffman symbol must have length 1")
		}
	default:
		kraft := 0
		for l := 1; l <= hufMaxLen; l++ {
			kraft += count[l] << (hufMaxLen - l)
		}
		if kraft != 1<<hufMaxLen {
			return corruptf("Huffman code lengths not complete (Kraft sum %d/%d)", kraft, 1<<hufMaxLen)
		}
	}
	t.maxDepth = maxLen

	// The canonical tree, level by level (§ 5.2.1). Codes of length d are
	// consecutive, in symbol order, and come before the prefixes of longer
	// codes, so the nodes of depth d are the leaves of length d, in symbol
	// order, then the internal nodes; the j-th internal node of depth d has
	// its children at positions 2j and 2j+1 of depth d+1. Depth d has
	// width[d] nodes, from nodes[base[d]]: the root, then twice the
	// internal nodes of the depth above (one child, the lone symbol, under
	// a lone-symbol root). Nodes come out in BFS order, the wire order of
	// the runs. A complete code of 256 symbols at most has fewer than 512
	// nodes. The first node of depth d has code value code[d], the next
	// ones the values after it.
	var base [hufMaxLen + 2]int
	var width, code [hufMaxLen + 1]int
	w := 1
	for d := 0; d <= maxLen; d++ {
		if count[d] > w {
			return corruptf("Huffman code lengths not complete")
		}
		width[d] = w
		base[d+1] = base[d] + w
		if d < maxLen {
			code[d+1] = 2 * (code[d] + count[d])
		}
		if d == 0 && present == 1 {
			w = 1
		} else {
			w = 2 * (w - count[d])
		}
	}
	nn := base[maxLen+1]
	t.base, t.code = base, code

	// The symbols of each length, in symbol order; absent symbols go to
	// slots past the 256, never read. Each quarter of the symbols places
	// its own from where the quarters before it end, so the four run side
	// by side.
	syms := &t.syms
	var first [16]int
	var pos [4][16]int
	for l, p := 1, 0; l < 16; l++ {
		first[l] = p
		p += all[l]
	}
	first[0] = hufNumSymbols
	for l := range 16 {
		pos[0][l] = first[l]
		pos[1][l] = pos[0][l] + q[0][l]
		pos[2][l] = pos[1][l] + q[1][l]
		pos[3][l] = pos[2][l] + q[2][l]
	}
	const m = 2*hufNumSymbols - 1
	for i := range hufNumSymbols / 4 {
		l0, l1, l2, l3 := lens[i]&15, lens[i+64]&15, lens[i+128]&15, lens[i+192]&15
		syms[pos[0][l0]&m] = uint8(i)
		syms[pos[1][l1]&m] = uint8(i + 64)
		syms[pos[2][l2]&m] = uint8(i + 128)
		syms[pos[3][l3]&m] = uint8(i + 192)
		pos[0][l0]++
		pos[1][l1]++
		pos[2][l2]++
		pos[3][l3]++
	}

	for d := range t.leafBase {
		t.leafBase[d] = first[min(max(d, 1), 15)]
	}
	t.leafBase[0] = 0
	t.leafBase[maxLen+1] = present

	// Perfect-subtree heights, bottom-up: 0 for a leaf, one more than its
	// children's for an internal node whose two children have the same
	// height, incomplete otherwise and under the lone-symbol root.
	const incomplete = 0xFF
	h := t.height[:nn]
	for d := maxLen; d >= 0; d-- {
		b, L := base[d], count[d]
		hd := h[b : b+width[d]]
		for p := range hd[:L] {
			hd[p] = 0
		}
		if present == 1 {
			for p := L; p < len(hd); p++ {
				hd[p] = incomplete
			}
			continue
		}
		hc := h[base[d+1]:base[min(d+2, maxLen+1)]]
		for p := L; p < len(hd); p++ {
			j := 2 * (p - L)
			if x := hc[j]; x == hc[j+1] && x != incomplete {
				hd[p] = x + 1
			} else {
				hd[p] = incomplete
			}
		}
	}

	// Flat roots: the first node of perfect height >= 2 on every path from
	// the root (§ 5.2.1, a fixed format rule). The descendants of a node of
	// depth d and code value c are, at depth d+k, the nodes of values c<<k
	// to c<<k + 2^k - 1, in a row: those above depth d+D are covered, those
	// of depth d+D its leaves. The r-th leaf has packed code r bit-reversed
	// on D bits, as the packed code holds the branch at relative depth j in
	// bit j: the leaves' symbols are permuted to that order, an involution.
	flat := t.flat[:nn]
	clear(flat)
	for d := 0; d < maxLen; d++ {
		b, L := base[d], count[d]
		for p := L; p < width[d]; p++ {
			i := b + p
			D := int(h[i])
			if flat[i] != 0 || D < 2 || D == incomplete {
				continue
			}
			flat[i] = uint8(D)
			c := code[d] + p
			for k := 1; k < D; k++ {
				row := flat[base[d+k]+c<<k-code[d+k]:][:1<<k]
				for q := range row {
					row[q] = hufCovered
				}
			}
			s := t.syms[t.flatSyms(d, p, D):][:1<<D]
			sh := 8 - D
			for r := range s {
				if rr := int(bits.Reverse8(uint8(r)) >> sh); r < rr {
					s[r], s[rr] = s[rr], s[r]
				}
			}
		}
	}
	t.maxDepth = maxLen
	return nil
}

// popcountBits counts the 1 bits among the first c bits of b, LSB first;
// the padding bits of the last byte are ignored.
func popcountBits(b []byte, c int) int {
	ones := 0
	full := c / 8
	k := 0
	for ; k+32 <= full; k += 32 {
		w := b[k : k+32 : k+32] // one bounds check for the four words
		ones += bits.OnesCount64(binary.LittleEndian.Uint64(w[0:])) +
			bits.OnesCount64(binary.LittleEndian.Uint64(w[8:])) +
			bits.OnesCount64(binary.LittleEndian.Uint64(w[16:])) +
			bits.OnesCount64(binary.LittleEndian.Uint64(w[24:]))
	}
	for ; k+8 <= full; k += 8 {
		ones += bits.OnesCount64(binary.LittleEndian.Uint64(b[k:]))
	}
	for ; k < full; k++ {
		ones += bits.OnesCount8(b[k])
	}
	if r := c % 8; r != 0 {
		ones += bits.OnesCount8(b[full] & (1<<r - 1))
	}
	return ones
}

// hufDecoder holds the buffers of the Huffman decoder, reused from section
// to section.
type hufDecoder struct {
	// count[i] is the number of symbols routed through node i; the slot
	// after the last node stands for the lone-symbol root's absent child.
	count [hufMaxNodes + 1]int
	runs  [hufMaxLen + 1]int // first byte of the runs of each depth
	tmp   []byte             // the odd levels of the ping-pong
}

// spread[x] has byte j set to 0xFF when bit j of x is set.
var spread = func() (t [256]uint64) {
	for x := range 256 {
		for j := range 8 {
			if x>>j&1 != 0 {
				t[x] |= 0xFF << (8 * j)
			}
		}
	}
	return t
}()

// decode decodes the n symbols of a section body (the runs, after any
// inline table) into out[:n]; out must hold n + wildPad bytes.
//
// Where there is an assembly decoder (decodeFast), it decodes the section
// in one call; it hands the section back on anything off its fast path,
// errors included, and the Go code below decodes it then, with the same
// result and the same errors.
//
// Pass 1, in wire order, finds the symbol count of every node from its
// parent's popcount, and where the runs of each depth start, checking that
// they lie within the body. Pass 2 rebuilds the symbol sequence bottom-up,
// one depth at a time (§ 5.2.1): the sequence of a leaf is its symbol
// repeated, that of a flat root is its packed codes looked up, and that of
// a bitmap node interleaves its two children's sequences as its bits say.
// The runs and the children of a depth follow position order, so running
// offsets locate them. Each depth is written next to the previous one,
// alternately in out (even depths, so depth 0 ends in out) and in a
// scratch buffer (odd depths).
func (hd *hufDecoder) decode(t *hufTree, body []byte, n int, out []byte) error {
	if hd.decodeFast(t, body, n, out) {
		return nil
	}
	out = out[:n+wildPad] // the merges read up to 8 bytes past a sequence
	nn := t.base[t.maxDepth+1]
	cnt := hd.count[:nn+1]
	cnt[0], cnt[nn] = n, 0

	// Pass 1. Covered nodes and the children of flat roots and of leaf
	// pairs are routed no symbol of their own: count 0, an empty run. The
	// internal nodes of depth d, with their counts in in and their kinds in
	// fl, have their children's counts in ch, two each; under the
	// lone-symbol root, the second is the slot after the last node.
	p := 0
	for d := 0; d < t.maxDepth; d++ {
		hd.runs[d] = p
		b, L, e := t.base[d], t.leaves(d), t.base[d+1]
		in := cnt[b+L : e]
		fl := t.flat[b+L : e][:len(in)]
		ch := cnt[e : e+2*len(in)]
		Lc := t.leaves(d + 1)
		for j, c := range in {
			k := 2 * j
			if D := int(fl[j]); D != 0 {
				// A flat root, or a covered node: c is 0 there, as its
				// parent, flat or covered, gave its children no symbol.
				nb := (c*D + 7) >> 3
				if nb > len(body)-p {
					return corruptf("Huffman run of node %d past the section", b+L+j)
				}
				p += nb
				ch[k], ch[k+1] = 0, 0
				continue
			}
			nb := (c + 7) >> 3
			if nb > len(body)-p {
				return corruptf("Huffman run of node %d past the section", b+L+j)
			}
			ones := popcountBits(body[p:p+nb], c)
			p += nb
			if k+1 < Lc {
				ch[k], ch[k+1] = 0, 0 // a leaf pair: the node emits both leaves
			} else {
				ch[k], ch[k+1] = c-ones, ones
			}
		}
	}
	if cnt[nn] != 0 {
		return corruptf("Huffman bits route symbols to an absent node")
	}

	// Pass 2.
	hd.tmp = grow(hd.tmp, n+wildPad)
	syms := t.symTable()
	for d := t.maxDepth; d >= 0; d-- {
		buf, child := out, hd.tmp
		if d&1 != 0 {
			buf, child = hd.tmp, out
		}
		b, L, e := t.base[d], t.leaves(d), t.base[d+1]
		off := 0
		lc := cnt[b : b+L]
		for i, s := range t.syms[t.leafBase[d]:][:len(lc)] {
			if c := lc[i]; c != 0 {
				fillRun(buf, off, c, s)
				off += c
			}
		}
		if d == t.maxDepth {
			continue
		}
		rp := hd.runs[d]
		in := cnt[b+L : e]
		fl := t.flat[b+L : e][:len(in)]
		ch := cnt[e : e+2*len(in)]
		Lc := t.leaves(d + 1)
		csym := t.syms[t.leafBase[d+1]:]
		coff := 0
		for j, c := range in {
			k := 2 * j
			if c != 0 {
				dst := buf[off : off+c]
				switch D := int(fl[j]); {
				case D != 0: // a flat root: covered nodes have no symbol
					unpackFlat(dst, body[rp:], uint8(D), syms, t.flatSyms(d, L+j, D))
					rp += (c*D + 7) >> 3
				case k+1 < Lc:
					mergePair(dst, body[rp:], csym[k], csym[k+1])
					rp += (c + 7) >> 3
				default:
					merge(dst, child, coff, ch[k], body[rp:])
					rp += (c + 7) >> 3
				}
				off += c
			}
			coff += ch[k] + ch[k+1]
		}
	}
	return nil
}

// fillRun writes c copies of v at b[off:]. A run of up to 32 bytes is
// written as 32 bytes when b has room for them: the bytes past the run
// belong to the nodes that follow it in the level, written after it, or
// to the slack after the level.
func fillRun(b []byte, off, c int, v byte) {
	if c <= 32 && off <= len(b)-32 {
		w := uint64(v) * 0x0101010101010101
		x := b[off : off+32 : off+32]
		binary.LittleEndian.PutUint64(x[0:], w)
		binary.LittleEndian.PutUint64(x[8:], w)
		binary.LittleEndian.PutUint64(x[16:], w)
		binary.LittleEndian.PutUint64(x[24:], w)
		return
	}
	fill(b[off:off+c], v)
}

// fill sets every byte of b to v.
func fill(b []byte, v byte) {
	if len(b) == 0 {
		return
	}
	b[0] = v
	for k := 1; k < len(b); k *= 2 {
		copy(b[k:], b[:k])
	}
}

// bitWord returns the 64 bits of run starting at byte q, LSB first; bytes
// past the end of run read as zero.
func bitWord(run []byte, q int) uint64 {
	if q+8 <= len(run) {
		return binary.LittleEndian.Uint64(run[q:])
	}
	var w uint64
	for j := len(run) - 1; j >= q; j-- {
		w = w<<8 | uint64(run[j])
	}
	return w
}

// unpackFlat decodes the packed D-bit codes of a flat root: symbol k is
// the table entry of the k-th D-bit field of run. The table is
// fb[base : base+2^D]; a flat root has at most 256 leaves, so D <= 8 and
// every index stays in fb.
func unpackFlat(dst, run []byte, D uint8, fb *[hufNumSymbols]uint8, base int) {
	k := 0
	if haveHufAsm && D <= 6 && len(dst) >= 16 {
		// 16 symbols a step in assembly, the rest below.
		k = flatFast(dst, run, D, fb[base:base+1<<D])
	}
	mask := uint64(1)<<D - 1
	b := uint64(base)
	bitPos := k * int(D)
	for k < len(dst) {
		sh := bitPos & 7
		w := bitWord(run, bitPos>>3) >> sh
		// Whole codes left in the word after the shift (at least 57 bits,
		// so at least 7 codes of up to 8 bits).
		m := min((64-sh)/int(D), len(dst)-k)
		o := dst[k : k+m]
		for j := range o {
			o[j] = fb[(b+w&mask)&255]
			w >>= D
		}
		k += m
		bitPos += m * int(D)
	}
}

// mergePair decodes a bitmap node whose children are both leaves: symbol k
// is s1 where bit k is set, s0 elsewhere. Eight symbols at a time.
func mergePair(dst, run []byte, s0, s1 byte) {
	rep0 := uint64(s0) * 0x0101010101010101
	delta := uint64(s0^s1) * 0x0101010101010101
	k := 0
	for ; k+8 <= len(dst); k += 8 {
		binary.LittleEndian.PutUint64(dst[k:], rep0^spread[run[k>>3]]&delta)
	}
	if k < len(dst) {
		w := rep0 ^ spread[run[k>>3]]&delta
		for j := k; j < len(dst); j++ {
			dst[j] = byte(w)
			w >>= 8
		}
	}
}

// mergeIdx[x][j] is where output j of a merge step whose 8 bits are x
// takes its symbol in a 16-byte window holding the next 8 left symbols
// then the next 8 right ones; mergeOnes[x] is how many come from the right.
var mergeIdx, mergeOnes = func() (idx [256][8]uint8, ones [256]uint8) {
	for x := range 256 {
		l, r := 0, 8
		for j := range 8 {
			if x>>j&1 != 0 {
				idx[x][j] = uint8(r)
				r++
			} else {
				idx[x][j] = uint8(l)
				l++
			}
		}
		ones[x] = uint8(r - 8)
	}
	return idx, ones
}()

// merge interleaves two child sequences into dst as the node's bits in run
// say: symbol k comes from the right where bit k is set. The left
// sequence is ch[lo:lo+nl], the right one follows it; ch must be readable
// 8 bytes past the right sequence (the level buffers carry wildPad bytes
// of slack).
func merge(dst, ch []byte, lo, nl int, run []byte) {
	l, r := lo, lo+nl
	k := 0
	if haveHufAsm && len(dst) >= 16 {
		// 16 symbols a step in assembly, then the steps of 8 and the tail
		// below.
		k, l, r = mergeFast(dst, ch, l, r, run)
	}
	for ; k+8 <= len(dst); k += 8 {
		x := run[k>>3]
		var w [16]byte
		binary.LittleEndian.PutUint64(w[:8], binary.LittleEndian.Uint64(ch[l:]))
		binary.LittleEndian.PutUint64(w[8:], binary.LittleEndian.Uint64(ch[r:]))
		idx := &mergeIdx[x]
		o := dst[k : k+8 : k+8]
		o[0] = w[idx[0]&15]
		o[1] = w[idx[1]&15]
		o[2] = w[idx[2]&15]
		o[3] = w[idx[3]&15]
		o[4] = w[idx[4]&15]
		o[5] = w[idx[5]&15]
		o[6] = w[idx[6]&15]
		o[7] = w[idx[7]&15]
		p := int(mergeOnes[x])
		l += 8 - p
		r += p
	}
	// Tail: fewer than 8 symbols, one at a time.
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
