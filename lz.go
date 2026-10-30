package zxc

import (
	"encoding/binary"
	"fmt"
)

// Constants shared by the SPL and PAK block decoders (§ 5.2, § 5.3).
const (
	lzHeaderSize = 12 // SPL and PAK sub-header
	litSlack     = 32 // bytes that must follow the literal section
	minMatch     = 5  // smallest match length; stored lengths are biased by it

	encRAW         = 0
	encRLE         = 1
	encHuffman     = 2
	encHuffmanDict = 3

	splTokenMask = 15  // 4-bit LL and ML fields of a SPL token
	pakLenMask   = 255 // 8-bit LL and ML fields of a PAK sequence word
)

// lzHeader is the 12-byte sub-header shared by SPL and PAK blocks.
type lzHeader struct {
	nSeq   uint32 // number of sequences
	nLit   uint32 // number of literal bytes, after entropy/RLE decoding
	encLit byte   // literal section encoding
	encTok byte   // token section encoding (SPL)
	encOff byte   // offset width (SPL): 0 = 16 bits, 1 = 8 bits
}

func parseLZHeader(p []byte) (lzHeader, error) {
	if len(p) < lzHeaderSize {
		return lzHeader{}, ErrBadHeader
	}
	return lzHeader{
		nSeq:   binary.LittleEndian.Uint32(p[0:]),
		nLit:   binary.LittleEndian.Uint32(p[4:]),
		encLit: p[8],
		encTok: p[9],
		// p[10], Match Length Encoding, is reserved and ignored on decode.
		encOff: p[11],
	}, nil
}

// copyMatch appends to out[d:] the ml bytes found off bytes behind d, with
// LZ77 semantics: when off < ml the source overlaps the destination and the
// last off bytes repeat. The caller has checked 1 <= off <= d and
// d+ml <= len(out).
func copyMatch(out []byte, d, off, ml int) {
	src := d - off
	end := d + ml
	if off >= ml {
		copy(out[d:end], out[src:src+ml])
		return
	}
	// Overlap: out[src:d] is one period of the pattern. Each copy appends
	// everything written since src, so the copied span doubles each time
	// and an offset-1 run of n bytes takes log2(n) copies.
	for d < end {
		d += copy(out[d:end], out[src:d])
	}
}

// wildPad is the slack that lets literal and match copies run in whole 16-
// and 32-byte strides ("wild copies") instead of exact-length copy calls.
// They may write up to 31 bytes past the end of a sequence, and read up to
// 31 bytes past the last literal:
//   - the output window carries wildPad bytes of capacity behind the block
//     size; whatever a wild copy leaves there is overwritten by the next
//     sequence or cut off when the block is done;
//   - RAW literals are read in place, and the format guarantees 32 readable
//     bytes behind the literal section (§ 5.2, "Literal section slack");
//   - decoded RLE literals get wildPad bytes of scratch behind them.
const wildPad = 32

// scratch holds the buffers a block decoder needs beyond its output,
// reused from block to block.
type scratch struct {
	lits []byte     // decoded RLE or Huffman literals, wildPad bytes of slack behind
	toks []byte     // decoded Huffman tokens
	huf  hufDecoder // Huffman decoding buffers

	// The trees of the last inline literal and token tables: consecutive
	// blocks often carry the same tables, and building a tree costs more
	// than comparing 128 bytes. Each tree's storage is reused otherwise.
	litTree, tokTree inlineTree
}

// inlineTree caches the tree of one inline Huffman table.
type inlineTree struct {
	table [hufTableSize]byte
	tree  hufTree
	valid bool
}

// get returns the tree of the 128-byte code-length table that opens an
// inline Huffman section, and the rest of the section.
func (it *inlineTree) get(sec []byte) (*hufTree, []byte, error) {
	if len(sec) < hufTableSize {
		return nil, nil, corruptf("Huffman section shorter than its table")
	}
	table := sec[:hufTableSize]
	if !it.valid || string(table) != string(it.table[:]) {
		it.valid = false
		lens := unpackLengths(table)
		if err := it.tree.build(&lens); err != nil {
			return nil, nil, err
		}
		copy(it.table[:], table)
		it.valid = true
	}
	return &it.tree, sec[hufTableSize:], nil
}

// grow returns b with length n, reusing its storage when large enough.
func grow(b []byte, n int) []byte {
	if cap(b) < n {
		return make([]byte, n)
	}
	return b[:n]
}

// lzOutput writes the sequences of one block. Every copy is checked against
// the logical bounds (limit, litEnd) before it runs; only its stride may
// spill into the padding.
type lzOutput struct {
	out    []byte // output window: block size + wildPad bytes
	limit  int    // block size: no block may decode past it (§ 11.1)
	d      int    // write position in out
	base   int    // where the block starts in out: the dictionary size
	lits   []byte // literals, readable wildPad bytes past litEnd
	litEnd int    // number of literals
	l      int    // literals consumed
}

// newLZOutput starts writing at out[base:]. base is the length of the
// dictionary prefix, 0 without one: matches may reach back into it, and the
// block itself runs from base to base + block size.
func newLZOutput(out []byte, base int, lits []byte, litEnd int) lzOutput {
	return lzOutput{out: out, limit: len(out) - wildPad, d: base, base: base, lits: lits, litEnd: litEnd}
}

// emit writes one sequence: ll literals, then a match of ml bytes at
// distance off. It handles every case and does every check.
//
// The block decoders first run a fast path (pakFast, splFast8, splFast16 in
// fast_safe.go or fast_unsafe.go) for the common shape: at most 32 literals
// and a match of at most 32 bytes at distance 32 or more, the vast majority
// of sequences at levels 1 to 5. Its checks are the same as emit's; its
// copies are a single fixed-size move each, which those bounds make safe:
// the reads stay inside the literal slack or behind d, the writes inside the
// output padding. Every other sequence goes through emit.
func (o *lzOutput) emit(ll, ml, off int) error {
	d, l := o.d, o.l
	if ll > o.limit-d || ml > o.limit-d-ll {
		return corruptf("block decodes past the block size")
	}
	if ll > o.litEnd-l {
		return corruptf("sequence reads past the literal section")
	}

	// Literals: fixed-size moves for short runs, copy (memmove) otherwise.
	switch {
	case ll <= 16:
		copy16(o.out[d:], o.lits[l:])
	case ll <= 32:
		copy32(o.out[d:], o.lits[l:])
	default:
		copy(o.out[d:d+ll], o.lits[l:l+ll])
	}
	d += ll
	o.l = l + ll

	if off > d {
		return corruptf("match offset %d reaches before the block start (%d bytes written)", off, d)
	}
	src := d - off

	// Match. A stride never reads past d: with off >= 16 each 16-byte chunk
	// reads bytes written before it, which also handles overlapping matches
	// whose period is at least 16.
	switch {
	case off >= 16 && ml <= 16:
		copy16(o.out[d:], o.out[src:])
	case off >= 32 && ml <= 32:
		copy32(o.out[d:], o.out[src:])
	case off >= ml:
		copy(o.out[d:d+ml], o.out[src:src+ml])
	case off >= 16:
		for k := 0; k < ml; k += 16 {
			copy16(o.out[d+k:], o.out[src+k:])
		}
	default:
		copyMatch(o.out, d, off, ml) // short period: exact doubling copies
	}
	o.d = d + ml
	return nil
}

// finish copies the trailing literals, those left after the last sequence,
// and returns the decoded size of the block, dictionary prefix excluded.
func (o *lzOutput) finish() (int, error) {
	rest := o.litEnd - o.l
	if rest > o.limit-o.d {
		return 0, corruptf("trailing literals exceed the block size")
	}
	copy(o.out[o.d:o.d+rest], o.lits[o.l:o.litEnd])
	return o.d + rest - o.base, nil
}

// decodePAK decodes the payload p of a PAK block (§ 5.3) into out[base:]
// and returns the number of bytes produced. out holds the dictionary prefix
// (base bytes, 0 without a dictionary), then room for one block plus
// wildPad bytes.
func decodePAK(out []byte, base int, p []byte) (int, error) {
	h, err := parseLZHeader(p)
	if err != nil {
		return 0, err
	}
	if h.encLit != encRAW || h.encTok != 0 {
		return 0, corruptf("PAK block with literal/token encoding %d/%d", h.encLit, h.encTok)
	}
	// Offset Encoding is unused in PAK and must be ignored.

	// Sections: literals, one 4-byte word per sequence, extras (the rest).
	body := p[lzHeaderSize:]
	nLit := uint64(h.nLit)
	seqBytes := uint64(h.nSeq) * 4
	if nLit+seqBytes > uint64(len(body)) {
		return 0, corruptf("PAK sections overrun the payload")
	}
	if uint64(len(body))-nLit < litSlack {
		return 0, corruptf("fewer than %d bytes behind the literal section", litSlack)
	}
	seqs := body[nLit : nLit+seqBytes]
	extras := body[nLit+seqBytes:]

	o := newLZOutput(out, base, body, int(nLit))
	e := 0
	for i := 0; i < len(seqs); i += 4 {
		// Run the fast path as far as it goes; it stops on the first
		// sequence it cannot take.
		if i, o.d, o.l, e = pakRun(&o, seqs, extras, i, e); i == len(seqs) {
			break
		}
		s := binary.LittleEndian.Uint32(seqs[i:])
		ll := int(s >> 24)
		mb := int(s >> 16 & 0xFF)
		off := int(s&0xFFFF) + 1 // stored biased by one
		ml := mb + minMatch
		if ll == pakLenMask {
			var v uint32
			if v, e, err = readVarint(extras, e); err != nil {
				return 0, err
			}
			ll += int(v)
		}
		if mb == pakLenMask {
			var v uint32
			if v, e, err = readVarint(extras, e); err != nil {
				return 0, err
			}
			ml += int(v)
		}
		if err := o.emit(ll, ml, off); err != nil {
			return 0, err
		}
	}
	return o.finish()
}

// decodeSPL decodes the payload p of a SPL block (§ 5.2) into out[base:],
// laid out as for decodePAK, and returns the number of bytes produced.
// sc holds the scratch buffers for decoded sections, reused across blocks;
// dict is the frame's dictionary, nil without one, whose shared Huffman
// table literal encoding 3 refers to.
func decodeSPL(out []byte, base int, p []byte, sc *scratch, dict *Dictionary) (int, error) {
	b, err := prepareSPL(out, base, p, sc, dict)
	if err != nil {
		return 0, err
	}
	o, tokens, offs, extras, offWidth := &b.o, b.tokens, b.offs, b.extras, b.offWidth
	e := 0
	for i := 0; i < len(tokens); i++ {
		// Run the fast path as far as it goes; it stops on the first
		// sequence it cannot take.
		if i, o.d, o.l, e = splRun(o, tokens, offs, extras, offWidth, i, e); i == len(tokens) {
			break
		}
		t := tokens[i]
		ll := int(t >> 4)
		ml := int(t & splTokenMask)
		var off int
		if offWidth == 1 {
			off = int(offs[i]) + 1
		} else {
			off = int(binary.LittleEndian.Uint16(offs[2*i:])) + 1
		}
		if ll == splTokenMask {
			var v uint32
			if v, e, err = readVarint(extras, e); err != nil {
				return 0, err
			}
			ll += int(v)
		}
		if ml == splTokenMask {
			var v uint32
			if v, e, err = readVarint(extras, e); err != nil {
				return 0, err
			}
			ml += int(v)
		}
		if err := o.emit(ll, ml+minMatch, off); err != nil {
			return 0, err
		}
	}
	return o.finish()
}

// splBlock is a SPL block ready for its sequence loop: the output window,
// the decoded literals and tokens, and the offset and extras sections.
type splBlock struct {
	o        lzOutput
	tokens   []byte
	offs     []byte
	extras   []byte
	offWidth int
}

// prepareSPL checks the header and sections of the SPL payload p, decodes
// its literal and token sections if they are encoded, and sets up the
// output window out[base:] (see decodeSPL).
func prepareSPL(out []byte, base int, p []byte, sc *scratch, dict *Dictionary) (splBlock, error) {
	h, err := parseLZHeader(p)
	if err != nil {
		return splBlock{}, err
	}
	// Closed value sets: anything undefined is rejected (§ 5.2).
	if h.encOff > 1 {
		return splBlock{}, corruptf("SPL offset encoding %d", h.encOff)
	}
	if h.encLit > encHuffmanDict {
		return splBlock{}, corruptf("SPL literal encoding %d", h.encLit)
	}
	if h.encTok != encRAW && h.encTok != encHuffman {
		return splBlock{}, corruptf("SPL token encoding %d", h.encTok)
	}

	// Section descriptors: only the sizes the header cannot imply, the
	// literal section's when it is encoded, the token section's when it is
	// Huffman-coded.
	pos := lzHeaderSize
	litComp := uint64(h.nLit)
	if h.encLit != encRAW {
		if len(p) < pos+4 {
			return splBlock{}, ErrBadHeader
		}
		litComp = uint64(binary.LittleEndian.Uint32(p[pos:]))
		pos += 4
	}
	nSeq := uint64(h.nSeq)
	tokComp := nSeq
	if h.encTok == encHuffman {
		if len(p) < pos+4 {
			return splBlock{}, ErrBadHeader
		}
		tokComp = uint64(binary.LittleEndian.Uint32(p[pos:]))
		pos += 4
	}
	body := p[pos:]

	// Sections: literals, tokens, offsets, extras (the rest).
	offWidth := uint64(2)
	if h.encOff == 1 {
		offWidth = 1
	}
	if litComp+tokComp+nSeq*offWidth > uint64(len(body)) {
		return splBlock{}, corruptf("SPL sections overrun the payload")
	}
	if uint64(len(body))-litComp < litSlack {
		return splBlock{}, corruptf("fewer than %d bytes behind the literal section", litSlack)
	}
	litSec := body[:litComp]
	tokens := body[litComp : litComp+tokComp]
	offs := body[litComp+tokComp : litComp+tokComp+nSeq*offWidth]
	extras := body[litComp+tokComp+nSeq*offWidth:]

	blockSize := uint64(len(out) - wildPad - base)
	if h.encLit != encRAW && uint64(h.nLit) > blockSize {
		return splBlock{}, corruptf("%d literals exceed the block size", h.nLit)
	}
	if nSeq > blockSize {
		return splBlock{}, corruptf("%d sequences exceed the block size", nSeq)
	}

	// RAW literals are read in place; the section slack checked above keeps
	// wild reads inside the payload. Encoded ones are decoded into scratch,
	// with wildPad bytes of slack behind them.
	lits := body
	nLit := int(h.nLit)
	switch h.encLit {
	case encRLE:
		if sc.lits, err = expandRLE(sc.lits, litSec, nLit); err != nil {
			return splBlock{}, err
		}
		lits = sc.lits[:nLit+wildPad]
	case encHuffman, encHuffmanDict:
		sc.lits = grow(sc.lits, nLit+wildPad)
		if nLit > 0 { // an empty section is not decoded
			var tree *hufTree
			sec := litSec
			if h.encLit == encHuffmanDict {
				if dict == nil || dict.tree == nil {
					return splBlock{}, fmt.Errorf("%w: literal encoding 3 needs a dictionary with a shared Huffman table", ErrDictRequired)
				}
				tree = dict.tree
			} else if tree, sec, err = sc.litTree.get(litSec); err != nil {
				return splBlock{}, err
			}
			if err := sc.huf.decode(tree, sec, nLit, sc.lits); err != nil {
				return splBlock{}, err
			}
		}
		lits = sc.lits[:nLit+wildPad]
	}

	// Huffman-coded tokens (level 7) are decoded likewise; the decoders
	// below then read them from scratch.
	if h.encTok == encHuffman {
		if nSeq == 0 {
			return splBlock{}, corruptf("Huffman token section for no sequence")
		}
		tree, sec, err := sc.tokTree.get(tokens)
		if err != nil {
			return splBlock{}, err
		}
		sc.toks = grow(sc.toks, int(nSeq)+wildPad)
		if err := sc.huf.decode(tree, sec, int(nSeq), sc.toks); err != nil {
			return splBlock{}, err
		}
		tokens = sc.toks[:nSeq]
	}

	return splBlock{
		o:        newLZOutput(out, base, lits, int(h.nLit)),
		tokens:   tokens,
		offs:     offs,
		extras:   extras,
		offWidth: int(offWidth),
	}, nil
}

// expandRLE decodes an RLE literal section (§ 5.2.3) of n bytes into buf,
// grown as needed, and returns buf[:n]; its capacity leaves wildPad bytes
// behind the literals. The runs must produce exactly n bytes and use the
// whole section.
func expandRLE(buf, sec []byte, n int) ([]byte, error) {
	if cap(buf) < n+wildPad {
		buf = make([]byte, n+wildPad)
	}
	buf = buf[:n]
	w, r := 0, 0
	for r < len(sec) && w < n {
		t := sec[r]
		r++
		if t < 0x80 {
			// Literal run: t+1 bytes copied as is.
			k := int(t) + 1
			if k > n-w || k > len(sec)-r {
				return nil, corruptf("RLE literal run overruns")
			}
			copy(buf[w:], sec[r:r+k])
			w += k
			r += k
		} else {
			// Repeat run: one byte written (t & 0x7F) + 4 times.
			k := int(t&0x7F) + 4
			if k > n-w || r >= len(sec) {
				return nil, corruptf("RLE repeat run overruns")
			}
			v := sec[r]
			r++
			run := buf[w : w+k]
			for j := range run {
				run[j] = v
			}
			w += k
		}
	}
	if w != n || r != len(sec) {
		return nil, corruptf("RLE section does not decode to exactly %d bytes", n)
	}
	return buf, nil
}

// corruptf returns ErrCorrupt with a description of what was found wrong.
// It is only called on failure paths.
func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrCorrupt}, args...)...)
}
