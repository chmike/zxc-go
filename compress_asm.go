//go:build !purego && (arm64 || amd64)

package zxc

import (
	"slices"
	"unsafe"
)

// Assembly parsers of the encoder (compress_arm64.s, compress_amd64.s).
// Each runs the whole parse of a block in one call, the match finder
// inline, and leaves the block's streams in the encoder's buffers; the Go
// code keeps the frame, the headers and the choices made once per block.

const havePakEncAsm = true

// encState is what pakEncAsm and splEncAsm read and write.
// TestEncStateLayout checks the offsets the assembly uses.
type encState struct {
	src        unsafe.Pointer // 0: the window, dictionary content then block
	ip         int            // 8: first position of the block
	iend       int            // 16: len(window)
	limit      int            // 24: no match starts at or after it, iend - 8
	head       unsafe.Pointer // 32: matcher.head
	tags       unsafe.Pointer // 40: matcher.tags
	chain      unsafe.Pointer // 48: matcher.chain
	epochMark  uint64         // 56
	offsetMask uint64         // 64
	minOffset  int            // 72
	sufficient int            // 80: lzParams.sufficientLen
	stepBase   int            // 88
	stepShift  int            // 96
	lits       unsafe.Pointer // 104: next literal byte; on return, the end
	seqs       unsafe.Pointer // 112: next sequence word; on return, the end
	extras     unsafe.Pointer // 120: next extras byte; on return, the end
	anchor     int            // 128: on return, the first unparsed literal

	// SPL only (PAK writes words to seqs; SPL writes tokens there).
	offs    unsafe.Pointer // 136: next offset; on return, the end
	maxOff  uint64         // 144: on return, the largest offset minus 1
	depth   int            // 152: lzParams.searchDepth
	lazyAtt int            // 160: lzParams.lazyAttempts
	lazyLen int            // 168: lzParams.lazyLenThreshold
	level   int            // 176
	scratch int            // 184: the assembly's spill
}

// pakEncAsm parses the block of st as the loop of appendPAK does, for
// levels 1 and 2.
//
//go:noescape
func pakEncAsm(st *encState)

// splEncAsm parses the block of st as lazyParse does, for levels 3 to 5.
//
//go:noescape
func splEncAsm(st *encState)

// pakParseFast parses the block src[start:] for appendPAK with pakEncAsm,
// into e.lits, e.seqs and e.extras, the trailing literals included, and
// reports whether it did; when not, the Go loop runs.
//
// Proof of the accesses of pakEncAsm. Positions ip run from start while ip
// < limit = len(src) - 8, so the 8-byte load at ip stays in src. A head
// entry of the current epoch holds a position already inserted, below ip;
// a chain link d of position q was q - p for an earlier position p, so an
// entry reached from a candidate below ip is below ip too, or, when the
// link was overwritten by a position 65536 further, wraps below 0 as a
// 32-bit value, which the distance test ip - idx <= 65535 rejects since ip
// is then above 65535 (a link is only overwritten past position 65536).
// A candidate ref < ip reads 4 bytes at ref and at ref + len - 3, and the
// match length compares src[ip+k] and src[ref+k] for ip + k < iend only;
// len < iend - ip holds at the gate (a longer match stops the walk), so
// ip + len + 1 <= iend. Backtracking reads src[ip-1] and src[ref-1] only
// with ip > anchor >= 0 and ref > 0. Tables: h < 2^15, ip & 0xFFFF and
// idx & 0xFFFF index head, tags and chain. Outputs: the literals copied
// are those of the block, at most len(src) - start bytes; each sequence
// covers 5 bytes at least, so at most (len(src) - start) / 5 words; each
// varint of 1 to 3 bytes follows 255 literals or match bytes at least.
// The buffers are grown to those bounds below.
func (e *encoder) pakParseFast(src []byte, start int, p *lzParams) bool {
	n := len(src) - start
	limit := len(src) - lzSearchMargin
	if limit <= start {
		return false
	}
	e.lits = grow(e.lits, n)
	e.seqs = growU32(e.seqs, n/lzMinMatch+1)
	e.extras = grow(e.extras, 3*(n/pakLenMask+1)*2)
	m := &e.m
	st := encState{
		src:        unsafe.Pointer(unsafe.SliceData(src)),
		ip:         start,
		iend:       len(src),
		limit:      limit,
		head:       unsafe.Pointer(&m.head[0]),
		tags:       unsafe.Pointer(&m.tags[0]),
		chain:      unsafe.Pointer(&m.chain[0]),
		epochMark:  uint64(m.epochMark),
		offsetMask: uint64(m.offsetMask),
		minOffset:  p.minOffset,
		sufficient: p.sufficientLen,
		stepBase:   p.stepBase,
		stepShift:  p.stepShift,
		lits:       unsafe.Pointer(unsafe.SliceData(e.lits)),
		seqs:       unsafe.Pointer(unsafe.SliceData(e.seqs)),
		extras:     unsafe.Pointer(unsafe.SliceData(e.extras)),
	}
	pakEncAsm(&st)
	nl := int(uintptr(st.lits) - uintptr(unsafe.Pointer(unsafe.SliceData(e.lits))))
	ns := int(uintptr(st.seqs)-uintptr(unsafe.Pointer(unsafe.SliceData(e.seqs)))) / 4
	nx := int(uintptr(st.extras) - uintptr(unsafe.Pointer(unsafe.SliceData(e.extras))))
	e.lits = append(e.lits[:nl], src[st.anchor:]...)
	e.seqs = e.seqs[:ns]
	e.extras = e.extras[:nx]
	return true
}

// growU32 returns s with room for n elements.
func growU32(s []uint32, n int) []uint32 {
	if cap(s) < n {
		return make([]uint32, n)
	}
	return s[:n]
}

// splParseFast parses the block src[start:] for lazyParse with splEncAsm,
// into e.lits, e.toks, e.offs and e.extras, the trailing literals included,
// and returns the largest offset minus 1 and true; false when it did not
// run, the Go loop then running.
//
// Proof of the accesses of splEncAsm: those of pakParseFast, the hash
// covering 5 bytes of the 8 loaded, plus:
//   - a lazy probe at lp = ip+1 or ip+2 < limit, for need = len+2 or +3
//     bytes, runs only when need <= iend - lp; it loads 8 bytes at lp < limit
//     and 4 at lp + need - 4, and for a candidate ref < lp, 4 bytes at ref
//     and at ref + need - 4, and 8-byte words within [ref, ref+need) and
//     [lp, lp+need), so up to lp + need <= iend;
//   - the level-5 insertion of position pos = end - 2, end = ip + len, runs
//     when end < iend - 7, so its 8-byte load ends at end + 6 < iend.
//
// Outputs: a token and an offset per sequence, at most n / 5 + 1 of each;
// an extras varint, 3 bytes at most, follows 15 literals or 20 match bytes
// at least.
func (e *encoder) splParseFast(src []byte, start int, p *lzParams) (uint16, bool) {
	n := len(src) - start
	limit := len(src) - lzSearchMargin
	if limit <= start {
		return 0, false
	}
	e.lits = grow(e.lits, n)
	e.toks = grow(e.toks, n/lzMinMatch+1)
	if cap(e.offs) < n/lzMinMatch+1 {
		e.offs = make([]uint16, n/lzMinMatch+1)
	}
	e.offs = e.offs[:n/lzMinMatch+1]
	e.extras = grow(e.extras, 3*2*(n/splTokenMask+1))
	m := &e.m
	st := encState{
		src:        unsafe.Pointer(unsafe.SliceData(src)),
		ip:         start,
		iend:       len(src),
		limit:      limit,
		head:       unsafe.Pointer(&m.head[0]),
		tags:       unsafe.Pointer(&m.tags[0]),
		chain:      unsafe.Pointer(&m.chain[0]),
		epochMark:  uint64(m.epochMark),
		offsetMask: uint64(m.offsetMask),
		minOffset:  p.minOffset,
		sufficient: p.sufficientLen,
		stepBase:   p.stepBase,
		stepShift:  p.stepShift,
		lits:       unsafe.Pointer(unsafe.SliceData(e.lits)),
		seqs:       unsafe.Pointer(unsafe.SliceData(e.toks)),
		extras:     unsafe.Pointer(unsafe.SliceData(e.extras)),
		offs:       unsafe.Pointer(unsafe.SliceData(e.offs)),
		depth:      p.searchDepth,
		lazyAtt:    p.lazyAttempts,
		lazyLen:    p.lazyLenThreshold,
		level:      e.level,
	}
	splEncAsm(&st)
	nl := int(uintptr(st.lits) - uintptr(unsafe.Pointer(unsafe.SliceData(e.lits))))
	ns := int(uintptr(st.seqs) - uintptr(unsafe.Pointer(unsafe.SliceData(e.toks))))
	nx := int(uintptr(st.extras) - uintptr(unsafe.Pointer(unsafe.SliceData(e.extras))))
	e.lits = append(e.lits[:nl], src[st.anchor:]...)
	e.toks = e.toks[:ns]
	e.offs = e.offs[:ns]
	e.extras = e.extras[:nx]
	return uint16(st.maxOff), true
}

// splitState is what splitAsm reads and writes. TestEncStateLayout checks
// the offsets the assembly uses.
type splitState struct {
	toks   unsafe.Pointer // 0: n tokens, room for 2n
	offs   unsafe.Pointer // 8: n offsets, room for 2n
	extras unsafe.Pointer // 16
	side   unsafe.Pointer // 24: n bytes
	hist   unsafe.Pointer // 32: [2][256]uint32 scratch
	bad    unsafe.Pointer // 40: [256]byte scratch
	n      int            // 48: tokens; on return, after the split
	limit  int            // 56: longest length code split
	nx     int            // 64: on return, the extras' length
	split  int            // 72: on return, 1 when the block was split
}

// splitAsm runs splitAnalyze and, when it says so, the two passes of
// splitMatches.
//
//go:noescape
func splitAsm(st *splitState)

// splitFast runs splitMatches with splitAsm, for limits up to 33, where a
// split match has 2 pieces at most, and reports whether it did.
//
// Proof of the accesses of splitAsm: it reads the n tokens and writes the
// n side bytes; hist and bad index by contexts below 2^8; the extras are
// read through the varints the tokens' escapes announce, which the encoder
// wrote, each found where the previous one ends, so within extras, and
// written back at or below where they were read; the expansion writes
// toks[k] and offs[k] for k < n + extra, extra being at most the number of
// split sequences, so at most n: below the 2n of room made here.
func (e *encoder) splitFast(toks []byte, offs []uint16, extras []byte, limit int) ([]byte, []uint16, []byte, bool) {
	n := len(toks)
	if limit > 33 || n == 0 || len(offs) != n {
		return toks, offs, extras, false
	}
	if cap(toks) < 2*n {
		t := make([]byte, n, 2*n)
		copy(t, toks)
		toks = t
	}
	if cap(offs) < 2*n {
		o := make([]uint16, n, 2*n)
		copy(o, offs)
		offs = o
	}
	var hist [2][256]uint32
	var bad [256]byte
	st := splitState{
		toks:   unsafe.Pointer(unsafe.SliceData(toks)),
		offs:   unsafe.Pointer(unsafe.SliceData(offs)),
		extras: unsafe.Pointer(unsafe.SliceData(extras)),
		side:   unsafe.Pointer(unsafe.SliceData(e.side)),
		hist:   unsafe.Pointer(&hist),
		bad:    unsafe.Pointer(&bad),
		n:      n,
		limit:  limit,
		nx:     len(extras),
	}
	splitAsm(&st)
	return toks[:st.n], offs[:st.n], extras[:st.nx], true
}

// rleState is what rleAsm reads and writes.
type rleState struct {
	lits unsafe.Pointer // 0
	n    int            // 8
	out  unsafe.Pointer // 16: where to write the section, nil for its size only; on return, its end
	size int            // 24: on return, the section's size
}

// rleAsm computes the size of the RLE section of n literals, and writes it
// when out is not nil.
//
//go:noescape
func rleAsm(st *rleState)

// rleFast is rleSize, and appendRLE when dst is not nil, with rleAsm. It
// returns the size, and dst with the section appended.
//
// Proof of the accesses of rleAsm. It reads lits[i] for i < n; the 8-byte
// run steps load lits[i:i+8] with i + 8 <= n; the 16-position steps of the
// copy search load 16 bytes at i, i+1, i+2 and i+3 with i + 19 <= n; a
// copy piece reads its c bytes, within the copy, exactly (16-byte steps,
// the last one ending at the piece's end, or two overlapping halves). It
// writes the section, at most n + n/128 + 1 bytes: a run of r >= 4 bytes
// takes at most r bytes, a copy of c bytes c + ceil(c/128); dst is grown
// to that bound below.
func rleFast(dst, lits []byte, write bool) (int, []byte) {
	st := rleState{n: len(lits)}
	if len(lits) == 0 {
		return 0, dst
	}
	st.lits = unsafe.Pointer(unsafe.SliceData(lits))
	at := len(dst)
	if write {
		dst = slices.Grow(dst, len(lits)+len(lits)/128+1)
		st.out = unsafe.Pointer(unsafe.SliceData(dst[at:cap(dst)]))
	}
	rleAsm(&st)
	if write {
		dst = dst[:at+st.size]
	}
	return st.size, dst
}

// optState is what optEncAsm reads and writes. TestEncStateLayout checks
// the offsets the assembly uses.
type optState struct {
	src        unsafe.Pointer // 0: the window, dictionary content then block
	start      int            // 8: first position of the block
	iend       int            // 16: len(window)
	limit      int            // 24: start + searchLimit
	head       unsafe.Pointer // 32
	tags       unsafe.Pointer // 40
	chain      unsafe.Pointer // 48
	epochMark  uint64         // 56
	offsetMask uint64         // 64
	dp         unsafe.Pointer // 72: dp[0], for position start
	parentLen  unsafe.Pointer // 80
	parentOff  unsafe.Pointer // 88
	litCost    uint64         // 96
	depth      int            // 104
	sufficient int            // 112
	skipUntil  int            // 120: positions, as ip
	lastOff    int            // 128
	prevP      int            // 136
	prevLen    int            // 144
}

// optEncAsm runs the dynamic program of optimalDP, findBestMatch inline,
// for levels 6 and 7.
//
//go:noescape
func optEncAsm(st *optState)

// optParseFast runs optimalDP with optEncAsm and reports whether it did.
//
// Proof of the accesses of optEncAsm: those of splParseFast for the hash,
// the tables and the chain walk, plus:
//   - the previous offset lastOff is tried only when 0 < lastOff <= 65535
//     and lastOff <= ip, so ref = ip - lastOff >= 0; its 4-byte test and
//     match length read as a chain candidate's;
//   - dp, parentLen and parentOff, of n+1 entries, are indexed by ip -
//     start for ip < iend: the position, ip+1 <= iend for a literal, and
//     ip+L for 5 <= L <= lMax <= iend - ip for a match.
func (e *encoder) optParseFast(src []byte, start int, p *lzParams, litCost uint32) bool {
	n := len(src) - start
	if n < lzSearchMargin+1 || len(e.dp) < n+1 || len(e.parentLen) < n+1 || len(e.parentOff) < n+1 {
		return false
	}
	m := &e.m
	st := optState{
		src:        unsafe.Pointer(unsafe.SliceData(src)),
		start:      start,
		iend:       len(src),
		limit:      start + n - lzSearchMargin,
		head:       unsafe.Pointer(&m.head[0]),
		tags:       unsafe.Pointer(&m.tags[0]),
		chain:      unsafe.Pointer(&m.chain[0]),
		epochMark:  uint64(m.epochMark),
		offsetMask: uint64(m.offsetMask),
		dp:         unsafe.Pointer(&e.dp[0]),
		parentLen:  unsafe.Pointer(&e.parentLen[0]),
		parentOff:  unsafe.Pointer(&e.parentOff[0]),
		litCost:    uint64(litCost),
		depth:      p.searchDepth,
		sufficient: p.sufficientLen,
	}
	optEncAsm(&st)
	return true
}
