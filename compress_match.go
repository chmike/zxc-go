package zxc

import (
	"encoding/binary"
	"math/bits"
)

// LZ77 match finder of the encoder: zxc_lz77_find_best_match and its
// helpers in zxc_compress.c, with the same tables, the same candidate order
// and the same tie rules, so that it picks the same match as the reference
// at every position.

const (
	lzHashBits     = 15
	lzHashSize     = 1 << lzHashBits
	lzWindowSize   = 1 << 16
	lzWindowMask   = lzWindowSize - 1
	lzMinMatch     = 5                // shortest match a sequence codes
	lzMaxDist      = lzWindowSize - 1 // largest offset
	lzMinDist      = 32               // distance floor of levels 1 to 5
	lzSearchMargin = 8                // no match starts in the last 8 bytes
	hashMult32     = 0x2D35182D
)

// lzParams are the search parameters of a level (zxc_get_lz77_params).
type lzParams struct {
	searchDepth      int  // candidates walked on the chain
	sufficientLen    int  // stop the walk at a match this long
	useLazy          bool // test the next positions for a longer match
	lazyAttempts     int  // candidates walked by a lazy probe
	lazyLenThreshold int  // no lazy probe for a match this long
	stepBase         int  // step between positions when no match is found:
	stepShift        int  //   stepBase + (bytes since the last match) >> stepShift
	minOffset        int  // shortest offset accepted
	splitMax         int  // longest escaped match split into inline pieces
}

var lzParamTable = [8]lzParams{
	{3, 16, false, 0, 0, 4, 4, lzMinDist, 0},      // fallback, unused
	{3, 16, false, 0, 0, 4, 4, lzMinDist, 0},      // level 1
	{3, 18, false, 0, 0, 3, 6, lzMinDist, 0},      // level 2
	{3, 16, true, 4, 128, 1, 4, lzMinDist, 33},    // level 3
	{3, 18, true, 4, 128, 1, 5, lzMinDist, 24},    // level 4
	{64, 256, true, 16, 128, 1, 8, lzMinDist, 23}, // level 5
	{64, 256, false, 0, 0, 1, 8, 1, 0},            // level 6
	{128, 256, false, 0, 0, 1, 8, 1, 0},           // level 7
}

// matcher holds the tables of the match finder. A head entry holds a
// position tagged with the epoch of its block above offsetMask; an entry of
// another epoch, like position 0, reads as no candidate, so the tables are
// never cleared between blocks (zxc_epoch_pos). chain holds, per position
// modulo the window, the distance back to the previous position of the same
// hash, 0 ending the chain.
type matcher struct {
	head       [lzHashSize]uint32
	tags       [lzHashSize]uint8
	chain      [lzWindowSize]uint16
	offsetBits uint
	offsetMask uint32
	epoch      uint32
	maxEpoch   uint32
	epochMark  uint32
}

// init sizes the epoch tagging for blocks of up to chunk bytes.
func (m *matcher) init(chunk int) {
	m.offsetBits = uint(bits.Len(uint(chunk)) - 1)
	m.offsetMask = 1<<m.offsetBits - 1
	m.maxEpoch = uint32(1 << (32 - m.offsetBits))
}

// newBlock starts the epoch of a new block, clearing the tables when the
// epochs run out.
func (m *matcher) newBlock() {
	m.epoch++
	if m.epoch >= m.maxEpoch {
		clear(m.head[:])
		clear(m.tags[:])
		m.epoch = 1
	}
	m.epochMark = m.epoch << m.offsetBits
}

// pos decodes a head entry: its position, or 0 when it is of another epoch.
func (m *matcher) pos(head uint32) uint32 {
	if head&^m.offsetMask == m.epochMark {
		return head & m.offsetMask
	}
	return 0
}

// chainDelta is the chain link from cur back to prev: 0 when there is no
// previous position or it lies beyond the window.
func chainDelta(cur, prev uint32) uint16 {
	if d := cur - prev; prev != 0 && d < lzWindowSize {
		return uint16(d)
	}
	return 0
}

// lzHash hashes the bytes starting with the low ones of v: 4 bytes up to
// level 2, 5 from level 3.
func lzHash(v uint64, hash5 bool) uint32 {
	if hash5 {
		return uint32((v & 0xFFFFFFFFFF) * hashXorShift64 >> (64 - lzHashBits))
	}
	v4 := v ^ v>>15
	return uint32(v4) * hashMult32 >> (32 - lzHashBits)
}

// lzTag is the 8-bit rejection tag of a position: the xor fold of its first
// 4 bytes.
func lzTag(v4 uint32) uint8 { return uint8(v4 ^ v4>>16) }

func load32(b []byte, i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }
func load64(b []byte, i int) uint64 { return binary.LittleEndian.Uint64(b[i:]) }

// matchLen returns the length of the common prefix of src[a:end] and
// src[b:], b < a, knowing that the first from bytes are equal.
func matchLen(src []byte, a, b, from, end int) int {
	n := from
	for a+n+8 <= end {
		if d := load64(src, a+n) ^ load64(src, b+n); d != 0 {
			return n + bits.TrailingZeros64(d)>>3
		}
		n += 8
	}
	for a+n < end && src[a+n] == src[b+n] {
		n++
	}
	return n
}

// match is a match found at a position: ref is the position it copies from,
// -1 for none; len counts the backtrack bytes, the bytes before the
// position that the match also covers.
type match struct {
	ref       int
	len       int
	backtrack int
}

// findBestMatch is zxc_lz77_find_best_match: it inserts position ip of src
// in the tables and returns the longest match there, extended back to
// anchor at most, or no match when a lazy probe finds a longer one at the
// next positions. Matches end at iend; lastOff, 0 for none, is the offset
// tried first.
func (m *matcher) findBestMatch(src []byte, ip, iend, searchLimit, anchor, level int, p *lzParams, lastOff int) match {
	hash5 := level >= 3
	best := match{ref: -1, len: lzMinMatch - 1}

	curVal8 := load64(src, ip)
	curVal := uint32(curVal8)
	h := lzHash(curVal8, hash5)
	curTag := lzTag(curVal)
	curPos := uint32(ip)

	// Up to level 2 a head with another tag is taken as no candidate.
	storedTag := m.tags[h]
	var idx uint32
	if level > 2 || storedTag == curTag {
		idx = m.pos(m.head[h])
	}
	skipHead := idx != 0 && storedTag != curTag

	m.head[h] = m.epochMark | curPos
	m.tags[h] = curTag
	m.chain[curPos&lzWindowMask] = chainDelta(curPos, idx)

	attempts := p.searchDepth

	// The previous offset first (level 6 only): it raises best.len and can
	// end the search early; the result is the same.
	if lastOff != 0 && lastOff >= p.minOffset && lastOff <= lzMaxDist && lastOff <= ip {
		ref := ip - lastOff
		if load32(src, ref) == curVal {
			best.len = matchLen(src, ip, ref, 4, iend)
			best.ref = ref
			if best.len >= p.sufficientLen || ip+best.len >= iend {
				goto finalize
			}
		}
	}

	if idx == 0 {
		goto finalize
	}
	if skipHead {
		d := m.chain[idx&lzWindowMask]
		if d != 0 {
			idx -= uint32(d)
		} else {
			idx = 0
		}
		attempts--
	}

	for idx > 0 {
		// attempts-- < 0 in the C code: the test sees the value before the
		// decrement, so searchDepth+1 candidates at most.
		if attempts < 0 || curPos-idx > lzMaxDist {
			break
		}
		attempts--
		ref := int(idx)
		d := m.chain[idx&lzWindowMask]
		// The gate: bytes [best.len-3, best.len+1) must match for a longer
		// match, then the first 4.
		if ip-ref >= p.minOffset &&
			load32(src, ref+best.len-3) == load32(src, ip+best.len-3) &&
			load32(src, ref) == curVal {
			if n := matchLen(src, ip, ref, 4, iend); n > best.len {
				best.len = n
				best.ref = ref
			}
			if best.len >= p.sufficientLen || ip+best.len >= iend {
				break
			}
		}
		if d != 0 {
			idx -= uint32(d)
		} else {
			idx = 0
		}
	}

finalize:
	if best.ref >= 0 {
		bip, bref := ip, best.ref
		for bip > anchor && bref > 0 && src[bip-1] == src[bref-1] {
			bip--
			bref--
			best.len++
			best.backtrack++
		}
		best.ref = bref
	}

	// Lazy: a match two bytes longer at ip+1, or from level 4 three bytes
	// longer at ip+2, cancels this one.
	if p.useLazy && best.ref >= 0 && best.len < p.lazyLenThreshold && ip+1 < searchLimit {
		if m.lazyProbe(src, ip+1, iend, best.len+2, hash5, p) ||
			level >= 4 && ip+2 < searchLimit && m.lazyProbe(src, ip+2, iend, best.len+3, hash5, p) {
			best.ref = -1
		}
	}
	return best
}

// lazyProbe is zxc_lazy_probe: it reports whether position lp, not
// inserted, has a match of at least need bytes among the first candidates
// of its chain. Candidates are gated on the last 4 of the need bytes.
func (m *matcher) lazyProbe(src []byte, lp, iend, need int, hash5 bool, p *lzParams) bool {
	if need > iend-lp {
		return false
	}
	val8 := load64(src, lp)
	val := uint32(val8)
	h := lzHash(val8, hash5)
	pos := uint32(lp)
	gate := load32(src, lp+need-4)
	idx := m.pos(m.head[h])
	skip := m.tags[h] != lzTag(val)
	for att := p.lazyAttempts; idx > 0 && att > 0; att-- {
		if pos-idx > lzMaxDist {
			break
		}
		ref := int(idx)
		if lp-ref >= p.minOffset && !skip && load32(src, ref+need-4) == gate &&
			load32(src, ref) == val && matchLen(src, lp, ref, 4, lp+need) >= need {
			return true
		}
		d := m.chain[idx&lzWindowMask]
		if d == 0 {
			break
		}
		idx -= uint32(d)
		skip = false
	}
	return false
}

// seedDict enters the positions of the dictionary content, win[:dictLen],
// in the tables, as zxc_lz_seed_dict does: every fourth position of its
// first half, without chain links, then every position of the second half,
// which gives the shorter offsets. The hash of the last positions reads up
// to the first byte of the block that follows the content in win.
func (m *matcher) seedDict(win []byte, dictLen int, hash5 bool) {
	if dictLen < lzMinMatch {
		return
	}
	limit := dictLen - (lzMinMatch - 1)
	half := limit / 2
	for i := 0; i < half; i += 4 {
		v := loadPad64(win, i)
		h := lzHash(v, hash5)
		m.head[h] = m.epochMark | uint32(i)
		m.tags[h] = lzTag(uint32(v))
		m.chain[i&lzWindowMask] = 0
	}
	for i := half; i < limit; i++ {
		v := loadPad64(win, i)
		h := lzHash(v, hash5)
		prev := m.pos(m.head[h])
		m.head[h] = m.epochMark | uint32(i)
		m.tags[h] = lzTag(uint32(v))
		m.chain[i&lzWindowMask] = chainDelta(uint32(i), prev)
	}
}

// loadPad64 is load64 for the last positions of b, the bytes past its end
// read as 0: the hashes use 6 bytes at most, which seedDict has.
func loadPad64(b []byte, i int) uint64 {
	if i+8 <= len(b) {
		return load64(b, i)
	}
	var t [8]byte
	copy(t[:], b[i:])
	return binary.LittleEndian.Uint64(t[:])
}

// shortDistBound is zxc_block_is_short_dist_bound: it samples the block and
// reports whether more than 20 % of the sampled positions repeat their 4
// bytes less than lzMinDist back, in which case the block keeps every
// distance; the samples stop as soon as the answer is settled.
func shortDistBound(blk []byte) bool {
	const dMax = lzMinDist
	size := len(blk)
	if size < dMax+4 {
		return true
	}
	want := min(max(size/1024, 16), 64)
	stride := max(size/want, dMax)
	planned := (size-4-dMax)/stride + 1
	bar := 20 * planned
	samples, hits := 0, 0
	for i := dMax; i+4 <= size; i += stride {
		cur := load32(blk, i)
		samples++
		for d := 1; d < dMax; d++ {
			if load32(blk, i-d) == cur {
				hits++
				break
			}
		}
		if hits*100 > bar {
			return true
		}
		if (hits+planned-samples)*100 <= bar {
			return false
		}
	}
	return hits*100 > bar
}
