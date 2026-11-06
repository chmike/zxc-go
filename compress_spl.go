package zxc

import (
	"encoding/binary"
	"math/bits"
)

// SPL block encoder (§ 5.2), levels 3 to 5: zxc_encode_block_glo of the
// reference library with its lazy parser, its match splitting and its
// choice between RAW and RLE literals.

// SPL token fields (§ 5.2): a 4-bit literal length and a 4-bit match length
// minus lzMinMatch; splTokenMask (lz.go) escapes to a varint of the excess.
const (
	splInlineMLCode     = splTokenMask - 1             // longest match length code inline
	splMaxInlineML      = splInlineMLCode + lzMinMatch // its match length, 19
	splSplitCtxBits     = 8                            // escape history bits of a context
	splSplitMispredict  = 80                           // % of escapes a predictor must miss
	rleMarginPremium    = 256 >> 5                     // RLE decode tax, Q8, below level 6
	rleFlag             = 0x80                         // RLE literal section: a run
	rleMaxRun           = 131                          // longest run of one RLE pair
	rleMaxCopy          = 128                          // longest copy of one header
	rleMinRun           = 4                            // shortest run coded as a pair
	hufPremium          = 4                            // Huffman decode tax, Q8, from level 6
	hufMinSymbols       = 139                          // shortest section tried in Huffman
	splSectionDescBytes = 4
)

// appendSPL appends the block src[start:] as a SPL block, header included,
// src[:start] being the dictionary content, and reports false when a
// length cannot be coded, the block then going out RAW.
func (e *encoder) appendSPL(dst, src []byte, start int) ([]byte, bool) {
	level := e.level
	p := lzParamTable[level]
	if p.minOffset > 1 && shortDistBound(src[start:]) {
		p.minOffset = 1
	}
	e.m.newBlock()
	e.m.seedDict(src, start, true)

	var maxOff uint16
	var ok bool
	if level >= 6 {
		maxOff, ok = e.optimalParse(src, start, &p)
	} else {
		maxOff, ok = e.lazyParse(src, start, &p)
	}
	if !ok {
		return dst, false
	}
	lits := e.lits
	toks, offs, extras := e.splitMatches(e.toks, e.offs, e.extras, p.splitMax)
	e.toks, e.offs, e.extras = toks, offs, extras

	// Literals: RLE when its size plus the decode tax beats the raw copy.
	premium := rleMarginPremium
	if level >= 6 {
		premium = 1
	}
	encLit := byte(encRAW)
	litSize := len(lits)
	bestJ := len(lits)
	if len(lits) > 0 {
		if rs := e.rleSize(lits); rs+len(lits)*premium>>8 < bestJ {
			encLit, litSize, bestJ = encRLE, rs, rs+len(lits)*premium>>8
		}
	}

	// From level 6, Huffman literals when their J beats the winner's, and at
	// level 7 Huffman tokens when theirs beats the raw tokens.
	maxLen := hufMaxCodeLenDensity
	if level >= 7 {
		maxLen = hufMaxCodeLenUltra
	}
	var litFreq, tokFreq [hufNumSymbols]uint32
	var litLen, tokLen [hufNumSymbols]uint8
	var litTree, tokTree *encTree
	if level >= 6 && len(lits) >= hufMinSymbols {
		for _, c := range lits {
			litFreq[c]++
		}
		if e.huf.buildCodeLengths(&litFreq, &litLen, maxLen) {
			e.huf.nudgeCodeLengths(&litFreq, &litLen, maxLen)
			if hs := pivcoSize(&litFreq, &litLen, &e.litTree); hs >= 0 && hs+len(lits)*hufPremium>>8 < bestJ {
				encLit, litSize, litTree = encHuffman, hs, &e.litTree
				bestJ = hs + len(lits)*hufPremium>>8
			}
		}
	}
	// With a dictionary carrying a literal table, the same code without its
	// 128-byte header, valid when every literal has a code in it.
	if level >= 6 && e.dictHuf && len(lits) > 0 {
		if len(lits) < hufMinSymbols {
			for _, c := range lits {
				litFreq[c]++
			}
		}
		if hs := pivcoBodySize(&litFreq, &e.dictLen, &e.dictTree); hs >= 0 && hs+len(lits)*hufPremium>>8 < bestJ {
			encLit, litSize = encHuffmanDict, hs
		}
	}
	encTok := byte(encRAW)
	tokSize := len(toks)
	if level >= 7 && len(toks) >= hufMinSymbols {
		for _, c := range toks {
			tokFreq[c]++
		}
		if e.huf.buildCodeLengths(&tokFreq, &tokLen, hufMaxCodeLenUltra) {
			e.huf.nudgeCodeLengths(&tokFreq, &tokLen, hufMaxCodeLenUltra)
			if hs := pivcoSize(&tokFreq, &tokLen, &e.tokTree); hs >= 0 && hs+len(toks)*hufPremium>>8 < len(toks) {
				encTok, tokSize, tokTree = encHuffman, hs, &e.tokTree
			}
		}
	}
	offWidth := 2
	if maxOff <= 255 {
		offWidth = 1
	}

	// [header 8][sub-header 12][literal size if not RAW][literals][tokens]
	// [offsets][extras][padding]; as for PAK, the sections behind the
	// literals span at least litSlack bytes.
	desc := 0
	if encLit != encRAW {
		desc += splSectionDescBytes
	}
	if encTok != encRAW {
		desc += splSectionDescBytes
	}
	behind := tokSize + offWidth*len(offs) + len(extras)
	pad := max(litSlack-behind, 0)
	payload := lzHeaderSize + desc + litSize + behind + pad
	h := makeBlockHeader(blockSPL, uint32(payload))
	dst = append(dst, h[:]...)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(toks)))
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(lits)))
	dst = append(dst, encLit, encTok, 0, byte(2-offWidth)) // offsets: 1 = one byte each
	if encLit != encRAW {
		dst = binary.LittleEndian.AppendUint32(dst, uint32(litSize))
	}
	if encTok != encRAW {
		dst = binary.LittleEndian.AppendUint32(dst, uint32(tokSize))
	}
	switch encLit {
	case encRLE:
		dst = e.appendRLE(dst, lits)
	case encHuffman:
		dst = appendPivCo(dst, lits, &litFreq, &litLen, litTree, true)
	case encHuffmanDict:
		dst = appendPivCo(dst, lits, &litFreq, &e.dictLen, &e.dictTree, false)
	default:
		dst = append(dst, lits...)
	}
	if encTok == encHuffman {
		dst = appendPivCo(dst, toks, &tokFreq, &tokLen, tokTree, true)
	} else {
		dst = append(dst, toks...)
	}
	if offWidth == 1 {
		for _, o := range offs {
			dst = append(dst, byte(o))
		}
	} else {
		for _, o := range offs {
			dst = binary.LittleEndian.AppendUint16(dst, o)
		}
	}
	dst = append(dst, extras...)
	dst = append(dst, make([]byte, pad)...)
	return dst, true
}

// lazyParse parses the block src[start:] into the encoder's streams with
// the greedy parser and its lazy probes (levels 3 to 5), and returns the
// largest offset minus 1, or false when a length cannot be coded.
func (e *encoder) lazyParse(src []byte, start int, p *lzParams) (uint16, bool) {
	if !e.noAsm {
		if maxOff, ok := e.splParseFast(src, start, p); ok {
			return maxOff, true
		}
	}
	m := &e.m
	iend := len(src)
	ip, anchor := start, start
	searchLimit := iend - lzSearchMargin
	lits, toks, offs, extras := e.lits[:0], e.toks[:0], e.offs[:0], e.extras[:0]
	defer func() { e.lits, e.toks, e.offs, e.extras = lits, toks, offs, extras }()
	maxOff := uint16(0)
	ok := true
	for ip < searchLimit {
		step := p.stepBase + (ip-anchor)>>p.stepShift
		if ip+step >= searchLimit {
			step = 1
		}
		mt := m.findBestMatch(src, ip, iend, searchLimit, anchor, e.level, p, 0)
		if mt.ref < 0 {
			ip += step
			continue
		}
		ip -= mt.backtrack
		ll := ip - anchor
		ml := mt.len - lzMinMatch
		off := uint16(ip - mt.ref - 1)
		lits = append(lits, src[anchor:ip]...)
		toks = append(toks, byte(min(ll, splTokenMask)<<4|min(ml, splTokenMask)))
		offs = append(offs, off)
		maxOff = max(maxOff, off)
		if ll >= splTokenMask {
			extras, ok = appendVarint(extras, uint32(ll-splTokenMask))
		}
		if ok && ml >= splTokenMask {
			extras, ok = appendVarint(extras, uint32(ml-splTokenMask))
		}
		if !ok {
			break
		}
		// From level 5, the position two bytes before the match end goes
		// into the tables too.
		if e.level > 4 {
			if end := ip + mt.len; end < iend-7 {
				m.insert(src, end-2, true)
			}
		}
		ip += mt.len
		anchor = ip
	}
	if !ok {
		return 0, false
	}
	lits = append(lits, src[anchor:]...)
	return maxOff, true
}

// insert enters position pos of src in the tables, as the level-5 parser
// does after a match.
func (m *matcher) insert(src []byte, pos int, hash5 bool) {
	v := load64(src, pos)
	h := lzHash(v, hash5)
	prev := m.pos(m.head[h])
	m.head[h] = m.epochMark | uint32(pos)
	m.tags[h] = lzTag(uint32(v))
	m.chain[pos&lzWindowMask] = chainDelta(uint32(pos), prev)
}

// rleSize returns the size appendRLE gives lits.
func rleSize(lits []byte) int {
	n := 0
	for i := 0; i < len(lits); {
		b, start := lits[i], i
		i++
		for i < len(lits) && lits[i] == b {
			i++
		}
		if run := i - start; run >= rleMinRun {
			n += run / rleMaxRun * 2
			if rem := run % rleMaxRun; rem >= rleMinRun {
				n += 2
			} else if rem > 0 {
				n += 1 + rem
			}
			continue
		}
		i = rleCopyEnd(lits, i)
		run := i - start
		n += run + (run+rleMaxCopy-1)/rleMaxCopy
	}
	return n
}

// rleCopyEnd returns where the copy that reaches position i of lits ends:
// at the next run of rleMinRun equal bytes, or at the end.
func rleCopyEnd(lits []byte, i int) int {
	// 8 bytes at a time: x has a zero byte j where bytes j and j+1 are
	// equal, z marks them exactly, and m the starts j <= 4 of 3 zero bytes
	// in a row, that is of 4 equal bytes, all within the word.
	const lo7 = 0x7F7F7F7F7F7F7F7F
	for i+8 <= len(lits) {
		w := load64(lits, i)
		x := w ^ w>>8
		z := ^((x&lo7 + lo7) | x | lo7)
		if m := z & (z >> 8) & (z >> 16) & 0x8080808080; m != 0 {
			return i + bits.TrailingZeros64(m)>>3
		}
		i += 5
	}
	for i < len(lits) {
		if i+3 < len(lits) && lits[i] == lits[i+1] && lits[i+1] == lits[i+2] && lits[i+2] == lits[i+3] {
			break
		}
		i++
	}
	return i
}

// appendRLE appends lits as an RLE literal section (§ 5.2.2): a header
// byte with rleFlag is a run of (h & 0x7F) + 4 copies of the next byte,
// without it a copy of the (h + 1) bytes that follow.
func appendRLE(dst, lits []byte) []byte {
	for i := 0; i < len(lits); {
		b, start := lits[i], i
		i++
		for i < len(lits) && lits[i] == b {
			i++
		}
		if run := i - start; run >= rleMinRun {
			for run >= rleMinRun {
				c := min(run, rleMaxRun)
				dst = append(dst, byte(rleFlag|(c-rleMinRun)), b)
				run -= c
			}
			if run > 0 {
				dst = append(dst, byte(run-1))
				dst = append(dst, lits[i-run:i]...)
			}
			continue
		}
		i = rleCopyEnd(lits, i)
		for s := start; s < i; s += rleMaxCopy {
			c := min(i-s, rleMaxCopy)
			dst = append(dst, byte(c-1))
			dst = append(dst, lits[s:s+c]...)
		}
	}
	return dst
}

// splitMatches is zxc_glo_split_block: when the block's match-length
// escapes look hard to predict, the escaped matches whose length code is at
// most limit and whose context mispredicts are re-emitted as several inline
// matches at the same offset, so that the decoder does not take the escape.
func (e *encoder) splitMatches(toks []byte, offs []uint16, extras []byte, limit int) ([]byte, []uint16, []byte) {
	n := len(toks)
	if limit <= splInlineMLCode || n == 0 {
		return toks, offs, extras
	}
	side := grow(e.side, n)[:n]
	e.side = side
	if !e.noAsm {
		if t, o, x, ok := e.splitFast(toks, offs, extras, limit); ok {
			return t, o, x
		}
	}
	var bad [1 << splSplitCtxBits]bool
	if !splitAnalyze(toks, side, &bad) {
		return toks, offs, extras
	}

	// 1. Mark the matches to split and drop their varints; the other extras
	// move down. The encoder wrote the varints: their lengths need no
	// checks.
	r, w, extra := 0, 0, 0
	side = side[:n]
	for i, t := range toks {
		isBad := bad[side[i]]
		side[i] = 0
		if t>>4 == splTokenMask {
			next := r + varintLen(extras[r])
			if w != r {
				copy(extras[w:], extras[r:next])
			}
			w += next - r
			r = next
		}
		if t&splTokenMask != splTokenMask {
			continue
		}
		v, next, _ := readVarint(extras, r)
		code := int(v) + splTokenMask
		if isBad && code <= limit {
			side[i] = byte(code)
			extra += (code+splMaxInlineML+lzMinMatch-1)/splMaxInlineML - 1
		} else {
			if w != r {
				copy(extras[w:], extras[r:next])
			}
			w += next - r
		}
		r = next
	}
	extras = extras[:w]
	if extra == 0 {
		return toks, offs, extras
	}

	// 2. Expand backward: a marked sequence becomes its pieces, the first
	// keeping the literal length, the last taking what remains.
	out := n + extra
	toks = append(toks, make([]byte, extra)...)
	offs = append(offs, make([]uint16, extra)...)
	for i := n - 1; i >= 0; i-- {
		t, o := toks[i], offs[i]
		code := int(side[i])
		if code == 0 {
			out--
			toks[out], offs[out] = t, o
			continue
		}
		llBits := t & (splTokenMask << 4)
		out -= (code + splMaxInlineML + lzMinMatch - 1) / splMaxInlineML
		k := out
		for code > splInlineMLCode {
			piece := min(code-lzMinMatch, splInlineMLCode)
			toks[k], offs[k] = llBits|byte(piece), o
			k++
			llBits = 0
			code -= piece + lzMinMatch
		}
		toks[k], offs[k] = llBits|byte(code), o
	}
	return toks, offs, extras
}

// splitAnalyze is zxc_glo_split_analyze: it records in side the context of
// each sequence, its last escape bits, marks in bad the contexts where an
// escape is a strict minority, and reports whether a static predictor
// would miss at least splSplitMispredict % of the escapes with some escape
// in a bad context.
func splitAnalyze(toks, side []byte, bad *[1 << splSplitCtxBits]bool) bool {
	n := len(toks)
	order := uint(splSplitCtxBits)
	for order > 2 && n>>order < 16 {
		order--
	}
	hmask := uint32(1)<<order - 1
	var hist [2][1 << splSplitCtxBits]uint32
	h, nEsc := uint8(0), 0
	m8 := uint8(hmask)
	side = side[:len(toks)]
	for i, t := range toks {
		esc := uint8(0)
		if t&splTokenMask == splTokenMask {
			esc = 1
		}
		side[i] = h
		hist[esc][h]++
		h = (h<<1 | esc) & m8
		nEsc += int(esc)
	}
	errors, badEsc := 0, 0
	for c := uint32(0); c <= hmask; c++ {
		n0, n1 := int(hist[0][c]), int(hist[1][c])
		bad[c] = n1 < n0
		if bad[c] {
			badEsc += n1
		}
		errors += min(n0, n1)
	}
	return badEsc != 0 && errors*100 >= splSplitMispredict*nEsc
}

// varintLen is the length of the prefix varint starting with byte b0 (§ 6).
func varintLen(b0 byte) int {
	switch {
	case b0 < 0x80:
		return 1
	case b0 < 0xC0:
		return 2
	}
	return 3
}

// rleSize and appendRLE of the encoder: the assembly ones where there are
// some.
func (e *encoder) rleSize(lits []byte) int {
	if e.noAsm {
		return rleSize(lits)
	}
	n, _ := rleFast(nil, lits, false)
	return n
}

func (e *encoder) appendRLE(dst, lits []byte) []byte {
	if e.noAsm {
		return appendRLE(dst, lits)
	}
	_, dst = rleFast(dst, lits, true)
	return dst
}
