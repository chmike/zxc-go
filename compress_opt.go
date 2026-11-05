package zxc

// Optimal parser of levels 6 and 7: zxc_lz77_optimal_parse_glo of the
// reference library. A forward dynamic program over the positions of the
// block: dp[p] is the least cost in bits of coding the first p bytes, a
// literal costing the estimate of estimateLitBits and a match of length L
// optMatchCostBase plus 8 bits per varint byte of its length escape. Ties
// keep the earlier transition.

const (
	optMatchCostBase = 3 * 8 // token and offset bytes of a match
	optLongMatchSkip = 256   // no search inside a match this long
	optInf           = 1<<32 - 1
)

// optimalParse parses the block src[start:] into the encoder's streams,
// src[:start] being the dictionary content, and returns the largest offset
// minus 1, or false when a length cannot be coded. The dynamic program runs
// over the block's positions; matches may reach into the dictionary.
func (e *encoder) optimalParse(src []byte, start int, p *lzParams) (uint16, bool) {
	blk := src[start:]
	lits, toks, offs, extras := e.lits[:0], e.toks[:0], e.offs[:0], e.extras[:0]
	defer func() { e.lits, e.toks, e.offs, e.extras = lits, toks, offs, extras }()
	n := len(blk)
	if n < lzSearchMargin+1 {
		lits = append(lits, blk...)
		return 0, true
	}
	pp := *p
	pp.useLazy = false
	m := &e.m
	searchLimit := n - lzSearchMargin
	litCost := e.huf.estimateLitBits(blk)

	if cap(e.dp) < n+1 {
		e.dp = make([]uint32, n+1)
		e.parentLen = make([]uint16, n+1)
		e.parentOff = make([]uint16, n+1)
	}
	dp, parentLen, parentOff := e.dp[:n+1], e.parentLen[:n+1], e.parentOff[:n+1]
	dp[0] = 0
	for i := 1; i <= n; i++ {
		dp[i] = optInf
	}
	relax := func(q, L int, nxt uint32, off uint16) {
		if nxt < dp[q+L] {
			dp[q+L] = nxt
			parentLen[q+L] = uint16(L)
			parentOff[q+L] = off
		}
	}

	skipUntil := 0
	lastOff := 0
	prevP, prevLen := 0, 0
	for q := 0; q < searchLimit; q++ {
		if dp[q] == optInf {
			continue
		}
		if nxt := dp[q] + litCost; nxt < dp[q+1] {
			dp[q+1] = nxt
			parentLen[q+1] = 0
		}
		if q < skipUntil {
			continue
		}
		ip := start + q
		mt := m.findBestMatch(src, ip, len(src), start+searchLimit, ip, e.level, &pp, lastOff)
		if mt.ref < 0 {
			continue
		}
		off := ip - mt.ref
		if off <= 0 || off > lzWindowSize {
			continue
		}
		lastOff = off
		lMax := min(mt.len, n-q, 1<<16-1)
		offB := uint16(off - 1)
		lMaxPlus := lMax + 1
		const cheapEnd = lzMinMatch + splTokenMask // lengths with no escape
		const v1End = cheapEnd + 128               // lengths with a 1-byte escape
		nxtCheap := dp[q] + optMatchCostBase
		nxtV1 := nxtCheap + 8

		// Covered: when the previous position relaxed longer lengths and
		// dp[q] >= dp[q-1], only the last length of each of the first two
		// cost classes can still win.
		covered := prevLen > lMax && prevP+1 == q && dp[q] >= dp[q-1]
		prevP, prevLen = q, lMax
		if covered {
			if lMaxPlus >= cheapEnd {
				relax(q, cheapEnd-1, nxtCheap, offB)
			}
			if lMaxPlus >= v1End {
				relax(q, v1End-1, nxtV1, offB)
			}
		} else {
			L := lzMinMatch
			for end := min(lMaxPlus, cheapEnd); L < end; L++ {
				relax(q, L, nxtCheap, offB)
			}
			for end := min(lMaxPlus, v1End); L < end; L++ {
				relax(q, L, nxtV1, offB)
			}
			for ; L < lMaxPlus; L++ {
				cost := uint32(optMatchCostBase + 8)
				for v := L - lzMinMatch - splTokenMask; v >= 128; v >>= 7 {
					cost += 8
				}
				relax(q, L, dp[q]+cost, offB)
			}
		}
		if lMax >= optLongMatchSkip {
			skipUntil = q + lMax - 1
		}
	}
	// The last lzSearchMargin bytes are literals.
	for q := searchLimit; q < n; q++ {
		if dp[q] == optInf {
			continue
		}
		if nxt := dp[q] + litCost; nxt < dp[q+1] {
			dp[q+1] = nxt
			parentLen[q+1] = 0
		}
	}

	// Walk back from the end, recording the match ends, then emit forward.
	ends := e.ends[:0]
	for pos := n; pos > 0; {
		if L := int(parentLen[pos]); L == 0 {
			pos--
		} else {
			ends = append(ends, pos)
			pos -= L
		}
	}
	e.ends = ends
	maxOff := uint16(0)
	litStart := 0
	ok := true
	for i := len(ends) - 1; i >= 0; i-- {
		pos := ends[i]
		L := int(parentLen[pos])
		o := parentOff[pos]
		mStart := pos - L
		ll, ml := mStart-litStart, L-lzMinMatch
		lits = append(lits, blk[litStart:mStart]...)
		toks = append(toks, byte(min(ll, splTokenMask)<<4|min(ml, splTokenMask)))
		offs = append(offs, o)
		maxOff = max(maxOff, o)
		if ll >= splTokenMask {
			extras, ok = appendVarint(extras, uint32(ll-splTokenMask))
		}
		if ok && ml >= splTokenMask {
			extras, ok = appendVarint(extras, uint32(ml-splTokenMask))
		}
		if !ok {
			return 0, false
		}
		litStart = pos
	}
	lits = append(lits, blk[litStart:]...)
	return maxOff, true
}
