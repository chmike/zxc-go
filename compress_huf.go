package zxc

import "math/bits"

// Huffman code construction of the encoder: zxc_huf_build_code_lengths of
// the reference library (zxc_huffman.c), boundary package-merge with the
// same orderings and tie rules, so that both give every symbol the same
// code length.

const (
	hufMaxCodeLenUltra   = 11 // code length cap at level 7
	hufMaxCodeLenDensity = 8  // below level 7
)

// hufLeaf is a symbol of nonzero frequency.
type hufLeaf struct {
	w   uint32
	sym int16
}

// hufItem is an item of a package-merge level: a leaf (sym >= 0) or a
// package of items left and right of the level below.
type hufItem struct {
	w           uint32
	left, right int16
	sym         int16
}

// hufBuilder holds the package-merge buffers, reused from block to block.
type hufBuilder struct {
	items [hufMaxCodeLenUltra][2 * hufNumSymbols]hufItem
	stack []hufFrame
	ws    *nudgeWS // the nudge's DP planes, allocated on first use
}

type hufFrame struct {
	lvl int8
	idx int16
}

// sortLeaves sorts leaves by ascending weight, ties by ascending symbol, as
// pm_leaves_sort does. Any stable order with this key gives the same
// result: the key is unique per symbol.
func sortLeaves(leaves []hufLeaf) {
	for i := 1; i < len(leaves); i++ {
		k := leaves[i]
		j := i - 1
		for j >= 0 && (leaves[j].w > k.w || leaves[j].w == k.w && leaves[j].sym > k.sym) {
			leaves[j+1] = leaves[j]
			j--
		}
		leaves[j+1] = k
	}
}

// buildCodeLengths sets codeLen to length-limited Huffman code lengths for
// freq, at most maxLen bits, 0 for an absent symbol; a lone symbol gets
// length 1. It reports false when no symbol is present.
func (b *hufBuilder) buildCodeLengths(freq *[hufNumSymbols]uint32, codeLen *[hufNumSymbols]uint8, maxLen int) bool {
	clear(codeLen[:])
	var buf [hufNumSymbols]hufLeaf
	leaves := buf[:0]
	for i, f := range freq {
		if f > 0 {
			leaves = append(leaves, hufLeaf{f, int16(i)})
		}
	}
	n := len(leaves)
	if n == 0 {
		return false
	}
	if n == 1 {
		codeLen[leaves[0].sym] = 1
		return true
	}
	sortLeaves(leaves)

	// Level 0: the leaves. Level k: the leaves merged with the packages of
	// pairs of level k-1, a leaf first on equal weights.
	var counts [hufMaxCodeLenUltra]int
	for i, l := range leaves {
		b.items[0][i] = hufItem{w: l.w, left: -1, right: -1, sym: l.sym}
	}
	counts[0] = n
	for k := 1; k < maxLen; k++ {
		prev := &b.items[k-1]
		cur := &b.items[k]
		packs := counts[k-1] / 2
		li, pi, m := 0, 0, 0
		for li < n || pi < packs {
			wl, wp := uint32(1<<32-1), uint32(1<<32-1)
			if li < n {
				wl = leaves[li].w
			}
			if pi < packs {
				wp = prev[2*pi].w + prev[2*pi+1].w
			}
			if wl <= wp && li < n {
				cur[m] = hufItem{w: wl, left: -1, right: -1, sym: leaves[li].sym}
				li++
			} else {
				cur[m] = hufItem{w: wp, left: int16(2 * pi), right: int16(2*pi + 1), sym: -1}
				pi++
			}
			m++
		}
		counts[k] = m
	}

	// The first 2n-2 items of the last level: each appearance of a leaf
	// below them adds one to its code length.
	take := min(2*n-2, counts[maxLen-1])
	stack := b.stack[:0]
	for i := range take {
		stack = append(stack, hufFrame{int8(maxLen - 1), int16(i)})
	}
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		it := &b.items[f.lvl][f.idx]
		if it.sym >= 0 {
			codeLen[it.sym]++
		} else {
			stack = append(stack, hufFrame{f.lvl - 1, it.left}, hufFrame{f.lvl - 1, it.right})
		}
	}
	b.stack = stack
	return true
}

// estimateLitBits is zxc_opt_estimate_lit_bits: the cost in bits of a
// literal for the optimal parser, the average code length of a sample of
// the block under an 8-bit length-limited code, rounded up, 8 at most.
func (b *hufBuilder) estimateLitBits(blk []byte) uint32 {
	const sampleMin = 1024
	if len(blk) < sampleMin {
		return 8
	}
	var hist [hufNumSymbols]uint32
	step := 1
	if len(blk) > 4096 {
		step = len(blk) >> 12
	}
	sampled := uint32(0)
	for i := 0; i < len(blk); i += step {
		hist[blk[i]]++
		sampled++
	}
	var codeLen [hufNumSymbols]uint8
	if !b.buildCodeLengths(&hist, &codeLen, hufMaxCodeLenDensity) {
		return 8
	}
	total := uint32(0)
	for k := range hufNumSymbols {
		total += hist[k] * uint32(codeLen[k])
	}
	return min((total+sampled-1)/sampled, 8)
}

// Code-length nudge: zxc_huf_nudge_code_lengths. Package-merge minimizes
// the section's bits alone; the PivCo decoder's cost also depends on the
// shape of the length histogram. The nudge tries a few reshaped histograms
// and adopts the cheapest under J = 256*bits + lambda*touches, when it
// costs at most 1.5 % more bits and cuts the modeled decode touches by 10 %
// at least. All arithmetic is that of the reference, integer and exact.

const (
	nudgeLambdaQ8          = 26
	nudgeBitsPermil        = 1015
	nudgeMergeQ8           = 230
	nudgeDeepFlatPenalty   = 24
	nudgeLevelCost         = 64
	nudgeDPM               = 64 // coarse symbols of the slot-ledger DP
	pivcoUnpackFlatSIMDMax = 6
	nudgeLU                = hufMaxCodeLenUltra
)

func log2u32(x uint32) int { return bits.Len32(x) - 1 }

// nudgeClasses returns the per-length class counts of codeLen and the
// number of present symbols.
func nudgeClasses(codeLen *[hufNumSymbols]uint8) ([nudgeLU + 1]uint32, int) {
	var blc [nudgeLU + 1]uint32
	n := 0
	for _, l := range codeLen {
		if l != 0 {
			blc[l]++
			n++
		}
	}
	return blc, n
}

// nudgePFCanonical sets pf to the frequency prefix sums of the leaves in
// canonical (length, symbol) order.
func nudgePFCanonical(codeLen *[hufNumSymbols]uint8, freq *[hufNumSymbols]uint32, blc *[nudgeLU + 1]uint32, pf *[hufNumSymbols + 1]uint64) {
	var pos [nudgeLU + 1]uint32
	acc := uint32(0)
	for l := 1; l <= nudgeLU; l++ {
		pos[l] = acc
		acc += blc[l]
	}
	var val [hufNumSymbols]uint32
	for s, l := range codeLen {
		if l != 0 {
			val[pos[l]] = freq[s]
			pos[l]++
		}
	}
	pf[0] = 0
	for i := uint32(0); i < acc; i++ {
		pf[i+1] = pf[i] + uint64(val[i])
	}
}

// nudgeTouches is the modeled decode cost of a buddy block of depth D whose
// leaves have length l.
func nudgeTouches(l, D int) uint64 {
	switch {
	case D == 0:
		return uint64(l + 1) // lone leaf: one fill and the merges above
	case D == 1:
		return uint64(l) // leaf pair: the parent's blend
	}
	t := l - D + 1 // flat root: one unpack and the merges above
	if D > pivcoUnpackFlatSIMDMax {
		t += nudgeDeepFlatPenalty
	}
	return uint64(t)
}

// nudgeEval returns the modeled bits and touches of the class counts blc,
// pf being the prefix sums of the leaves in code order.
func nudgeEval(blc *[nudgeLU + 1]uint32, pf []uint64) (bitsOut, touches uint64) {
	maxLen := 0
	S, base := uint32(0), uint32(0)
	for l := 1; l <= nudgeLU; l++ {
		if blc[l] == 0 {
			continue
		}
		maxLen = l
		bitsOut += uint64(l) * (pf[base+blc[l]] - pf[base])
		w := uint32(1) << (nudgeLU - l)
		end := S + blc[l]*w
		for x := S; x < end; {
			wx := uint32(1) << nudgeLU
			if x != 0 {
				wx = x & -x
			}
			wr := uint32(1) << log2u32(end-x)
			W := min(wx, wr)
			D := log2u32(W) - (nudgeLU - l)
			i0 := base + (x-S)>>(nudgeLU-l)
			mass := pf[i0+W>>(nudgeLU-l)] - pf[i0]
			touches += mass * nudgeTouches(l, D)
			x += W
		}
		S = end
		base += blc[l]
	}
	touches += nudgeLevelCost * uint64(maxLen+1)
	return bitsOut, touches
}

func nudgeJ(b, t uint64) uint64 { return 256*b + nudgeLambdaQ8*t }

// nudgeClamp returns the feasible class count nearest to want at level l,
// with s open slots and nRem symbols left to place.
func nudgeClamp(want, s, nRem uint32, l, capLen int) uint32 {
	if nRem <= s || l >= capLen {
		return nRem
	}
	m := uint32(1) << (capLen - l)
	lo := uint32(0)
	if 2*s > nRem {
		lo = 2*s - nRem
	}
	hi := s - 1
	hi = min(hi, (s*m-nRem)/(m-1))
	c := max(want, lo)
	return min(c, hi)
}

// nudgeComplete fills levels l+1 to capLen of blc with the baseline counts
// blc0 clamped into feasibility.
func nudgeComplete(blc *[nudgeLU + 1]uint32, l int, s, nRem uint32, blc0 *[nudgeLU + 1]uint32, capLen int) {
	for j := l + 1; j <= capLen && nRem != 0; j++ {
		c := nudgeClamp(blc0[j], s, nRem, j, capLen)
		blc[j] = c
		nRem -= c
		s = 2 * (s - c)
	}
}

// nudgeWalk is the greedy shallow-to-deep walk of zxc_huf_nudge_walk.
func nudgeWalk(blc0 *[nudgeLU + 1]uint32, pfRank []uint64, n, capLen int) [nudgeLU + 1]uint32 {
	var out [nudgeLU + 1]uint32
	s, nRem := uint32(2), uint32(n)
	for l := 1; l <= capLen && nRem != 0; l++ {
		type cand struct {
			c     uint32
			flatD int
		}
		var cands [6]cand
		nc := 0
		cBase := nudgeClamp(blc0[l], s, nRem, l, capLen)
		cands[nc] = cand{cBase, 0}
		nc++
		if cBase < nRem {
			iBase := s - cBase
			iDn := uint32(1) << log2u32(iBase)
			rest := iBase - iDn
			third := iDn
			if rest != 0 {
				third |= 1 << log2u32(rest)
			}
			for _, sh := range [3]uint32{iDn, iDn << 1, third} {
				want := uint32(0)
				if s > sh {
					want = s - sh
				}
				c := nudgeClamp(want, s, nRem, l, capLen)
				dup := false
				for p := range nc {
					dup = dup || cands[p].c == c
				}
				if !dup {
					cands[nc] = cand{c, 0}
					nc++
				}
			}
			for d := 1; d <= capLen-l && nc < 6; d++ {
				den := uint32(1)<<d - 1
				num := int32(s<<d) - int32(nRem)
				if num < 0 || uint32(num)%den != 0 {
					continue
				}
				c := uint32(num) / den
				if c >= s || c >= nRem {
					continue
				}
				cands[nc] = cand{c, d}
				nc++
				break
			}
		}
		bestJ, bestC := uint64(1<<64-1), cBase
		for k := range nc {
			tmp := out
			tmp[l] = cands[k].c
			if rem := nRem - cands[k].c; rem != 0 {
				if cands[k].flatD != 0 {
					tmp[l+cands[k].flatD] = rem
				} else {
					nudgeComplete(&tmp, l, 2*(s-cands[k].c), rem, blc0, capLen)
				}
			}
			b, t := nudgeEval(&tmp, pfRank)
			if j := nudgeJ(b, t); j < bestJ {
				bestJ, bestC = j, cands[k].c
			}
		}
		out[l] = bestC
		nRem -= bestC
		s = 2 * (s - bestC)
	}
	return out
}

// nudgeDPRunJ is zxc_huf_nudge_dp_run_j: the J of a run of c coarse slots
// placed at coarse level lc with s open slots, after k groups.
func nudgeDPRunJ(lu, lc, g int, s, c uint32, pfg []uint64, k uint32) uint64 {
	if c == 0 {
		return 0
	}
	lr := lc + g
	w := uint32(1) << (lu - lc)
	S := uint32(1)<<lu - s*w
	end := S + c*w
	b := uint64(lr) * (pfg[k+c] - pfg[k])
	touches := uint64(0)
	for x := S; x < end; {
		wx := uint32(1) << lu
		if x != 0 {
			wx = x & -x
		}
		wr := uint32(1) << log2u32(end-x)
		W := min(wx, wr)
		d := log2u32(W>>(lu-lc)) + g
		i0 := k + (x-S)>>(lu-lc)
		mass := pfg[i0+W>>(lu-lc)] - pfg[i0]
		touches += mass * nudgeTouches(lr, d)
		x += W
	}
	return 256*b + nudgeLambdaQ8*touches
}

// nudgeWS holds the planes of the slot-ledger DP.
type nudgeWS struct {
	jcur, jnxt [(nudgeDPM + 1) * (nudgeDPM + 1)]uint64
	arrive     [(nudgeLU + 1) * (nudgeDPM + 1) * (nudgeDPM + 1)]uint8
}

// nudgeDPSolve is zxc_huf_nudge_dp_solve: the class counts minimizing J
// over m coarse symbols, or false when no finish is feasible.
func (ws *nudgeWS) solve(pfg []uint64, m, capC, lu, g int) ([nudgeLU + 1]uint32, bool) {
	var out [nudgeLU + 1]uint32
	if m < 2 || m > nudgeDPM || capC < 1 || capC > nudgeLU {
		return out, false
	}
	plane := (m + 1) * (m + 1)
	arriveCnt := (capC + 1) * plane
	jcur, jnxt := ws.jcur[:plane], ws.jnxt[:plane]
	idx := func(k, s int) int { return k*(m+1) + s }
	const inf = uint64(1<<64 - 1)
	for i := range jcur {
		jcur[i] = inf
	}
	jcur[idx(0, 2)] = 0
	bestJ := inf
	bestL, bestK, bestS := 0, 0, 0
	for lc := 1; lc <= capC; lc++ {
		for i := range jnxt {
			jnxt[i] = inf
		}
		for k := 0; k < m; k++ {
			nRem := uint32(m - k)
			for s := uint32(1); s <= nRem; s++ {
				from := idx(k, int(s))
				if from >= plane {
					continue
				}
				j0 := jcur[from]
				if j0 == inf {
					continue
				}
				if s == nRem {
					j := j0 + nudgeDPRunJ(lu, lc, g, s, s, pfg, uint32(k)) +
						nudgeLambdaQ8*nudgeLevelCost*uint64(lc+g+1)
					if j < bestJ {
						bestJ, bestL, bestK, bestS = j, lc, k, int(s)
					}
					continue
				}
				if lc == capC {
					continue
				}
				mm := uint32(1) << (capC - lc)
				lo := uint32(0)
				if 2*s > nRem {
					lo = 2*s - nRem
				}
				hi := min(s-1, (s*mm-nRem)/(mm-1))
				for c := lo; c <= hi; c++ {
					j := j0 + nudgeDPRunJ(lu, lc, g, s, c, pfg, uint32(k))
					to := idx(k+int(c), int(2*(s-c)))
					arr := (lc+1)*plane + to
					if to >= plane || arr >= arriveCnt {
						continue
					}
					if j < jnxt[to] {
						jnxt[to] = j
						ws.arrive[arr] = uint8(c)
					}
				}
			}
		}
		jcur, jnxt = jnxt, jcur
	}
	if bestJ == inf {
		return out, false
	}
	out[bestL] = uint32(bestS)
	k, s := bestK, bestS
	for lc := bestL; lc > 1; lc-- {
		c := int(ws.arrive[lc*plane+idx(k, s)])
		out[lc-1] = uint32(c)
		s = s/2 + c
		k -= c
	}
	if k != 0 || s != 2 {
		return out, false
	}
	return out, true
}

// nudgeCodeLengths may replace codeLen, built by buildCodeLengths for freq
// with the cap maxLen, by a reshaped code that the PivCo decoder walks
// faster; it reports whether it did.
func (b *hufBuilder) nudgeCodeLengths(freq *[hufNumSymbols]uint32, codeLen *[hufNumSymbols]uint8, maxLen int) bool {
	blc0, n := nudgeClasses(codeLen)
	if n < 4 {
		return false
	}
	var pf [hufNumSymbols + 1]uint64
	nudgePFCanonical(codeLen, freq, &blc0, &pf)
	bits0, touches0 := nudgeEval(&blc0, pf[:])

	// Frequency-rank order, rank 0 the most frequent: the ascending order
	// of buildCodeLengths read backwards.
	var lb [hufNumSymbols]hufLeaf
	leaves := lb[:0]
	for s, f := range freq {
		if f != 0 {
			leaves = append(leaves, hufLeaf{f, int16(s)})
		}
	}
	sortLeaves(leaves)
	var symOrder [hufNumSymbols]int16
	var pfRank [hufNumSymbols + 1]uint64
	for r := range n {
		symOrder[r] = leaves[n-1-r].sym
		pfRank[r+1] = pfRank[r] + uint64(leaves[n-1-r].w)
	}
	assign := func(blc *[nudgeLU + 1]uint32, cl *[hufNumSymbols]uint8) {
		clear(cl[:])
		r := 0
		for l := 1; l <= nudgeLU; l++ {
			for range blc[l] {
				cl[symOrder[r]] = uint8(l)
				r++
			}
		}
	}

	// Candidates: the greedy walk, package-merge at caps 1 and 2 below the
	// baseline's depth, and the slot-ledger DP.
	var cands [4][hufNumSymbols]uint8
	nc := 0
	blcW := nudgeWalk(&blc0, pfRank[:], n, maxLen)
	assign(&blcW, &cands[nc])
	nc++
	maxLen0 := 0
	for l := nudgeLU; l >= 1; l-- {
		if blc0[l] != 0 {
			maxLen0 = l
			break
		}
	}
	if maxLen0 >= 2 {
		for cut := 1; cut <= 2; cut++ {
			cap2 := maxLen0 - cut
			if cap2 < 2 || 1<<cap2 < n {
				break
			}
			if !b.buildCodeLengths(freq, &cands[nc], cap2) {
				break
			}
			nc++
		}
	}
	g2 := 0
	for (n+1<<g2-1)>>g2 > nudgeDPM {
		g2++
	}
	g := 1 << g2
	m := (n + g - 1) / g
	capC := maxLen - g2
	if m >= 2 && capC >= 1 && m <= 1<<capC {
		var pfg [nudgeDPM + 1]uint64
		for j := 0; j <= m; j++ {
			pfg[j] = pfRank[min(j*g, n)]
		}
		if b.ws == nil {
			b.ws = new(nudgeWS)
		}
		if cblc, ok := b.ws.solve(pfg[:], m, capC, nudgeLU-g2, g2); ok {
			cl := &cands[nc]
			clear(cl[:])
			r, ghosts := 0, 0
			ghostLen := uint8(0)
			for lc := 1; lc <= capC; lc++ {
				for range cblc[lc] {
					for range g {
						if r < n {
							cl[symOrder[r]] = uint8(lc + g2)
						} else {
							ghostLen = uint8(lc + g2)
							ghosts++
						}
						r++
					}
				}
			}
			for s := 0; s < hufNumSymbols && ghosts > 0; s++ {
				if freq[s] == 0 && cl[s] == 0 {
					cl[s] = ghostLen
					ghosts--
				}
			}
			nc++
		}
	}

	// The cheapest candidate within the guards and strictly below the
	// baseline's J, if any.
	bestJ := nudgeJ(bits0, touches0)
	best := -1
	for ci := range nc {
		valid := true
		for s := range hufNumSymbols {
			if freq[s] != 0 && cands[ci][s] == 0 {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		blc, _ := nudgeClasses(&cands[ci])
		nudgePFCanonical(&cands[ci], freq, &blc, &pf)
		b1, t1 := nudgeEval(&blc, pf[:])
		if b1*1000 > bits0*nudgeBitsPermil || t1*256 > touches0*nudgeMergeQ8 {
			continue
		}
		if j := nudgeJ(b1, t1); j < bestJ {
			bestJ, best = j, ci
		}
	}
	if best >= 0 {
		*codeLen = cands[best]
	}
	return best >= 0
}

// PivCo section encoder (§ 5.2.1): zxc_pivco_tree_build, zxc_huf_calc_size
// and zxc_huf_encode_section of the reference library.

const (
	pivcoMaxNodes   = 2*hufNumSymbols - 1
	pivcoNodeSlots  = pivcoMaxNodes + 1
	pivcoCovered    = 0xFF
	pivcoIncomplete = 0xFE
)

// encTree is the canonical code tree of a set of code lengths, as the
// encoder walks it. Nodes are numbered depth by depth, the leaves of a
// depth first; the d-bit prefix c is node base[d] + c.
type encTree struct {
	maxDepth int
	base     [hufMaxCodeLenUltra + 2]int
	nodeBase [hufMaxCodeLenUltra + 2]int
	leafBase [hufMaxCodeLenUltra + 2]int
	syms     [hufNumSymbols]uint8
	flatD    [pivcoNodeSlots]uint8 // flat-root depth, 0, or pivcoCovered
}

func (t *encTree) leaves(d int) int { return t.leafBase[d+1] - t.leafBase[d] }

// build builds the tree of codeLen, Kraft-tight or a lone length-1 symbol,
// and reports false for other lengths.
func (t *encTree) build(codeLen *[hufNumSymbols]uint8) bool {
	var blCount [hufMaxCodeLenUltra + 1]int
	present, maxDepth := 0, 0
	for _, l := range codeLen {
		if l == 0 {
			continue
		}
		if l > hufMaxCodeLenUltra {
			return false
		}
		blCount[l]++
		present++
		maxDepth = max(maxDepth, int(l))
	}
	if present == 0 {
		return false
	}
	if present >= 2 {
		kraft := 0
		for l := 1; l <= hufMaxCodeLenUltra; l++ {
			kraft += blCount[l] << (hufMaxCodeLenUltra - l)
		}
		if kraft != 1<<hufMaxCodeLenUltra {
			return false
		}
	} else if blCount[1] != 1 {
		return false
	}
	t.maxDepth = maxDepth
	width, first := 1, 0
	t.nodeBase[0], t.leafBase[0] = 0, 0
	for d := 0; d <= maxDepth; d++ {
		t.base[d] = t.nodeBase[d] - first
		t.nodeBase[d+1] = t.nodeBase[d] + width
		t.leafBase[d+1] = t.leafBase[d] + blCount[d]
		first = 2 * (first + blCount[d])
		if d == 0 && present == 1 {
			width = 1
		} else {
			width = 2 * (width - blCount[d])
		}
	}
	var pos [hufMaxCodeLenUltra + 1]int
	for d := 0; d <= maxDepth; d++ {
		pos[d] = t.leafBase[d]
	}
	for s, l := range codeLen {
		if l != 0 {
			t.syms[pos[l]] = uint8(s)
			pos[l]++
		}
	}

	// Bottom-up, the heights of complete subtrees; top-down, the first
	// height of 2 or more on a path is a flat root, the nodes below it
	// covered, and its leaves are stored in bit-reversed order.
	t.flatD[t.nodeBase[maxDepth+1]] = 0
	for d := maxDepth; d >= 0; d-- {
		h := t.flatD[t.nodeBase[d]:]
		hc := t.flatD[t.nodeBase[d+1]:]
		L := t.leaves(d)
		N := t.nodeBase[d+1] - t.nodeBase[d]
		for i := range L {
			h[i] = 0
		}
		for i := L; i < N; i++ {
			a, b := hc[2*(i-L)], hc[2*(i-L)+1]
			if a == b && a != pivcoIncomplete {
				h[i] = a + 1
			} else {
				h[i] = pivcoIncomplete
			}
		}
	}
	for d := 0; d < maxDepth; d++ {
		fd := t.flatD[t.nodeBase[d]:]
		var up []uint8
		if d > 0 {
			up = t.flatD[t.nodeBase[d-1]+t.leaves(d-1):]
		}
		N := t.nodeBase[d+1] - t.nodeBase[d]
		for i := t.leaves(d); i < N; i++ {
			switch {
			case up != nil && up[i>>1] != 0:
				fd[i] = pivcoCovered
			case fd[i] < 2 || fd[i] == pivcoIncomplete:
				fd[i] = 0
			default:
				D := int(fd[i])
				g := t.nodeBase[d] + i
				e := d + D
				first := t.leafBase[e] + t.base[e] - t.nodeBase[e] + (g-t.base[d])<<D
				bitrevPermute(t.syms[first:first+1<<D], D)
			}
		}
	}
	return true
}

// bitrevPermute reorders s, of 2^D entries, by bit-reversed index.
func bitrevPermute(s []uint8, D int) {
	m := uint(1) << D
	c := uint(0)
	for r := uint(0); r < m; r++ {
		if r < c {
			s[r], s[c] = s[c], s[r]
		}
		bit := m >> 1
		for ; c&bit != 0; bit >>= 1 {
			c ^= bit
		}
		c |= bit
	}
}

// counts sets count to the number of symbols under each node.
func (t *encTree) counts(freq *[hufNumSymbols]uint32, count *[pivcoNodeSlots]uint32) {
	count[t.nodeBase[t.maxDepth+1]] = 0
	for d := t.maxDepth; d >= 0; d-- {
		L := t.leaves(d)
		N := t.nodeBase[d+1] - t.nodeBase[d]
		cnt := count[t.nodeBase[d]:]
		ccnt := count[t.nodeBase[d+1]:]
		sym := t.syms[t.leafBase[d]:]
		for i := range L {
			cnt[i] = freq[sym[i]]
		}
		for i := L; i < N; i++ {
			cnt[i] = ccnt[2*(i-L)] + ccnt[2*(i-L)+1]
		}
	}
}

// layout returns the payload size of the runs, and sets cur, when not nil,
// to the first bit of each run: every uncovered internal node in wire
// order, ceil(count*D/8) bytes for a flat root of depth D, ceil(count/8)
// for a merge node.
func (t *encTree) layout(count *[pivcoNodeSlots]uint32, cur *[pivcoMaxNodes]uint32) int {
	total := 0
	for d := 0; d < t.maxDepth; d++ {
		for g := t.nodeBase[d] + t.leaves(d); g < t.nodeBase[d+1]; g++ {
			fd := t.flatD[g]
			if fd == pivcoCovered {
				continue
			}
			if cur != nil {
				cur[g] = uint32(total << 3)
			}
			if fd != 0 {
				total += (int(count[g])*int(fd) + 7) / 8
			} else {
				total += (int(count[g]) + 7) / 8
			}
		}
	}
	return total
}

// pivcoSize is zxc_huf_calc_size with the header: the size of the PivCo
// section of a histogram under codeLen, or -1 when the lengths are
// malformed or a present symbol has no code.
func pivcoSize(freq *[hufNumSymbols]uint32, codeLen *[hufNumSymbols]uint8, t *encTree) int {
	if !t.build(codeLen) {
		return -1
	}
	if n := pivcoBodySize(freq, codeLen, t); n >= 0 {
		return hufTableSize + n
	}
	return -1
}

// pivcoBodySize is zxc_huf_calc_size_dict: the size of the runs of a PivCo
// section under the code of the built tree t, or -1 when a present symbol
// has no code.
func pivcoBodySize(freq *[hufNumSymbols]uint32, codeLen *[hufNumSymbols]uint8, t *encTree) int {
	for k := range hufNumSymbols {
		if freq[k] != 0 && codeLen[k] == 0 {
			return -1
		}
	}
	var count [pivcoNodeSlots]uint32
	t.counts(freq, &count)
	return t.layout(&count, nil)
}

// appendPivCo appends the PivCo section of syms under codeLen, whose tree
// t is built: the 128-byte table of the lengths, 4 bits per symbol low
// nibble first, when header is set (not for the shared table of a
// dictionary), then the runs. Each symbol is walked from the
// root, appending its branch bit to the run of each node on its path, or
// its last D bits to a flat root's run, where the walk stops.
func appendPivCo(dst, syms []byte, freq *[hufNumSymbols]uint32, codeLen *[hufNumSymbols]uint8, t *encTree, header bool) []byte {
	var codes [hufNumSymbols]uint32
	for d := 1; d <= t.maxDepth; d++ {
		for i := range t.leaves(d) {
			codes[t.syms[t.leafBase[d]+i]] = uint32(t.nodeBase[d] + i - t.base[d])
		}
	}
	var count [pivcoNodeSlots]uint32
	t.counts(freq, &count)
	var cur [pivcoMaxNodes]uint32
	payload := t.layout(&count, &cur)
	for i := 0; header && i < hufNumSymbols; i += 2 {
		dst = append(dst, codeLen[i]&0x0F|codeLen[i+1]<<4)
	}
	at := len(dst)
	dst = append(dst, make([]byte, payload+2)...) // +2: the 3-byte writes of flat codes
	out := dst[at:]
	for _, s := range syms {
		c := codes[s]
		l := int(codeLen[s])
		for d := range l {
			g := t.base[d] + int(c>>(l-d))
			if fd := t.flatD[g]; fd != 0 {
				p := cur[g]
				cur[g] += uint32(fd)
				q := out[p>>3:]
				w := uint32(q[0]) | uint32(q[1])<<8 | uint32(q[2])<<16
				w |= (c & (1<<fd - 1)) << (p & 7)
				q[0], q[1], q[2] = byte(w), byte(w>>8), byte(w>>16)
				break
			}
			p := cur[g]
			cur[g]++
			out[p>>3] |= byte((c >> (l - 1 - d)) & 1 << (p & 7))
		}
	}
	return dst[:at+payload]
}
