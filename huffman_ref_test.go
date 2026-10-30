package zxc

import "testing"

// The former Huffman decoder, a structure per node of the code tree, kept
// as the reference the level-based decoder of huffman.go is held to, with
// the straightforward PivCo encoder the tests build sections with.

// hufNode is a node of the canonical code tree. Nodes are stored in BFS
// order (parents before children, left before right), which is the wire
// order of the runs.
type hufNode struct {
	child [2]int32 // left, right; -1 when absent (lone-symbol root's right)
	flat  int32    // flat roots: offset of their code -> symbol table in flatBuf
	sym   uint8    // leaves only
	leaf  bool
	flatD uint8 // > 0: flat root of a perfect subtree of this depth
	inner bool  // strict descendant of a flat root: emits no run
	pair  bool  // bitmap node whose two children are leaves
	depth uint8 // depth in the tree
}

// refTree is the former code tree, a structure per node, kept for the
// tests: its decoders are the references the decoder is held to.
type refTree struct {
	nodes    []hufNode
	maxDepth int
	level    [hufMaxLen + 2]int32 // nodes of depth d are nodes[level[d]:level[d+1]]

	// Flat-root tables: 2^D symbols each, indexed by packed code. Their
	// sizes add up to the number of leaves under flat roots, at most 256.
	flatBuf [hufNumSymbols]uint8

	height []uint8 // perfect-subtree heights, while building
}

// flatTable returns the code -> symbol table of flat root nd.
func (t *refTree) flatTable(nd *hufNode) []uint8 {
	return t.flatBuf[nd.flat : nd.flat+1<<nd.flatD]
}

// newRefTree builds the reference tree of lens.
func newRefTree(t testing.TB, lens *[hufNumSymbols]uint8) *refTree {
	t.Helper()
	rt := new(refTree)
	if err := rt.buildTrie(lens); err != nil {
		t.Fatal(err)
	}
	return rt
}

// buildTrie builds the tree of lens the simplest way: it inserts every code
// into a trie, then renumbers the trie in BFS order.
func (t *refTree) buildTrie(lens *[hufNumSymbols]uint8) error {
	var count [hufMaxLen + 1]int
	present, maxLen := 0, 0
	for _, l := range lens {
		if l == 0 {
			continue
		}
		if l > hufMaxLen {
			return corruptf("Huffman code length %d > %d", l, hufMaxLen)
		}
		count[l]++
		present++
		maxLen = max(maxLen, int(l))
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

	// Canonical codes: symbols ordered by (length, symbol), consecutive
	// values, shifted left when the length grows. Insert each into a trie,
	// read MSB first. A complete code of 256 symbols at most has fewer
	// than 512 nodes.
	trie := []hufNode{{child: [2]int32{-1, -1}}}
	code := 0
	prevLen := 0
	for l := 1; l <= maxLen; l++ {
		if count[l] == 0 {
			continue
		}
		for s := range hufNumSymbols {
			if int(lens[s]) != l {
				continue
			}
			code <<= l - prevLen
			prevLen = l
			n := int32(0)
			for d := l - 1; d >= 0; d-- {
				b := code >> d & 1
				c := trie[n].child[b]
				if c < 0 {
					c = int32(len(trie))
					trie = append(trie, hufNode{child: [2]int32{-1, -1}, depth: uint8(l - d)})
					trie[n].child[b] = c
				}
				n = c
			}
			trie[n].leaf = true
			trie[n].sym = uint8(s)
			code++
		}
	}

	// Renumber in BFS order: nodes[] is filled as a queue; a node's
	// children still hold trie indices until it is dequeued.
	t.height = make([]uint8, len(trie))
	nodes := []hufNode{trie[0]}
	for i := 0; i < len(nodes); i++ {
		for k, c := range nodes[i].child {
			if c >= 0 {
				nodes[i].child[k] = int32(len(nodes))
				nodes = append(nodes, trie[c])
			}
		}
	}
	t.nodes = nodes

	// Flat roots: the first node of perfect height >= 2 on every path from
	// the root (§ 5.2.1, a fixed format rule).
	const incomplete = 0xFF
	h := t.height[:len(nodes)]
	for i := len(nodes) - 1; i >= 0; i-- { // children after parents
		nd := &nodes[i]
		switch {
		case nd.leaf:
			h[i] = 0
		case nd.child[0] < 0 || nd.child[1] < 0:
			h[i] = incomplete
		default:
			a, b := h[nd.child[0]], h[nd.child[1]]
			if a == b && a != incomplete {
				h[i] = a + 1
			} else {
				h[i] = incomplete
			}
		}
	}
	flatUsed := int32(0)
	for i := range nodes { // parents before children
		nd := &nodes[i]
		if nd.leaf || nd.inner || h[i] == incomplete || h[i] < 2 {
			continue
		}
		nd.flatD = h[i]
		nd.flat = flatUsed
		flatUsed += 1 << h[i]
		t.markFlat(int32(i), int32(i), 0, 0)
	}
	for i := range nodes {
		nd := &nodes[i]
		if !nd.leaf && !nd.inner && nd.flatD == 0 && nd.child[1] >= 0 &&
			nodes[nd.child[0]].leaf && nodes[nd.child[1]].leaf {
			nd.pair = true
		}
	}
	// BFS order is level order: each depth is a contiguous range.
	t.level = [hufMaxLen + 2]int32{}
	for i := range nodes {
		t.level[nodes[i].depth+1] = int32(i + 1)
	}
	for d := 1; d < len(t.level); d++ {
		t.level[d] = max(t.level[d], t.level[d-1])
	}
	return nil
}

// markFlat walks the perfect subtree below flat root r: it marks the inner
// nodes and records the symbol of each leaf under its packed code, whose
// bit j is the branch at relative depth j.
func (t *refTree) markFlat(r, n int32, depth uint8, code int) {
	nd := &t.nodes[n]
	if nd.leaf {
		t.flatBuf[int(t.nodes[r].flat)+code] = nd.sym
		return
	}
	if n != r {
		nd.inner = true
	}
	for b, c := range nd.child {
		t.markFlat(r, c, depth+1, code|b<<depth)
	}
}

// hufRun is the bit run of one emitting node, located by the sizing pass.
type hufRun struct {
	off   int // first byte in the section body
	count int // symbols routed through the node
}

// sizeRuns is pass 1 of the decoder: in wire order, it locates every
// node's run, checks it lies within the body, and derives the symbol count
// of every node from its parent's popcount. runs is indexed by node.
func (t *refTree) sizeRuns(body []byte, n int, runs []hufRun) error {
	for i := range runs {
		runs[i] = hufRun{}
	}
	runs[0].count = n
	p := 0
	for i := range t.nodes {
		nd := &t.nodes[i]
		if nd.leaf || nd.inner {
			continue
		}
		c := runs[i].count
		runs[i].off = p
		if nd.flatD > 0 {
			nb := (c*int(nd.flatD) + 7) / 8
			if nb > len(body)-p {
				return corruptf("Huffman run of node %d past the section", i)
			}
			p += nb
			continue
		}
		nb := (c + 7) / 8
		if nb > len(body)-p {
			return corruptf("Huffman run of node %d past the section", i)
		}
		ones := popcountBits(body[p:p+nb], c)
		p += nb
		l, r := nd.child[0], nd.child[1]
		switch {
		case r < 0:
			if ones != 0 {
				return corruptf("Huffman bits route symbols to an absent node")
			}
			runs[l].count = c
		case nd.pair:
			// The node emits its two leaves itself: they hold no sequence
			// of their own in the level below.
		default:
			runs[l].count = c - ones
			runs[r].count = ones
		}
	}
	return nil
}

// decodeRef is the former decode: it decodes the n symbols of a section body (the runs, after any
// inline table) into out[:n]; out must hold n + wildPad bytes.
//
// It rebuilds the symbol sequence bottom-up, one tree level at a time
// (§ 5.2.1): the sequence of a leaf is its symbol repeated, that of a flat
// root is its packed codes looked up, and that of a bitmap node interleaves
// its two children's sequences as its bits say. Each level is written next
// to the previous one, alternately in out (even depths, so depth 0 ends in
// out) and in a scratch buffer (odd depths).
func (t *refTree) decodeRef(body []byte, n int, out []byte) error {
	var hd struct {
		runs []hufRun
		tmp  []byte
	}
	out = out[:n+wildPad] // the merges read up to 8 bytes past a sequence
	if cap(hd.runs) < len(t.nodes) {
		hd.runs = make([]hufRun, len(t.nodes))
	}
	runs := hd.runs[:len(t.nodes)]
	if err := t.sizeRuns(body, n, runs); err != nil {
		return err
	}
	hd.tmp = grow(hd.tmp, n+wildPad)
	for d := t.maxDepth; d >= 0; d-- {
		buf, child := out, hd.tmp
		if d&1 != 0 {
			buf, child = hd.tmp, out
		}
		off, coff := 0, 0
		for i := t.level[d]; i < t.level[d+1]; i++ {
			nd := &t.nodes[i]
			c := runs[i].count
			if c == 0 {
				continue
			}
			dst := buf[off : off+c]
			off += c
			switch {
			case nd.leaf:
				fill(dst, nd.sym)
			case nd.flatD > 0:
				unpackFlat(dst, body[runs[i].off:], nd.flatD, &t.flatBuf, int(nd.flat))
			case nd.pair:
				s0 := t.nodes[nd.child[0]].sym
				s1 := t.nodes[nd.child[1]].sym
				mergePair(dst, body[runs[i].off:], s0, s1)
			default:
				nl := runs[nd.child[0]].count
				nr := 0
				if nd.child[1] >= 0 {
					nr = runs[nd.child[1]].count
				}
				merge(dst, child, coff, nl, body[runs[i].off:])
				coff += nl + nr
			}
		}
	}
	return nil
}

// decodeWalk decodes n symbols of a section body into out the simple way:
// each symbol walks from the root to its leaf, taking the next bit (or D
// bits) of every node it crosses. It is the reference the tests hold
// the merge-based decoder to.
func (t *refTree) decodeWalk(body []byte, n int, out []byte) error {
	runs := make([]hufRun, len(t.nodes))
	if err := t.sizeRuns(body, n, runs); err != nil {
		return err
	}
	cur := make([]int, len(t.nodes)) // bit position in each node's run
	for i := range n {
		k := int32(0)
		for {
			nd := &t.nodes[k]
			if nd.leaf {
				out[i] = nd.sym
				break
			}
			bitPos := runs[k].off*8 + cur[k]
			if nd.flatD > 0 {
				v := 0
				for j := range int(nd.flatD) {
					v |= int(body[(bitPos+j)/8]>>((bitPos+j)%8)&1) << j
				}
				cur[k] += int(nd.flatD)
				out[i] = t.flatTable(nd)[v]
				break
			}
			b := body[bitPos/8] >> (bitPos % 8) & 1
			cur[k]++
			k = nd.child[b]
		}
	}
	return nil
}

// encodePivCo is a straightforward PivCo encoder, written from § 5.2.1 for
// the tests: each symbol walks from the root to its leaf, appending its
// branch bit to every bitmap node it crosses, or its D-bit packed code to
// the flat root it reaches. The runs are then laid out in BFS order, each
// padded to a byte.
func encodePivCo(t *refTree, data []byte) []byte {
	// Path of each symbol: the nodes from the root to its leaf.
	type step struct {
		node int32
		b    int
	}
	paths := make(map[byte][]step)
	var walk func(n int32, path []step)
	walk = func(n int32, path []step) {
		nd := &t.nodes[n]
		if nd.leaf {
			paths[nd.sym] = append([]step(nil), path...)
			return
		}
		for b, c := range nd.child {
			if c >= 0 {
				walk(c, append(path, step{n, b}))
			}
		}
	}
	walk(0, nil)

	runs := make([][]int, len(t.nodes)) // bits of each node, in order
	for _, s := range data {
		path, ok := paths[s]
		if !ok {
			panic("symbol without a code")
		}
		for i := 0; i < len(path); i++ {
			nd := &t.nodes[path[i].node]
			if nd.flatD > 0 {
				for j := range int(nd.flatD) {
					runs[path[i].node] = append(runs[path[i].node], path[i+j].b)
				}
				break
			}
			runs[path[i].node] = append(runs[path[i].node], path[i].b)
		}
	}
	var out []byte
	for i := range t.nodes {
		nd := &t.nodes[i]
		if nd.leaf || nd.inner {
			continue
		}
		run := make([]byte, (len(runs[i])+7)/8)
		for k, b := range runs[i] {
			run[k/8] |= byte(b) << (k % 8)
		}
		out = append(out, run...)
	}
	return out
}
