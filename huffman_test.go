package zxc

import (
	"bytes"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

// randomLengths returns the code lengths of a random complete code of k
// symbols with codes of at most maxLen bits: a random full binary tree,
// grown by splitting random leaves, its leaves given random symbols.
func randomLengths(r *rand.Rand, k, maxLen int) (lens [hufNumSymbols]uint8) {
	if k == 1 {
		lens[r.IntN(256)] = 1
		return lens
	}
	depths := []int{1, 1}
	for len(depths) < k {
		i := r.IntN(len(depths))
		if depths[i] >= maxLen {
			continue
		}
		d := depths[i] + 1
		depths[i] = d
		depths = append(depths, d)
	}
	syms := r.Perm(256)
	for i, d := range depths {
		lens[syms[i]] = uint8(d)
	}
	return lens
}

// randomData draws n symbols among those with a code, with a skewed
// distribution so that some nodes see many symbols and others few or none.
func randomData(r *rand.Rand, lens *[hufNumSymbols]uint8, n int) []byte {
	var present []byte
	for s, l := range lens {
		if l != 0 {
			present = append(present, byte(s))
		}
	}
	data := make([]byte, n)
	for i := range data {
		j := r.IntN(len(present))
		if r.IntN(2) == 0 {
			j = j * j / len(present) // favour the first symbols
		}
		data[i] = present[j]
	}
	return data
}

func checkRoundTrip(t *testing.T, lens *[hufNumSymbols]uint8, data []byte) {
	t.Helper()
	tree, err := buildHufTree(lens)
	if err != nil {
		t.Fatal(err)
	}
	ref := newRefTree(t, lens)
	body := encodePivCo(ref, data)
	n := len(data)

	walk := make([]byte, n)
	if err := ref.decodeWalk(body, n, walk); err != nil {
		t.Fatalf("decodeWalk: %v", err)
	}
	if !bytes.Equal(walk, data) {
		t.Fatal("decodeWalk differs from the input")
	}
	var hd hufDecoder
	fast := make([]byte, n+wildPad)
	if err := hd.decode(tree, body, n, fast); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(fast[:n], data) {
		for i := range data {
			if fast[i] != data[i] {
				t.Fatalf("decode differs from the input at %d of %d", i, n)
			}
		}
	}
}

func TestHuffmanRandomTrees(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	for iter := range 3000 {
		k := 1 + r.IntN(256)
		maxLen := 2 + r.IntN(hufMaxLen-1)
		for k > 1<<maxLen {
			maxLen++
		}
		if k == 1 {
			maxLen = 1
		}
		lens := randomLengths(r, k, maxLen)
		n := 1 + r.IntN(3000)
		if iter%10 == 0 {
			n = 1 + r.IntN(20) // tails shorter than a merge step
		}
		checkRoundTrip(t, &lens, randomData(r, &lens, n))
	}
}

func TestHuffmanSpecialTrees(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 8))
	var all8, two, lone [hufNumSymbols]uint8
	for s := range all8 {
		all8[s] = 8 // one flat root of depth 8: the whole section packed
	}
	two['a'], two['b'] = 1, 1 // a root leaf pair
	lone['z'] = 1             // a single symbol
	for name, lens := range map[string]*[hufNumSymbols]uint8{"all8": &all8, "two": &two, "lone": &lone} {
		t.Run(name, func(t *testing.T) {
			for _, n := range []int{1, 7, 8, 9, 63, 64, 65, 1000} {
				checkRoundTrip(t, lens, randomData(r, lens, n))
			}
		})
	}
}

func TestHuffmanTreeValidation(t *testing.T) {
	var lens [hufNumSymbols]uint8
	if _, err := buildHufTree(&lens); err == nil {
		t.Error("accepted a table without symbols")
	}
	lens[0] = 2
	if _, err := buildHufTree(&lens); err == nil {
		t.Error("accepted a lone symbol of length 2")
	}
	lens[0], lens[1], lens[2] = 1, 2, 3 // Kraft sum below 1
	if _, err := buildHufTree(&lens); err == nil {
		t.Error("accepted an incomplete code")
	}
	lens[2] = 2
	if _, err := buildHufTree(&lens); err != nil {
		t.Errorf("rejected a complete code: %v", err)
	}
	lens[3] = 12
	if _, err := buildHufTree(&lens); err == nil {
		t.Error("accepted a 12-bit code")
	}
}

// FuzzHuffman feeds arbitrary section bodies to both decoders for random
// trees: they must agree, on the output or on the rejection, and never
// panic.
func FuzzHuffman(f *testing.F) {
	f.Add(uint64(1), []byte{0xAA, 0x55, 0x0F})
	f.Add(uint64(2), bytes.Repeat([]byte{0xFF}, 300))
	f.Fuzz(func(t *testing.T, seed uint64, body []byte) {
		r := rand.New(rand.NewPCG(seed, seed>>32))
		k := 1 + r.IntN(256)
		maxLen := hufMaxLen
		if k == 1 {
			maxLen = 1
		}
		lens := randomLengths(r, k, maxLen)
		tree, err := buildHufTree(&lens)
		if err != nil {
			t.Fatal(err)
		}
		n := 1 + int(seed%2000)
		walk := make([]byte, n)
		errW := newRefTree(t, &lens).decodeWalk(body, n, walk)
		var hd hufDecoder
		fast := make([]byte, n+wildPad)
		errF := hd.decode(tree, body, n, fast)
		if (errW == nil) != (errF == nil) {
			t.Fatalf("walk: %v, fast: %v", errW, errF)
		}
		if errW == nil && !bytes.Equal(walk, fast[:n]) {
			t.Fatal("decoders disagree")
		}
	})
}

// BenchmarkHuffman measures the literal decoder alone on the sections of
// a level-6 or level-7 archive named by ZXC_BENCH_FILE.
func BenchmarkHuffman(b *testing.B) {
	path := os.Getenv("ZXC_BENCH_FILE")
	if path == "" {
		path = filepath.Join("testdata", "v9", "valid", "spl_pivco_wide_l7.zxc")
	}
	src, err := os.ReadFile(path)
	if err != nil {
		b.Skip(err)
	}
	hdr, err := parseFileHeader(src)
	if err != nil {
		b.Fatal(err)
	}
	type section struct {
		tree *hufTree
		body []byte
		n    int
	}
	var secs []section
	total := 0
	ck := 0
	if hdr.hasChecksum {
		ck = blockChecksumSize
	}
	for pos := fileHeaderSize; ; {
		typ, size, err := parseBlockHeader(src[pos:])
		if err != nil || typ == blockEOF {
			break
		}
		p := src[pos+blockHeaderSize : pos+blockHeaderSize+int(size)]
		pos += blockHeaderSize + int(size) + ck
		if typ != blockSPL {
			continue
		}
		h, _ := parseLZHeader(p)
		if h.encLit != encHuffman || h.nLit == 0 {
			continue
		}
		litComp := int(uint32(p[12]) | uint32(p[13])<<8 | uint32(p[14])<<16 | uint32(p[15])<<24)
		off := lzHeaderSize + 4
		if h.encTok == encHuffman {
			off += 4
		}
		sec := p[off : off+litComp]
		lens := unpackLengths(sec)
		tree, err := buildHufTree(&lens)
		if err != nil {
			b.Fatal(err)
		}
		secs = append(secs, section{tree, sec[hufTableSize:], int(h.nLit)})
		total += int(h.nLit)
	}
	if len(secs) == 0 {
		b.Skip("no Huffman literal section")
	}
	var hd hufDecoder
	out := make([]byte, 1<<21+wildPad)
	b.SetBytes(int64(total))
	b.ResetTimer()
	for range b.N {
		for _, s := range secs {
			if err := hd.decode(s.tree, s.body, s.n, out); err != nil {
				b.Fatal(err)
			}
		}
	}
}
