package zxc

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"
)

// decodePAKRef decodes a PAK payload like decodePAK, but every sequence
// goes through the checked emit path: no fast path, no assembly. It is the
// reference the fast paths are held to.
func decodePAKRef(out []byte, base int, p []byte) (int, error) {
	h, err := parseLZHeader(p)
	if err != nil {
		return 0, err
	}
	if h.encLit != encRAW || h.encTok != 0 {
		return 0, corruptf("PAK block with literal/token encoding %d/%d", h.encLit, h.encTok)
	}
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
		s := binary.LittleEndian.Uint32(seqs[i:])
		ll := int(s >> 24)
		mb := int(s >> 16 & 0xFF)
		off := int(s&0xFFFF) + 1
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

func putVarint(b []byte, v int) []byte {
	switch {
	case v < 1<<7:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, 0x80|byte(v&0x3F), byte(v>>6))
	}
	return append(b, 0xC0|byte(v&0x1F), byte(v>>5), byte(v>>13))
}

// makePAK builds a random valid PAK payload decoding to at most blockSize
// bytes, with every shape of sequence: long literal runs and matches
// (varints included), offsets from 1 up, and a tail that runs close to
// the block end. It returns the payload and the bytes it decodes to. With
// fill, the block decodes to exactly blockSize bytes, as every block of a
// frame but the last must.
func makePAK(r *rand.Rand, blockSize int, fill bool) ([]byte, []byte) {
	var lits, seqs, ext, want []byte
	nSeq := 0
	for {
		ll := r.IntN(12)
		switch r.IntN(8) {
		case 0:
			ll = r.IntN(300) // past 32, sometimes a varint
		case 1:
			ll = 0
		}
		ml := minMatch + r.IntN(28)
		switch r.IntN(8) {
		case 0:
			ml = minMatch + r.IntN(600)
		case 1:
			ml = minMatch + 250 + r.IntN(20) // around the varint threshold
		}
		if len(want)+ll+ml > blockSize {
			break
		}
		for range ll {
			c := byte(r.IntN(4) + 'a')
			lits = append(lits, c)
			want = append(want, c)
		}
		if len(want) == 0 {
			continue
		}
		off := 1 + r.IntN(min(len(want), 65536))
		switch r.IntN(4) {
		case 0:
			off = 1 + r.IntN(min(len(want), 40)) // short periods
		}
		for k := range ml {
			want = append(want, want[len(want)-off])
			_ = k
		}
		llf, mlf := ll, ml-minMatch
		if llf >= pakLenMask {
			ext = putVarint(ext, llf-pakLenMask)
			llf = pakLenMask
		}
		if mlf >= pakLenMask {
			ext = putVarint(ext, mlf-pakLenMask)
			mlf = pakLenMask
		}
		seqs = binary.LittleEndian.AppendUint32(seqs, uint32(llf)<<24|uint32(mlf)<<16|uint32(off-1))
		nSeq++
	}
	tail := r.IntN(min(40, blockSize-len(want)+1))
	if fill {
		tail = blockSize - len(want)
	}
	for range tail {
		c := byte(r.IntN(4) + 'a')
		lits = append(lits, c)
		want = append(want, c)
	}
	p := binary.LittleEndian.AppendUint32(nil, uint32(nSeq))
	p = binary.LittleEndian.AppendUint32(p, uint32(len(lits)))
	p = append(p, encRAW, 0, 0, 0)
	p = append(p, lits...)
	p = append(p, seqs...)
	p = append(p, ext...)
	p = append(p, make([]byte, litSlack)...)
	return p, want
}

// comparePAK decodes p with decodePAK and decodePAKRef; they must agree
// on success, size and output.
func comparePAK(t *testing.T, p []byte, blockSize int) {
	t.Helper()
	a := make([]byte, blockSize+wildPad)
	b := make([]byte, blockSize+wildPad)
	na, ea := decodePAK(a, 0, p)
	nb, eb := decodePAKRef(b, 0, p)
	if (ea == nil) != (eb == nil) {
		t.Fatalf("decodePAK: %v, reference: %v", ea, eb)
	}
	if ea == nil && (na != nb || !bytes.Equal(a[:na], b[:nb])) {
		t.Fatalf("decodePAK and the reference disagree: %d and %d bytes", na, nb)
	}
}

// TestPAKRandom holds decodePAK to the reference on random valid blocks,
// then on the same blocks with corrupted bytes. ZXC_PAK_ITERS sets the
// number of blocks (default 300), for long runs where go test -fuzz is not
// available, such as under user-mode emulation.
func TestPAKRandom(t *testing.T) {
	iters := 300
	if v, err := strconv.Atoi(os.Getenv("ZXC_PAK_ITERS")); err == nil && v > 0 {
		iters = v
	}
	r := rand.New(rand.NewPCG(11, uint64(iters)))
	for iter := range iters {
		blockSize := []int{4096, 65536, 1 << 19}[iter%3]
		p, want := makePAK(r, blockSize, false)
		out := make([]byte, blockSize+wildPad)
		n, err := decodePAK(out, 0, p)
		if err != nil || !bytes.Equal(out[:n], want) {
			t.Fatalf("iter %d: valid block: %v, %d bytes, want %d", iter, err, n, len(want))
		}
		comparePAK(t, p, blockSize)
		for range 10 {
			q := bytes.Clone(p)
			for range 1 + r.IntN(4) {
				q[r.IntN(len(q))] = byte(r.Uint32())
			}
			comparePAK(t, q, blockSize)
		}
	}
}

// TestPAKCorpus holds decodePAK to the reference on every PAK block of the
// archive named by ZXC_BENCH_FILE, if set.
func TestPAKCorpus(t *testing.T) {
	name := os.Getenv("ZXC_BENCH_FILE")
	if name == "" {
		t.Skip("ZXC_BENCH_FILE not set")
	}
	src, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := parseFileHeader(src)
	if err != nil {
		t.Fatal(err)
	}
	ck := 0
	if hdr.hasChecksum {
		ck = blockChecksumSize
	}
	n := 0
	for pos := fileHeaderSize; ; {
		typ, size, err := parseBlockHeader(src[pos:])
		if err != nil || typ == blockEOF {
			break
		}
		p := src[pos+blockHeaderSize : pos+blockHeaderSize+int(size)]
		pos += blockHeaderSize + int(size) + ck
		if typ == blockPAK {
			comparePAK(t, p, hdr.blockSize)
			n++
		}
	}
	t.Logf("%d PAK blocks", n)
}

// FuzzPAK holds decodePAK to the reference on arbitrary payloads, seeded
// with random valid blocks.
func FuzzPAK(f *testing.F) {
	r := rand.New(rand.NewPCG(13, 14))
	for range 8 {
		p, _ := makePAK(r, 4096, false)
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p []byte) {
		comparePAK(t, p, 4096)
	})
}

// TestPAKVarintBounds builds PAK blocks of short sequences with an empty
// extras section, and sets a length escape on one of their last sequence
// words: the varint it announces would run past the extras, which the
// decoder must report, not read. The payload ends with its sequence words.
func TestPAKVarintBounds(t *testing.T) {
	r := rand.New(rand.NewPCG(37, 38))
	for range 400 {
		nSeq := 10 + r.IntN(100)
		var lits, seqs []byte
		n := 0
		for range nSeq {
			ll, mb := r.IntN(4), r.IntN(6)
			for range ll {
				lits = append(lits, byte('a'+r.IntN(4)))
			}
			n += ll
			if n == 0 {
				lits = append(lits, 'a')
				ll, n = 1, 1
			}
			off := 1 + r.IntN(min(n, 200))
			seqs = binary.LittleEndian.AppendUint32(seqs, uint32(ll)<<24|uint32(mb)<<16|uint32(off-1))
			n += mb + minMatch
		}
		p := binary.LittleEndian.AppendUint32(nil, uint32(nSeq))
		p = binary.LittleEndian.AppendUint32(p, uint32(len(lits)))
		p = append(p, encRAW, 0, 0, 0)
		p = append(p, lits...)
		p = append(p, seqs...)
		p = p[:len(p):len(p)]
		comparePAK(t, p, 1<<16)
		word := lzHeaderSize + len(lits) + 4*(nSeq-1-r.IntN(4))
		if r.IntN(2) == 0 {
			p[word+3] = pakLenMask // LL
		} else {
			p[word+2] = pakLenMask // ML
		}
		comparePAK(t, p, 1<<16)
	}
}
