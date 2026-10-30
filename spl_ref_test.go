package zxc

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"
)

// decodeSPLRef decodes a SPL payload like decodeSPL, but every sequence
// goes through the checked emit path: no fast path, no assembly.
func decodeSPLRef(out []byte, base int, p []byte, sc *scratch, dict *Dictionary) (int, error) {
	b, err := prepareSPL(out, base, p, sc, dict)
	if err != nil {
		return 0, err
	}
	o, e := &b.o, 0
	for i, t := range b.tokens {
		ll := int(t >> 4)
		ml := int(t & splTokenMask)
		var off int
		if b.offWidth == 1 {
			off = int(b.offs[i]) + 1
		} else {
			off = int(binary.LittleEndian.Uint16(b.offs[2*i:])) + 1
		}
		if ll == splTokenMask {
			var v uint32
			if v, e, err = readVarint(b.extras, e); err != nil {
				return 0, err
			}
			ll += int(v)
		}
		if ml == splTokenMask {
			var v uint32
			if v, e, err = readVarint(b.extras, e); err != nil {
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

// makeSPL builds a random valid SPL payload, RAW literals and tokens, with
// offsets of w bytes, decoding to at most blockSize bytes: short and long
// literal runs and matches (varints included), offsets from 1 up to what
// the width allows, and a tail close to the block end.
func makeSPL(r *rand.Rand, blockSize, w int) ([]byte, []byte) {
	var lits, toks, offs, ext, want []byte
	maxOff := 65536
	if w == 1 {
		maxOff = 256
	}
	for {
		ll := r.IntN(8)
		switch r.IntN(8) {
		case 0:
			ll = r.IntN(60) // past 14: a varint
		case 1:
			ll = 0
		}
		ml := minMatch + r.IntN(15)
		switch r.IntN(8) {
		case 0:
			ml = minMatch + r.IntN(300)
		case 1:
			ml = minMatch + 13 + r.IntN(4) // around the escape value
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
		off := 1 + r.IntN(min(len(want), maxOff))
		if r.IntN(4) == 0 {
			off = 1 + r.IntN(min(len(want), 40))
		}
		for range ml {
			want = append(want, want[len(want)-off])
		}
		llf, mlf := ll, ml-minMatch
		if llf >= splTokenMask {
			ext = putVarint(ext, llf-splTokenMask)
			llf = splTokenMask
		}
		if mlf >= splTokenMask {
			ext = putVarint(ext, mlf-splTokenMask)
			mlf = splTokenMask
		}
		toks = append(toks, byte(llf<<4|mlf))
		if w == 1 {
			offs = append(offs, byte(off-1))
		} else {
			offs = binary.LittleEndian.AppendUint16(offs, uint16(off-1))
		}
	}
	for range r.IntN(min(40, blockSize-len(want)+1)) {
		c := byte(r.IntN(4) + 'a')
		lits = append(lits, c)
		want = append(want, c)
	}
	p := binary.LittleEndian.AppendUint32(nil, uint32(len(toks)))
	p = binary.LittleEndian.AppendUint32(p, uint32(len(lits)))
	encOff := byte(0)
	if w == 1 {
		encOff = 1
	}
	p = append(p, encRAW, encRAW, 0, encOff)
	p = append(p, lits...)
	p = append(p, toks...)
	p = append(p, offs...)
	p = append(p, ext...)
	p = append(p, make([]byte, litSlack)...)
	return p, want
}

// compareSPL decodes p with decodeSPL and decodeSPLRef; they must agree on
// success, size and output.
func compareSPL(t *testing.T, p []byte, blockSize int) {
	t.Helper()
	a := make([]byte, blockSize+wildPad)
	b := make([]byte, blockSize+wildPad)
	na, ea := decodeSPL(a, 0, p, &scratch{}, nil)
	nb, eb := decodeSPLRef(b, 0, p, &scratch{}, nil)
	if (ea == nil) != (eb == nil) {
		t.Fatalf("decodeSPL: %v, reference: %v", ea, eb)
	}
	if ea == nil && (na != nb || !bytes.Equal(a[:na], b[:nb])) {
		t.Fatalf("decodeSPL and the reference disagree: %d and %d bytes", na, nb)
	}
}

// TestSPLRandom holds decodeSPL to the reference on random valid blocks of
// both offset widths, then on the same blocks corrupted. ZXC_SPL_ITERS
// sets the number of blocks (default 300).
func TestSPLRandom(t *testing.T) {
	iters := 300
	if v, err := strconv.Atoi(os.Getenv("ZXC_SPL_ITERS")); err == nil && v > 0 {
		iters = v
	}
	r := rand.New(rand.NewPCG(31, uint64(iters)))
	for iter := range iters {
		blockSize := []int{4096, 65536, 1 << 19}[iter%3]
		w := 1 + iter%2
		p, want := makeSPL(r, blockSize, w)
		out := make([]byte, blockSize+wildPad)
		n, err := decodeSPL(out, 0, p, &scratch{}, nil)
		if err != nil || !bytes.Equal(out[:n], want) {
			t.Fatalf("iter %d: valid block: %v, %d bytes, want %d", iter, err, n, len(want))
		}
		compareSPL(t, p, blockSize)
		for range 10 {
			q := bytes.Clone(p)
			for range 1 + r.IntN(4) {
				q[r.IntN(len(q))] = byte(r.Uint32())
			}
			compareSPL(t, q, blockSize)
		}
	}
}

// TestSPLCorpus holds decodeSPL to the reference on every SPL block of the
// archive named by ZXC_BENCH_FILE, if set (levels 3 to 7).
func TestSPLCorpus(t *testing.T) {
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
		if typ == blockSPL {
			compareSPL(t, p, hdr.blockSize)
			n++
		}
	}
	t.Logf("%d SPL blocks", n)
}

// FuzzSPL holds decodeSPL to the reference on arbitrary payloads, seeded
// with random valid blocks of both offset widths.
func FuzzSPL(f *testing.F) {
	r := rand.New(rand.NewPCG(33, 34))
	for i := range 8 {
		p, _ := makeSPL(r, 4096, 1+i%2)
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p []byte) {
		compareSPL(t, p, 4096)
	})
}

// TestSPLVarintBounds builds SPL blocks of short sequences with an empty
// extras section, and sets the length escape on one of their last tokens:
// the varint it announces would run past the extras, which the decoder
// must report, not read. The payload ends with its offsets, the literal
// slack being made of the tokens and offsets themselves.
func TestSPLVarintBounds(t *testing.T) {
	r := rand.New(rand.NewPCG(35, 36))
	for iter := range 400 {
		w := 1 + iter%2
		nTok := 40 + r.IntN(200)
		var lits, toks, offs []byte
		n := 0
		for range nTok {
			ll, mb := r.IntN(4), r.IntN(6)
			for range ll {
				lits = append(lits, byte('a'+r.IntN(4)))
			}
			n += ll
			if n == 0 { // the first match needs a byte behind it
				lits = append(lits, 'a')
				ll, n = 1, 1
			}
			off := 1 + r.IntN(min(n, 200))
			toks = append(toks, byte(ll<<4|mb))
			if w == 1 {
				offs = append(offs, byte(off-1))
			} else {
				offs = binary.LittleEndian.AppendUint16(offs, uint16(off-1))
			}
			n += mb + minMatch
		}
		p := binary.LittleEndian.AppendUint32(nil, uint32(nTok))
		p = binary.LittleEndian.AppendUint32(p, uint32(len(lits)))
		p = append(p, encRAW, encRAW, 0, byte(2-w))
		p = append(p, lits...)
		p = append(p, toks...)
		p = append(p, offs...)
		p = p[:len(p):len(p)]
		compareSPL(t, p, 1<<16)
		tok := lzHeaderSize + len(lits) + nTok - 1 - r.IntN(4)
		if r.IntN(2) == 0 {
			p[tok] |= splTokenMask << 4
		} else {
			p[tok] |= splTokenMask
		}
		compareSPL(t, p, 1<<16)
	}
}
