package zxc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

// compressLevels are the levels the encoder implements so far.
var compressLevels = []int{1, 2, 3, 4, 5, 6, 7}

// testInputs returns inputs that exercise the encoder's edge cases: empty
// and tiny inputs, around the margins and the distance floor, runs,
// incompressible bytes, repeats at every distance and lengths around the
// 255 escape.
func testInputs() map[string][]byte {
	r := rand.New(rand.NewPCG(51, 52))
	rnd := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		return b
	}
	in := map[string][]byte{
		"empty":  {},
		"one":    {'a'},
		"four":   []byte("abcd"),
		"nine":   []byte("abcdabcda"),
		"zeros":  make([]byte, 300000),
		"random": rnd(200000),
	}
	for _, n := range []int{31, 32, 33, 35, 36, 40, 63, 64, 65, 4095, 4096, 4097} {
		b := make([]byte, n)
		for i := range b {
			b[i] = "abcdefgh"[i%8]
		}
		in["period8-"+strconv.Itoa(n)] = b
	}
	// Mixed: runs, copies from a random distance, random stretches.
	var mix []byte
	for len(mix) < 1<<20 {
		switch k := r.IntN(10); {
		case k < 3:
			mix = append(mix, bytes.Repeat([]byte{byte(r.Uint32())}, 1+r.IntN(700))...)
		case k < 7 && len(mix) > 16:
			s := r.IntN(len(mix))
			e := min(len(mix), s+1+r.IntN(700))
			mix = append(mix, mix[s:e]...)
		default:
			mix = append(mix, rnd(1+r.IntN(300))...)
		}
	}
	in["mix"] = mix
	// Text-like: words from a small vocabulary, with long literal runs and
	// matches at every distance up to the window.
	words := []string{"the ", "zxc ", "block ", "match ", "offset ", "literal ", "\n", "sequence "}
	var text []byte
	for len(text) < 600000 {
		text = append(text, words[r.IntN(len(words))]...)
		if r.IntN(50) == 0 {
			text = append(text, rnd(300+r.IntN(400))...)
		}
	}
	in["text"] = text
	// Blocks of 4 KiB with 100 to 300 fresh bytes each, the rest repeats:
	// literal and token sections around the Huffman thresholds.
	var few []byte
	for k := range 200 {
		blk := rnd(100 + k)
		for len(blk) < 4096 {
			s := r.IntN(len(blk))
			blk = append(blk, blk[s:min(len(blk), s+8+r.IntN(40))]...)
		}
		few = append(few, blk[:4096]...)
	}
	in["fewlits"] = few
	return in
}

// compressOptions are the option sets the tests run every level with.
var compressOptions = []struct {
	name string
	opts []Option
	cli  []string // the same options for the zxc CLI
}{
	{"default", nil, nil},
	{"nochecksum", []Option{WithChecksums(false)}, []string{"-N"}},
	{"seekable", []Option{WithSeekable(true)}, []string{"-S"}},
	{"4K", []Option{WithBlockSize(4 << 10)}, []string{"-B", "4K"}},
	{"64K-seekable-nochecksum", []Option{WithBlockSize(64 << 10), WithSeekable(true), WithChecksums(false)}, []string{"-B", "64K", "-S", "-N"}},
	{"2M", []Option{WithBlockSize(2 << 20)}, []string{"-B", "2M"}},
}

// TestCompressRoundTrip decompresses what Compress writes, at every level
// and with every option set, seekable archives also through Seekable.
func TestCompressRoundTrip(t *testing.T) {
	for name, src := range testInputs() {
		for _, l := range compressLevels {
			for _, o := range compressOptions {
				opts := append([]Option{WithLevel(l)}, o.opts...)
				z, err := Compress(src, opts...)
				if err != nil {
					t.Fatalf("%s level %d %s: %v", name, l, o.name, err)
				}
				out, err := Decompress(z)
				if err != nil || !bytes.Equal(out, src) {
					t.Fatalf("%s level %d %s: round trip failed: %v", name, l, o.name, err)
				}
				if o.name == "seekable" && len(src) > 0 {
					s, err := OpenSeekable(z)
					if err != nil {
						t.Fatalf("%s level %d: OpenSeekable: %v", name, l, err)
					}
					p := make([]byte, len(src)/2+1)
					n, err := s.ReadAt(p, int64(len(src)-len(p)))
					if err != nil || !bytes.Equal(p[:n], src[len(src)-len(p):]) {
						t.Fatalf("%s level %d: ReadAt: %v", name, l, err)
					}
				}
			}
		}
	}
}

// TestCompressAppend checks that AppendCompress keeps dst and appends the
// same frame as Compress.
func TestCompressAppend(t *testing.T) {
	src := testInputs()["text"]
	z, err := Compress(src, WithLevel(1))
	if err != nil {
		t.Fatal(err)
	}
	a, err := AppendCompress([]byte("> "), src, WithLevel(1))
	if err != nil || string(a[:2]) != "> " || !bytes.Equal(a[2:], z) {
		t.Fatalf("AppendCompress differs from Compress: %v", err)
	}
}

// TestCompressOptionErrors checks the options Compress refuses.
func TestCompressOptionErrors(t *testing.T) {
	for _, bs := range []int{-1, 0, 1000, 2048, 3 << 12, 4 << 20} {
		if _, err := Compress([]byte("x"), WithBlockSize(bs)); !errors.Is(err, ErrBadBlockSize) {
			t.Errorf("block size %d: got %v, want ErrBadBlockSize", bs, err)
		}
	}
}

// refCLI is the zxc CLI of the reference version the encoder follows,
// looked for in zxcbench/bin when ZXC_CLI does not name one.
var refCLI = filepath.Join("zxcbench", "bin", "zxc-v0.15.0-"+runtime.GOARCH)

// TestCompressMatchesC compresses the test inputs with the zxc CLI of
// v0.15.0 of the reference library, and requires the very same bytes from
// Compress, at every level and with every option set. The CLI is the one
// ZXC_CLI names, else refCLI. The file named by ZXC_BENCH_FILE, if set, is
// added to the inputs.
func TestCompressMatchesC(t *testing.T) {
	cli := os.Getenv("ZXC_CLI")
	if cli == "" {
		cli = refCLI
		if _, err := os.Stat(cli); err != nil {
			t.Skipf("no %s: set ZXC_CLI to a zxc v0.15.0 binary", cli)
		}
	}
	inputs := testInputs()
	if name := os.Getenv("ZXC_BENCH_FILE"); name != "" {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		inputs[filepath.Base(name)] = b
	}
	dir := t.TempDir()
	for name, src := range inputs {
		in := filepath.Join(dir, name)
		if err := os.WriteFile(in, src, 0o644); err != nil {
			t.Fatal(err)
		}
		for _, l := range compressLevels {
			for _, o := range compressOptions {
				out := filepath.Join(dir, "c.zxc")
				args := append([]string{"-" + strconv.Itoa(l)}, o.cli...)
				args = append(args, "-k", "-f", "-q", "-o", out, in)
				if b, err := exec.Command(cli, args...).CombinedOutput(); err != nil {
					t.Fatalf("%s %v: %v\n%s", cli, args, err, b)
				}
				want, err := os.ReadFile(out)
				if err != nil {
					t.Fatal(err)
				}
				got, err := Compress(src, append([]Option{WithLevel(l)}, o.opts...)...)
				if err != nil {
					t.Fatalf("%s level %d %s: %v", name, l, o.name, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("%s level %d %s: %s", name, l, o.name, firstDifference(got, want))
				}
			}
		}
	}
}

// firstDifference describes where two frames first differ: the block,
// found by walking the block headers of want, and the byte offset.
func firstDifference(got, want []byte) string {
	i := 0
	for i < len(got) && i < len(want) && got[i] == want[i] {
		i++
	}
	where := "file header or footer"
	if hdr, err := parseFileHeader(want); err == nil {
		pos, k := fileHeaderSize, 0
		for pos+blockHeaderSize <= len(want) {
			typ, size, err := parseBlockHeader(want[pos:])
			if err != nil || typ == blockEOF {
				break
			}
			end := pos + blockHeaderSize + int(size)
			if hdr.hasChecksum {
				end += blockChecksumSize
			}
			if i < end {
				where = fmt.Sprintf("block %d (type %d), %d bytes into it", k, typ, i-pos)
				break
			}
			pos, k = end, k+1
		}
	}
	return fmt.Sprintf("frames differ at byte %d of %d (want %d bytes): %s", i, len(got), len(want), where)
}

// FuzzCompress compresses arbitrary input at a level and block size taken
// from the fuzzer, and requires the decoder to give it back.
func FuzzCompress(f *testing.F) {
	f.Add([]byte("Hello ZXC\n"), uint8(1), uint8(0))
	f.Add(bytes.Repeat([]byte("abcdefgh"), 100), uint8(2), uint8(1))
	f.Fuzz(func(t *testing.T, src []byte, level, bs uint8) {
		l := compressLevels[int(level)%len(compressLevels)]
		z, err := Compress(src, WithLevel(l), WithBlockSize(4<<10<<(bs%3)))
		if err != nil {
			t.Fatal(err)
		}
		out, err := Decompress(z)
		if err != nil || !bytes.Equal(out, src) {
			t.Fatalf("level %d: round trip failed: %v", l, err)
		}
	})
}

// TestCompressEpochWrap encodes blocks across the epoch wrap of the match
// finder's tables, which clears them, and requires the same blocks as a
// fresh encoder gives: entries of earlier blocks must never matter.
func TestCompressEpochWrap(t *testing.T) {
	src := testInputs()["text"]
	const bs = 4 << 10
	for _, l := range compressLevels {
		cfg := newConfig([]Option{WithLevel(l), WithBlockSize(bs)})
		fresh, wrapped := newEncoder(cfg), newEncoder(cfg)
		wrapped.m.epoch = wrapped.m.maxEpoch - 3
		for i := 0; (i+1)*bs <= len(src) && i < 8; i++ {
			blk := src[i*bs : (i+1)*bs]
			a := fresh.appendBlock(nil, blk, uint64(i))
			b := wrapped.appendBlock(nil, blk, uint64(i))
			if !bytes.Equal(a, b) {
				t.Fatalf("level %d block %d: differs across the epoch wrap", l, i)
			}
		}
	}
}

// lzSeq is a decoded sequence: literal length, match length, offset.
type lzSeq struct{ ll, ml, off int }

// splSequences decodes the sequences of a SPL block payload of a block of
// n bytes, and returns them with the block's literal count.
func splSequences(p []byte, n int) (int, []lzSeq, error) {
	var sc scratch
	b, err := prepareSPL(make([]byte, n+wildPad), 0, p, &sc, nil)
	if err != nil {
		return 0, nil, err
	}
	h, _ := parseLZHeader(p)
	seqs := make([]lzSeq, len(b.tokens))
	e := 0
	for i, t := range b.tokens {
		s := lzSeq{int(t >> 4), int(t&splTokenMask) + minMatch, 0}
		if b.offWidth == 1 {
			s.off = int(b.offs[i]) + 1
		} else {
			s.off = int(binary.LittleEndian.Uint16(b.offs[2*i:])) + 1
		}
		var v uint32
		if s.ll == splTokenMask {
			if v, e, err = readVarint(b.extras, e); err != nil {
				return 0, nil, err
			}
			s.ll += int(v)
		}
		if s.ml == splTokenMask+minMatch {
			if v, e, err = readVarint(b.extras, e); err != nil {
				return 0, nil, err
			}
			s.ml += int(v)
		}
		seqs[i] = s
	}
	return int(h.nLit), seqs, nil
}

// encoderSequences parses blk at the encoder's level and returns its
// sequences and literal count, before any literal or token coding.
func encoderSequences(e *encoder, blk []byte) (int, []lzSeq) {
	p := lzParamTable[e.level]
	e.m.newBlock()
	if e.level >= 6 {
		e.optimalParse(blk, 0, &p)
	} else {
		e.lazyParse(blk, 0, &p)
	}
	toks, offs, extras := e.splitMatches(e.toks, e.offs, e.extras, p.splitMax)
	var b bytes.Buffer
	b.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	binary.LittleEndian.PutUint32(b.Bytes()[0:], uint32(len(toks)))
	binary.LittleEndian.PutUint32(b.Bytes()[4:], uint32(len(e.lits)))
	b.Write(e.lits)
	b.Write(toks)
	for _, o := range offs {
		b.Write([]byte{byte(o), byte(o >> 8)})
	}
	b.Write(extras)
	b.Write(make([]byte, litSlack))
	nLit, seqs, err := splSequences(b.Bytes(), len(blk))
	if err != nil {
		panic(err)
	}
	return nLit, seqs
}

// TestOptimalParseMatchesC compares, block by block, the sequences of the
// level-6 and level-7 parser with those of the SPL blocks of the zxc CLI
// (see TestCompressMatchesC), whatever the coding of their literals and
// tokens.
func TestOptimalParseMatchesC(t *testing.T) {
	cli := os.Getenv("ZXC_CLI")
	if cli == "" {
		cli = refCLI
		if _, err := os.Stat(cli); err != nil {
			t.Skipf("no %s: set ZXC_CLI to a zxc v0.15.0 binary", cli)
		}
	}
	inputs := testInputs()
	if name := os.Getenv("ZXC_BENCH_FILE"); name != "" {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		inputs[filepath.Base(name)] = b
	}
	dir := t.TempDir()
	for name, src := range inputs {
		in := filepath.Join(dir, name)
		if err := os.WriteFile(in, src, 0o644); err != nil {
			t.Fatal(err)
		}
		for _, l := range []int{6, 7} {
			for _, bs := range []int{512 << 10, 64 << 10} {
				out := filepath.Join(dir, "c.zxc")
				args := []string{"-" + strconv.Itoa(l), "-N", "-B", strconv.Itoa(bs>>10) + "K", "-k", "-f", "-q", "-o", out, in}
				if b, err := exec.Command(cli, args...).CombinedOutput(); err != nil {
					t.Fatalf("%s %v: %v\n%s", cli, args, err, b)
				}
				z, err := os.ReadFile(out)
				if err != nil {
					t.Fatal(err)
				}
				e := newEncoder(newConfig([]Option{WithLevel(l), WithBlockSize(bs)}))
				pos, compared := fileHeaderSize, 0
				for k := 0; ; k++ {
					typ, size, err := parseBlockHeader(z[pos:])
					if err != nil {
						t.Fatal(err)
					}
					if typ == blockEOF {
						break
					}
					blk := src[k*bs : min((k+1)*bs, len(src))]
					payload := z[pos+blockHeaderSize : pos+blockHeaderSize+int(size)]
					pos += blockHeaderSize + int(size)
					gotLit, got := encoderSequences(e, blk)
					if typ != blockSPL {
						continue // RAW: the C sequences are not on the wire
					}
					wantLit, want, err := splSequences(payload, len(blk))
					if err != nil {
						t.Fatal(err)
					}
					if gotLit != wantLit || len(got) != len(want) {
						t.Fatalf("%s level %d block %d: %d literals and %d sequences, want %d and %d",
							name, l, k, gotLit, len(got), wantLit, len(want))
					}
					for i := range got {
						if got[i] != want[i] {
							t.Fatalf("%s level %d block %d: sequence %d is %v, want %v", name, l, k, i, got[i], want[i])
						}
					}
					compared++
				}
				if testing.Verbose() {
					t.Logf("%s level %d block size %d: %d SPL blocks compared", name, l, bs, compared)
				}
			}
		}
	}
}

// TestCompressParallel requires the same frame from 2, 3 and 8 goroutines
// as from a sequential run, with and without a dictionary.
func TestCompressParallel(t *testing.T) {
	src := testInputs()["text"]
	dict, err := NewRawDictionary(src[:20000])
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range compressLevels {
		for _, extra := range [][]Option{nil, {WithDictionary(dict)}, {WithSeekable(true), WithChecksums(false)}} {
			opts := append([]Option{WithLevel(l), WithBlockSize(16 << 10)}, extra...)
			seq, err := Compress(src, append(opts, WithParallel(1))...)
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range []int{2, 3, 8} {
				par, err := Compress(src, append(opts, WithParallel(w))...)
				if err != nil || !bytes.Equal(par, seq) {
					t.Fatalf("level %d, %d goroutines: differs from the sequential frame (%v)", l, w, err)
				}
			}
		}
	}
}

// TestCompressDictRoundTrip decompresses what Compress writes with a raw
// dictionary, and checks that the archive names it.
func TestCompressDictRoundTrip(t *testing.T) {
	in := testInputs()
	dict, err := NewRawDictionary(in["text"][:30000])
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range in {
		for _, l := range compressLevels {
			z, err := Compress(src, WithLevel(l), WithDictionary(dict), WithBlockSize(4<<10))
			if err != nil {
				t.Fatalf("%s level %d: %v", name, l, err)
			}
			if id, ok, err := ArchiveDictID(z); err != nil || !ok || id != dict.ID() {
				t.Fatalf("%s level %d: archive names dictionary %#x, %v, %v", name, l, id, ok, err)
			}
			out, err := Decompress(z, WithDictionary(dict))
			if err != nil || !bytes.Equal(out, src) {
				t.Fatalf("%s level %d: round trip failed: %v", name, l, err)
			}
		}
	}
}

// TestCompressDictMatchesC trains a dictionary with the zxc CLI (see
// TestCompressMatchesC) on samples of the text input, then requires the
// same frames as the CLI from Compress with it, at every level.
func TestCompressDictMatchesC(t *testing.T) {
	cli := os.Getenv("ZXC_CLI")
	if cli == "" {
		cli = refCLI
		if _, err := os.Stat(cli); err != nil {
			t.Skipf("no %s: set ZXC_CLI to a zxc v0.15.0 binary", cli)
		}
	}
	in := testInputs()
	text := in["text"]
	dir := t.TempDir()
	var samples []string
	for k := range 40 {
		p := filepath.Join(dir, "s"+strconv.Itoa(k))
		if err := os.WriteFile(p, text[k*4000:k*4000+3000], 0o644); err != nil {
			t.Fatal(err)
		}
		samples = append(samples, p)
	}
	zxd := filepath.Join(dir, "d.zxd")
	args := append([]string{"--train", "-q", "-o", zxd}, samples...)
	if b, err := exec.Command(cli, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s --train: %v\n%s", cli, err, b)
	}
	b, err := os.ReadFile(zxd)
	if err != nil {
		t.Fatal(err)
	}
	dict, err := LoadDictionary(b)
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string][]byte{"text": text[200000:], "mix": in["mix"][:200000], "nine": in["nine"], "period8-4097": in["period8-4097"]}
	for name, src := range inputs {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, src, 0o644); err != nil {
			t.Fatal(err)
		}
		for _, l := range compressLevels {
			for _, o := range compressOptions[:4] {
				out := filepath.Join(dir, "c.zxc")
				args := append([]string{"-" + strconv.Itoa(l), "-D", zxd}, o.cli...)
				args = append(args, "-k", "-f", "-q", "-o", out, f)
				if b, err := exec.Command(cli, args...).CombinedOutput(); err != nil {
					t.Fatalf("%s %v: %v\n%s", cli, args, err, b)
				}
				want, err := os.ReadFile(out)
				if err != nil {
					t.Fatal(err)
				}
				got, err := Compress(src, append([]Option{WithLevel(l), WithDictionary(dict)}, o.opts...)...)
				if err != nil {
					t.Fatalf("%s level %d %s: %v", name, l, o.name, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("%s level %d %s: %s", name, l, o.name, firstDifference(got, want))
				}
			}
		}
	}
}
