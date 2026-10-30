package zxc

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeFrame builds a random valid frame of nb blocks of 4 KiB, PAK and RAW
// mixed, the last one shorter, with or without checksums. It returns the
// frame and the bytes it decodes to.
func makeFrame(r *rand.Rand, nb int, checksums bool) ([]byte, []byte) {
	const code, bs = 12, 1 << 12
	hdr := make([]byte, fileHeaderSize)
	binary.LittleEndian.PutUint32(hdr, magicWord)
	hdr[4] = formatVersion
	hdr[5] = code
	if checksums {
		hdr[6] = flagHasChecksum
	}
	binary.LittleEndian.PutUint16(hdr[14:], hash16(hdr))
	frame := hdr
	var want []byte
	var digest uint64
	for i := range nb {
		last := i == nb-1
		var payload, data []byte
		typ := byte(blockPAK)
		if r.IntN(5) == 0 {
			typ = blockRAW
			n := bs
			if last {
				n = 1 + r.IntN(bs)
			}
			data = make([]byte, n)
			for k := range data {
				data[k] = byte(r.Uint32())
			}
			payload = data
		} else {
			payload, data = makePAK(r, bs, !last)
		}
		h := makeBlockHeader(typ, uint32(len(payload)))
		frame = append(frame, h[:]...)
		frame = append(frame, payload...)
		if checksums {
			c := blockChecksum(data, uint64(i))
			frame = binary.LittleEndian.AppendUint32(frame, c)
			digest = digestCombine(digest, c)
		}
		want = append(want, data...)
	}
	eof := makeBlockHeader(blockEOF, 0)
	frame = append(frame, eof[:]...)
	l := makeFooterLayout(uint64(len(frame)), uint64(len(want)), checksums)
	foot := make([]byte, l.len)
	l.encode(foot, uint64(len(want)), digest)
	return append(frame, foot...), want
}

// compareConcurrency decodes src sequentially and with several goroutines:
// both must give the same output, or the same error.
func compareConcurrency(t *testing.T, src []byte, opts ...Option) {
	t.Helper()
	opts = opts[:len(opts):len(opts)] // the appends below never share it
	seq, errSeq := Decompress(src, append(opts, WithParallel(1))...)
	for _, c := range []int{2, 3, 8} {
		par, errPar := Decompress(src, append(opts, WithParallel(c))...)
		if (errSeq == nil) != (errPar == nil) || errSeq != nil && errSeq.Error() != errPar.Error() {
			t.Fatalf("concurrency %d: error %v, sequential %v", c, errPar, errSeq)
		}
		if !bytes.Equal(seq, par) {
			t.Fatalf("concurrency %d: output differs from the sequential decode", c)
		}
	}
}

// parallelTaken reports whether the parallel path decodes the single-frame
// archive src, instead of handing it to the sequential one.
func parallelTaken(t *testing.T, src []byte, opts ...Option) bool {
	t.Helper()
	dec := newDecoder(newConfig(opts))
	dec.workers = 4
	hdr, err := parseFileHeader(src)
	if err != nil {
		return false
	}
	_, _, ok := dec.decodeFrameParallel(nil, src, &hdr)
	return ok
}

// TestParallelRandomFrames checks the parallel decoder on random frames and
// on the same frames corrupted, alone and concatenated.
func TestParallelRandomFrames(t *testing.T) {
	r := rand.New(rand.NewPCG(21, 22))
	for iter := range 150 {
		nb := minParBlocks + r.IntN(30)
		frame, want := makeFrame(r, nb, iter%2 == 0)
		out, err := Decompress(frame)
		if err != nil || !bytes.Equal(out, want) {
			t.Fatalf("iter %d: valid frame: %v", iter, err)
		}
		if !parallelTaken(t, frame) {
			t.Fatalf("iter %d: the parallel path did not take a valid frame", iter)
		}
		compareConcurrency(t, frame)
		compareConcurrency(t, frame, WithChecksums(false))
		two := append(bytes.Clone(frame), frame...)
		compareConcurrency(t, two)
		for range 8 {
			q := bytes.Clone(frame)
			for range 1 + r.IntN(3) {
				q[r.IntN(len(q))] = byte(r.Uint32())
			}
			compareConcurrency(t, q)
			compareConcurrency(t, q[:r.IntN(len(q))])
		}
	}
}

// TestParallelConformance runs the conformance vectors with several
// goroutines: same outputs and errors as the sequential decoder.
func TestParallelConformance(t *testing.T) {
	dir := conformanceDir(t)
	files, _ := filepath.Glob(filepath.Join(dir, "*", "*.zxc"))
	for _, name := range files {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var opts []Option
		if strings.Contains(name, string(filepath.Separator)+"valid"+string(filepath.Separator)) {
			opts = dictFor(t, dir, src)
		}
		compareConcurrency(t, src, opts...)
	}
}

// TestParallelCorpus checks the archive named by ZXC_BENCH_FILE, if set:
// the parallel path takes it, with the sequential output.
func TestParallelCorpus(t *testing.T) {
	name := os.Getenv("ZXC_BENCH_FILE")
	if name == "" {
		t.Skip("ZXC_BENCH_FILE not set")
	}
	src, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if !parallelTaken(t, src) {
		t.Fatal("the parallel path did not take the archive")
	}
	compareConcurrency(t, src)
}

// FuzzParallel compares the parallel and sequential decoders on arbitrary
// archives, seeded with random multi-block frames.
func FuzzParallel(f *testing.F) {
	r := rand.New(rand.NewPCG(23, 24))
	for i := range 6 {
		frame, _ := makeFrame(r, minParBlocks+r.IntN(8), i%2 == 0)
		f.Add(frame)
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		compareConcurrency(t, src)
	})
}
