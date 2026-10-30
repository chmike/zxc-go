package zxc

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadVarint(t *testing.T) {
	for _, c := range []struct {
		in   []byte
		want uint32
	}{
		{[]byte{0x00}, 0},
		{[]byte{0x7F}, 127},
		{[]byte{0xAC, 0x04}, 300},          // FORMAT.md § 6
		{[]byte{0xC3, 0x35, 0x0C}, 100003}, // FORMAT.md § 6
		{[]byte{0xBF, 0xFF}, 1<<14 - 1},
		{[]byte{0xDF, 0xFF, 0xFF}, 1<<21 - 1},
	} {
		v, n, err := readVarint(c.in, 0)
		if err != nil || v != c.want || n != len(c.in) {
			t.Errorf("% x: got (%d, %d, %v), want (%d, %d, nil)", c.in, v, n, err, c.want, len(c.in))
		}
	}
	for _, in := range [][]byte{
		{},                       // nothing to read
		{0x80},                   // 2-byte form cut short
		{0xC0, 0x00},             // 3-byte form cut short
		{0xE0, 0x00, 0x00, 0x00}, // 4-byte form: out of spec
		{0xFF},
	} {
		if _, _, err := readVarint(in, 0); !errors.Is(err, ErrCorrupt) {
			t.Errorf("% x: err = %v, want ErrCorrupt", in, err)
		}
	}
}

func TestExpandRLE(t *testing.T) {
	// "ab" as a literal run, then 'x' repeated 6 times, then "c".
	sec := []byte{0x01, 'a', 'b', 0x82, 'x', 0x00, 'c'}
	got, err := expandRLE(nil, sec, 9)
	if err != nil || string(got) != "abxxxxxxc" {
		t.Fatalf("got (%q, %v), want (\"abxxxxxxc\", nil)", got, err)
	}
	for name, n := range map[string]int{"too few bytes": 10, "too many bytes": 8} {
		if _, err := expandRLE(nil, sec, n); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: err = %v, want ErrCorrupt", name, err)
		}
	}
	// Bytes left over once n is reached.
	if _, err := expandRLE(nil, append(sec, 0x00, 'z'), 9); !errors.Is(err, ErrCorrupt) {
		t.Errorf("leftover section bytes: err = %v, want ErrCorrupt", err)
	}
}

func TestCopyMatch(t *testing.T) {
	for _, c := range []struct {
		prefix  string
		off, ml int
		want    string
	}{
		{"abcdef", 6, 6, "abcdefabcdef"},      // no overlap
		{"abcdef", 3, 2, "abcdefde"},          // inside, no overlap
		{"a", 1, 7, "aaaaaaaa"},               // run of offset 1
		{"xyz", 3, 8, "xyzxyzxyzxy"},          // period 3, overlapping
		{"0123", 2, 9, "0123232323232"},       // period 2 from the middle
		{"hello", 5, 12, "hellohellohellohe"}, // two and a half periods
	} {
		out := make([]byte, len(c.prefix)+c.ml)
		copy(out, c.prefix)
		copyMatch(out, len(c.prefix), c.off, c.ml)
		if string(out) != c.want {
			t.Errorf("copyMatch(%q, off=%d, ml=%d) = %q, want %q", c.prefix, c.off, c.ml, out, c.want)
		}
	}
}

// TestCorruptionNeverPanics flips every byte of each valid conformance
// vector, one at a time, through a few values. The decoder must either
// succeed or return an error: a panic means a missing bounds check.
func TestCorruptionNeverPanics(t *testing.T) {
	dir := conformanceDir(t)
	files, _ := os.ReadDir(dir + "/valid")
	for _, f := range files {
		name := f.Name()
		if !strings.HasSuffix(name, ".zxc") {
			continue
		}
		src, err := os.ReadFile(dir + "/valid/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if len(src) > 20000 {
			continue // keep the test fast
		}
		buf := make([]byte, len(src))
		for i := range src {
			for _, x := range []byte{0x01, 0x80, 0xFF} {
				copy(buf, src)
				buf[i] ^= x
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("%s: byte %d ^= %#02x: panic: %v", name, i, x, r)
						}
					}()
					_, _ = Decompress(buf, WithChecksums(false))
				}()
			}
		}
	}
}

// BenchmarkDecompress measures throughput on the archive named by
// ZXC_BENCH_FILE, in MB/s of decompressed output.
func BenchmarkDecompress(b *testing.B) {
	path := os.Getenv("ZXC_BENCH_FILE")
	if path == "" {
		b.Skip("set ZXC_BENCH_FILE to a .zxc archive")
	}
	src, err := os.ReadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	out, err := Decompress(src)
	if err != nil {
		b.Fatal(err)
	}
	if unsafeFastPath {
		b.Log("fast paths: unsafe and assembly (default build)")
	}
	b.SetBytes(int64(len(out)))
	b.ResetTimer()
	for range b.N {
		if out, err = AppendDecompress(out[:0], src); err != nil {
			b.Fatal(err)
		}
	}
}

// FuzzDecompress feeds arbitrary input to the decoder, seeded with the
// conformance vectors. It must never panic; in the default build it also
// exercises the unchecked fast paths and the assembly. Run with:
//
//	go test -fuzz FuzzDecompress -fuzztime 60s
//	go test -tags purego -fuzz FuzzDecompress -fuzztime 60s
func FuzzDecompress(f *testing.F) {
	for _, sub := range []string{"valid", "invalid"} {
		dir := filepath.Join("testdata", "v9", sub)
		files, _ := filepath.Glob(filepath.Join(dir, "*.zxc"))
		for _, name := range files {
			if b, err := os.ReadFile(name); err == nil && len(b) <= 1<<16 {
				f.Add(b)
			}
		}
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		out, err := Decompress(src, WithChecksums(false))
		if err != nil && len(out) != 0 {
			t.Fatalf("error %v returned with %d bytes of output", err, len(out))
		}
	})
}

// FuzzBlock feeds arbitrary payloads straight to the SPL and PAK block
// decoders, past the header checksums that stop most FuzzDecompress inputs
// early. It is seeded with the real payloads of the conformance vectors;
// the first byte selects the block type and the block size.
func FuzzBlock(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("testdata", "v9", "valid", "*.zxc"))
	for _, name := range files {
		src, err := os.ReadFile(name)
		if err != nil || len(src) < fileHeaderSize {
			continue
		}
		hdr, err := parseFileHeader(src)
		if err != nil {
			continue
		}
		ck := 0
		if hdr.hasChecksum {
			ck = blockChecksumSize
		}
		for pos := fileHeaderSize; pos+blockHeaderSize <= len(src); {
			typ, size, err := parseBlockHeader(src[pos:])
			end := pos + blockHeaderSize + int(size)
			if err != nil || typ == blockEOF || end > len(src) {
				break
			}
			if typ == blockSPL || typ == blockPAK {
				sel := typ - 1 // 0 = SPL, 1 = PAK; 4 KB blocks
				if hdr.blockSize > 4096 {
					sel |= 2 // 64 KB blocks
				}
				f.Add(append([]byte{sel}, src[pos+blockHeaderSize:end]...))
			}
			pos = end + ck
		}
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) == 0 {
			return
		}
		blockSize := 4096
		if in[0]&2 != 0 {
			blockSize = 65536
		}
		out := make([]byte, blockSize+wildPad)
		if in[0]&1 == 0 {
			_, _ = decodeSPL(out, 0, in[1:], &scratch{}, nil)
		} else {
			_, _ = decodePAK(out, 0, in[1:])
		}
	})
}
