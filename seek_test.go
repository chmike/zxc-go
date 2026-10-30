package zxc

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkSeekable reads src through a Seekable, whole and in random ranges,
// and compares with want.
func checkSeekable(t *testing.T, src, want []byte, opts ...Option) {
	t.Helper()
	s, err := OpenSeekable(src, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if s.Size() != int64(len(want)) {
		t.Fatalf("Size = %d, want %d", s.Size(), len(want))
	}
	got := make([]byte, len(want))
	if n, err := s.ReadAt(got, 0); n != len(want) || err != nil {
		t.Fatalf("ReadAt(all) = %d, %v", n, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("whole read differs")
	}
	r := rand.New(rand.NewPCG(1, 2))
	for range 200 {
		off := r.IntN(len(want) + 1)
		n := r.IntN(len(want) - off + 1)
		buf := make([]byte, n)
		if m, err := s.ReadAt(buf, int64(off)); m != n || err != nil {
			t.Fatalf("ReadAt(%d bytes at %d) = %d, %v", n, off, m, err)
		}
		if !bytes.Equal(buf, want[off:off+n]) {
			t.Fatalf("ReadAt(%d bytes at %d) differs", n, off)
		}
	}
	// Past the end: io.EOF with what there is.
	buf := make([]byte, 10)
	off := int64(len(want)) - 3
	if off < 0 {
		off = 0
	}
	n, err := s.ReadAt(buf, off)
	if int64(n) != int64(len(want))-off || err != io.EOF {
		t.Fatalf("ReadAt past the end = %d, %v; want %d, io.EOF", n, err, int64(len(want))-off)
	}
}

func TestSeekableWorkedExample(t *testing.T) {
	s := mustHex(t, helloSeekable)
	checkSeekable(t, s, []byte("Hello ZXC\n"))
	// Concatenated seekable frames stay seekable (§ 2.1).
	two := append(append([]byte{}, s...), s...)
	checkSeekable(t, two, []byte("Hello ZXC\nHello ZXC\n"))
	// A frame without a seek table makes the archive not seekable.
	if _, err := OpenSeekable(mustHex(t, helloArchive)); err == nil {
		t.Fatal("opened an archive without a seek table")
	}
}

func TestSeekableConformance(t *testing.T) {
	dir := conformanceDir(t)
	files, _ := filepath.Glob(filepath.Join(dir, "valid", "*.zxc"))
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".zxc")
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		hdr, err := parseFileHeader(src)
		if err != nil || !hdr.hasSeek {
			continue
		}
		t.Run(name, func(t *testing.T) {
			want, err := os.ReadFile(strings.TrimSuffix(f, ".zxc") + ".expected")
			if err != nil {
				t.Fatal(err)
			}
			opts := dictFor(t, dir, src)
			if _, err := Decompress(src, opts...); errors.Is(err, ErrNotImplemented) {
				t.Skip(err)
			}
			checkSeekable(t, src, want, opts...)
		})
	}
}

// Every invalid vector with a seek table must be refused by a seekable
// reader too, at open or on reading the whole range; sek_forged_entry is
// the one only a seekable reader can catch.
func TestSeekableInvalid(t *testing.T) {
	dir := conformanceDir(t)
	files, _ := filepath.Glob(filepath.Join(dir, "invalid", "sek_*.zxc"))
	if len(files) == 0 {
		t.Skip("no sek_* vectors")
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".zxc")
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			s, err := OpenSeekable(src)
			if err != nil {
				t.Log("open:", err)
				return
			}
			buf := make([]byte, s.Size())
			if _, err := s.ReadAt(buf, 0); err != nil {
				t.Log("read:", err)
				return
			}
			t.Fatal("accepted a malformed archive")
		})
	}
}

// FuzzSeekable must never panic, whatever the archive and the range.
func FuzzSeekable(f *testing.F) {
	for _, sub := range []string{"valid", "invalid"} {
		files, _ := filepath.Glob(filepath.Join("testdata", "v9", sub, "*.zxc"))
		for _, name := range files {
			if b, err := os.ReadFile(name); err == nil && len(b) <= 1<<16 {
				f.Add(b, int64(0), 1<<16)
			}
		}
	}
	f.Fuzz(func(t *testing.T, src []byte, off int64, n int) {
		s, err := OpenSeekable(src, WithChecksums(false))
		if err != nil {
			return
		}
		if n < 0 || n > 1<<20 {
			n = 1 << 20
		}
		_, _ = s.ReadAt(make([]byte, n), off)
	})
}
