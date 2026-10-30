package zxc

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mustHex decodes a hexdump written with arbitrary spaces and newlines.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Worked example of FORMAT.md § 14.1: "Hello ZXC\n", one RAW block,
// checksums on.
const helloArchive = `
F5 2E B0 9C 09 13 80 00 00 00 00 00 00 00 6D 86
00 00 00 0A 00 00 00 A0 48 65 6C 6C 6F 20 5A 58
43 0A 90 BB A1 75 FF 00 00 00 00 00 00 83 BD 8A
9E 74 2A A2 9A B6 0A 39 00`

// Seekable variant of the same archive, FORMAT.md § 14.4.
const helloSeekable = `
F5 2E B0 9C 09 13 A0 00 00 00 00 00 00 00 0D 45
00 00 00 0A 00 00 00 A0 48 65 6C 6C 6F 20 5A 58
43 0A 90 BB A1 75 FF 00 00 00 00 00 00 83 FE 00
00 0C 00 00 00 6F 10 00 00 00 00 00 00 00 16 00
00 00 BD 8A 9E 74 2A A2 9A B6 0A 4D 00`

func TestHeaderHashes(t *testing.T) {
	a := mustHex(t, helloArchive)
	if got := hash16(a[0:16]); got != 0x866D {
		t.Errorf("file header hash16 = %#04x, want 0x866d", got)
	}
	if got := hash8(a[0x10:0x18]); got != 0xA0 {
		t.Errorf("RAW block header hash8 = %#02x, want 0xa0", got)
	}
	if got := hash8(a[0x26:0x2E]); got != 0x83 {
		t.Errorf("EOF block header hash8 = %#02x, want 0x83", got)
	}
	s := mustHex(t, helloSeekable)
	if got := hash16(s[0:16]); got != 0x450D {
		t.Errorf("seekable file header hash16 = %#04x, want 0x450d", got)
	}
	if got := makeBlockHeader(blockSEK, 12); !bytes.Equal(got[:], s[0x2E:0x36]) {
		t.Errorf("SEK header = % x, want % x", got, s[0x2E:0x36])
	}
}

func TestDigest(t *testing.T) {
	if got := digestCombine(0, 0x75A1BB90); got != 0xB69AA22A749E8ABD {
		t.Errorf("digest = %#016x, want 0xb69aa22a749e8abd", got)
	}
}

// Footer example of FORMAT.md § 8: 10 000 000 source bytes, 3 000 000-byte
// prefix, no checksums.
func TestFooterLayout(t *testing.T) {
	l := makeFooterLayout(3_000_000, 10_000_000, false)
	if l.compressedSize != 3_000_007 {
		t.Errorf("compressed frame size = %d, want 3000007", l.compressedSize)
	}
	got := make([]byte, l.len)
	l.encode(got, 10_000_000, 0)
	if want := mustHex(t, "80 96 98 C7 C6 2D 22"); !bytes.Equal(got, want) {
		t.Errorf("footer = % x, want % x", got, want)
	}
}

func TestWorkedExamples(t *testing.T) {
	want := []byte("Hello ZXC\n")
	for name, dump := range map[string]string{"plain": helloArchive, "seekable": helloSeekable} {
		t.Run(name, func(t *testing.T) {
			got, err := Decompress(mustHex(t, dump))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestConcatenatedFrames(t *testing.T) {
	a := mustHex(t, helloArchive)
	s := mustHex(t, helloSeekable)
	src := append(append([]byte{}, a...), s...)
	got, err := AppendDecompress([]byte("> "), src)
	if err != nil {
		t.Fatal(err)
	}
	if want := "> Hello ZXC\nHello ZXC\n"; string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// Trailing bytes that are not a magic word are corruption.
	if _, err := Decompress(append(src, 1, 2, 3)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("trailing garbage: err = %v, want ErrCorrupt", err)
	}
}

func TestDigestMismatch(t *testing.T) {
	a := mustHex(t, helloArchive)
	a[0x2E] ^= 1 // first digest byte
	if _, err := Decompress(a); !errors.Is(err, ErrBadChecksum) {
		t.Errorf("err = %v, want ErrBadChecksum", err)
	}
	if _, err := Decompress(a, WithChecksums(false)); err != nil {
		t.Errorf("SkipChecksums: err = %v, want nil", err)
	}
}

// conformanceDir locates the v9 conformance corpus of the reference
// repository (tests/conformance/v9, formerly conformance/v9). Copy it to
// testdata/v9, or point ZXC_CONFORMANCE_DIR at it.
func conformanceDir(t testing.TB) string {
	dir := os.Getenv("ZXC_CONFORMANCE_DIR")
	if dir == "" {
		dir = filepath.Join("testdata", "v9")
	}
	if _, err := os.Stat(filepath.Join(dir, "valid")); err != nil {
		t.Skipf("conformance corpus not found in %s", dir)
	}
	return dir
}

// dictFor returns the options an archive of the corpus needs: the .zxd of
// the valid directory whose id the archive header names, as the reference
// test does, or nil when it names none.
func dictFor(t testing.TB, dir string, src []byte) []Option {
	id, ok, err := ArchiveDictID(src)
	if err != nil || !ok {
		return nil
	}
	files, _ := filepath.Glob(filepath.Join(dir, "valid", "*.zxd"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		d, err := LoadDictionary(b)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if d.ID() == id {
			return []Option{WithDictionary(d)}
		}
	}
	t.Fatalf("no .zxd with id %#08x", id)
	return nil
}

func TestConformanceValid(t *testing.T) {
	dir := conformanceDir(t)
	files, _ := filepath.Glob(filepath.Join(dir, "valid", "*.zxc"))
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".zxc")
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(strings.TrimSuffix(f, ".zxc") + ".expected")
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decompress(src, dictFor(t, dir, src)...)
			if errors.Is(err, ErrNotImplemented) {
				t.Skip(err)
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("output differs from .expected (%d vs %d bytes)", len(got), len(want))
			}
		})
	}
}

// Invalid vectors a sequential decoder cannot reject; TestSeekable covers
// them.
var invalidPending = map[string]string{
	"sek_forged_entry": "only a seekable reader reads the table",
}

func TestConformanceInvalid(t *testing.T) {
	dir := conformanceDir(t)
	files, _ := filepath.Glob(filepath.Join(dir, "invalid", "*.zxc"))
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".zxc")
		t.Run(name, func(t *testing.T) {
			if why, ok := invalidPending[name]; ok {
				t.Skip(why)
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var opts []Option
			if name == "dict_id_mismatch" {
				// The binding check is only reached once a dictionary is
				// offered: the corpus README says to offer dict_http.zxd.
				b, err := os.ReadFile(filepath.Join(dir, "valid", "dict_http.zxd"))
				if err != nil {
					t.Fatal(err)
				}
				d, err := LoadDictionary(b)
				if err != nil {
					t.Fatal(err)
				}
				opts = []Option{WithDictionary(d)}
			}
			_, err = Decompress(src, opts...)
			if errors.Is(err, ErrNotImplemented) {
				// Rejected, but for the wrong reason: not conclusive yet.
				t.Skip(err)
			}
			if err == nil {
				t.Fatal("accepted a malformed archive")
			}
			if name == "dict_id_mismatch" && !errors.Is(err, ErrDictMismatch) {
				t.Fatalf("err = %v, want ErrDictMismatch", err)
			}
			t.Log(err)
		})
	}
}
