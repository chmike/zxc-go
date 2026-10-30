package zxc

import (
	"errors"
	"testing"
)

// FORMAT.md § 15: a dictionary of the 5 bytes "hello" with its shared
// Huffman table, 149 bytes.
const helloDict = `
C7 D1 B0 9C 02 00 05 00 34 07 FC 0C 00 00 C6 51
68 65 6C 6C 6F 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 20 00 02 00 02 20 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00`

func TestLoadDictionary(t *testing.T) {
	zxd := mustHex(t, helloDict)
	d, err := LoadDictionary(zxd)
	if err != nil {
		t.Fatal(err)
	}
	if d.ID() != 0x0CFC0734 || d.Len() != 5 || string(d.content) != "hello" {
		t.Fatalf("got id %#08x, %d bytes %q", d.ID(), d.Len(), d.content)
	}

	// Each corruption is caught, for the right reason.
	for _, c := range []struct {
		name string
		at   int
		want error
	}{
		{"magic", 0, ErrBadMagic},
		{"version", 4, ErrBadVersion},
		{"flags", 5, ErrBadHeader},
		{"reserved", 12, ErrBadHeader},
		{"header checksum", 14, ErrBadHeader},
		{"dict_id", 8, ErrBadHeader}, // the header checksum covers it first
		{"content", 16, ErrBadChecksum},
		{"table", 16 + 5 + 50, ErrBadChecksum},
	} {
		b := append([]byte(nil), zxd...)
		b[c.at] ^= 1
		if _, err := LoadDictionary(b); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := LoadDictionary(zxd[:len(zxd)-1]); !errors.Is(err, ErrTruncated) {
		t.Errorf("truncated: err = %v, want ErrTruncated", err)
	}
}

func TestRawDictionary(t *testing.T) {
	d, err := NewRawDictionary([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	// § 12.3: a raw dictionary's id is the folded rapidhash of its content.
	if d.ID() != blockChecksum([]byte("hello"), 0) {
		t.Fatalf("id %#08x", d.ID())
	}
	if _, err := NewRawDictionary(nil); err == nil {
		t.Error("accepted an empty dictionary")
	}
	if _, err := NewRawDictionary(make([]byte, 1<<16)); err == nil {
		t.Error("accepted a 64 KiB dictionary")
	}
}
