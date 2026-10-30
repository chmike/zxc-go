package zxc

import (
	"encoding/binary"
	"os"
	"testing"
)

// Bench of the Huffman decoder alone, on the very sections of an archive,
// against the reference decoder's: TestDumpHufSections writes the Huffman
// sections (literals and tokens) of the archive ZXC_BENCH_FILE to the file
// ZXC_HUF_DUMP, which BenchmarkHufSections and the C program hufbench.c
// both decode. The format: per section, a byte (0 literals, 1 tokens), the
// symbol count and the section size as 32-bit little-endian words, then
// the section (its 128-byte table, then the runs).

type hufSection struct {
	kind byte
	n    int
	sec  []byte
}

func TestDumpHufSections(t *testing.T) {
	name, dump := os.Getenv("ZXC_BENCH_FILE"), os.Getenv("ZXC_HUF_DUMP")
	if name == "" || dump == "" {
		t.Skip("ZXC_BENCH_FILE and ZXC_HUF_DUMP not set")
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
	var out []byte
	nl, nt := 0, 0
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
		h, err := parseLZHeader(p)
		if err != nil {
			t.Fatal(err)
		}
		q := lzHeaderSize
		litComp := uint32(h.nLit)
		if h.encLit != encRAW {
			litComp = binary.LittleEndian.Uint32(p[q:])
			q += 4
		}
		tokComp := uint32(h.nSeq)
		if h.encTok == encHuffman {
			tokComp = binary.LittleEndian.Uint32(p[q:])
			q += 4
		}
		body := p[q:]
		add := func(kind byte, n uint32, sec []byte) {
			out = append(out, kind)
			out = binary.LittleEndian.AppendUint32(out, n)
			out = binary.LittleEndian.AppendUint32(out, uint32(len(sec)))
			out = append(out, sec...)
		}
		if h.encLit == encHuffman {
			add(0, h.nLit, body[:litComp])
			nl++
		}
		if h.encTok == encHuffman {
			add(1, h.nSeq, body[litComp:litComp+tokComp])
			nt++
		}
	}
	if err := os.WriteFile(dump, out, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d literal and %d token sections written to %s", nl, nt, dump)
}

func readHufSections(b *testing.B) []hufSection {
	data, err := os.ReadFile(os.Getenv("ZXC_HUF_DUMP"))
	if err != nil {
		b.Skip("ZXC_HUF_DUMP not set or unreadable")
	}
	var secs []hufSection
	for len(data) > 0 {
		n := binary.LittleEndian.Uint32(data[1:])
		size := binary.LittleEndian.Uint32(data[5:])
		secs = append(secs, hufSection{data[0], int(n), data[9 : 9+size]})
		data = data[9+size:]
	}
	return secs
}

// BenchmarkHufSections decodes the dumped sections, tree builds included,
// as the C program does; the sub-benchmarks take the literal sections, the
// token sections, or all.
func BenchmarkHufSections(b *testing.B) {
	secs := readHufSections(b)
	for _, kind := range []struct {
		name string
		k    int
	}{{"lits", 0}, {"toks", 1}, {"all", -1}} {
		b.Run(kind.name, func(b *testing.B) {
			var it inlineTree
			var hd hufDecoder
			out := make([]byte, 1<<21+wildPad)
			total := 0
			for _, s := range secs {
				if kind.k < 0 || int(s.kind) == kind.k {
					total += s.n
				}
			}
			b.SetBytes(int64(total))
			for range b.N {
				for _, s := range secs {
					if kind.k >= 0 && int(s.kind) != kind.k {
						continue
					}
					tree, body, err := it.get(s.sec)
					if err != nil {
						b.Fatal(err)
					}
					if err := hd.decode(tree, body, s.n, out); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
