package zxc

import (
	"encoding/binary"
	"fmt"
)

// Dictionary file constants (§ 12.4).
const (
	dictMagic      = 0x9CB0D1C7
	dictVersion    = 2
	dictHeaderSize = 16
	dictMaxSize    = 1<<16 - 1 // content size, bounded by the 64 KiB window
	hufTableSize   = 128       // 256 four-bit code lengths
)

// A Dictionary is the pre-trained content an archive was compressed with
// (§ 12). It is needed, unchanged, to decompress that archive: pass it in
// WithDictionary. A Dictionary is read-only once built and may be shared by
// concurrent decoders.
type Dictionary struct {
	content []byte
	table   []byte // shared literal Huffman table (128 bytes), nil for a raw dictionary
	id      uint32

	// The decoding tree of table, built once; treeErr when the table is
	// not a valid code. Like the reference decoder, an invalid table is
	// only reported when an archive is decoded with the dictionary.
	tree    *hufTree
	treeErr error
}

// LoadDictionary parses a .zxd dictionary file (§ 12.4), as written by
// zxc --train. It checks the header, its checksum and the dict_id, and
// copies the content and the shared Huffman table out of zxd.
func LoadDictionary(zxd []byte) (*Dictionary, error) {
	if len(zxd) < dictHeaderSize {
		return nil, ErrTruncated
	}
	if binary.LittleEndian.Uint32(zxd) != dictMagic {
		return nil, ErrBadMagic
	}
	if zxd[4] != dictVersion {
		return nil, ErrBadVersion
	}
	n := int(binary.LittleEndian.Uint16(zxd[6:]))
	if n == 0 {
		return nil, corruptf("empty dictionary")
	}
	if len(zxd) < dictHeaderSize+n+hufTableSize {
		return nil, ErrTruncated
	}
	// Same 16-bit header checksum as the archive header (§ 7.1). Flags hold
	// the checksum algorithm, only 0 is defined; Reserved must be 0.
	if binary.LittleEndian.Uint16(zxd[14:]) != hash16(zxd) ||
		zxd[5] != checksumAlgoRapidHash || binary.LittleEndian.Uint16(zxd[12:]) != 0 {
		return nil, ErrBadHeader
	}
	content := zxd[dictHeaderSize : dictHeaderSize+n]
	table := zxd[dictHeaderSize+n : dictHeaderSize+n+hufTableSize]
	d := &Dictionary{
		content: append([]byte(nil), content...),
		table:   append([]byte(nil), table...),
		id:      dictID(content, table),
	}
	if stored := binary.LittleEndian.Uint32(zxd[8:]); stored != d.id {
		return nil, fmt.Errorf("%w: dictionary id %#08x, computed %#08x", ErrBadChecksum, stored, d.id)
	}
	lens := unpackLengths(d.table)
	if d.tree, d.treeErr = buildHufTree(&lens); d.treeErr != nil {
		d.treeErr = fmt.Errorf("shared Huffman table of dictionary %#08x: %w", d.id, d.treeErr)
	}
	return d, nil
}

// NewRawDictionary makes a dictionary from raw content alone, without a
// shared Huffman table: the form the library API of the reference
// implementation accepts (§ 12.3). Its id covers the content only, so it
// matches only archives compressed with that same raw content. content is
// copied; it must hold 1 to 65535 bytes.
func NewRawDictionary(content []byte) (*Dictionary, error) {
	if len(content) == 0 || len(content) > dictMaxSize {
		return nil, fmt.Errorf("zxc: dictionary size %d out of range [1, %d]", len(content), dictMaxSize)
	}
	return &Dictionary{
		content: append([]byte(nil), content...),
		id:      dictID(content, nil),
	}, nil
}

// ID returns the dictionary id, the value an archive header stores to name
// the dictionary it needs.
func (d *Dictionary) ID() uint32 { return d.id }

// Len returns the size of the dictionary content.
func (d *Dictionary) Len() int { return len(d.content) }

// dictID computes the dictionary id of § 12.3: fold32(rapidhash(content)),
// and when a shared table is attached, fold32(rapidhash(table)) seeded with
// that first value.
func dictID(content, table []byte) uint32 {
	id := blockChecksum(content, 0)
	if table != nil {
		id = blockChecksum(table, uint64(id))
	}
	return id
}

// ArchiveDictID returns the id of the dictionary the first frame of an
// archive needs, and false when it needs none. It only reads the 16-byte
// file header.
func ArchiveDictID(src []byte) (uint32, bool, error) {
	hdr, err := parseFileHeader(src)
	if err != nil {
		return 0, false, err
	}
	return hdr.dictID, hdr.hasDict, nil
}
