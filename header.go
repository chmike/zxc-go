package zxc

import (
	"bytes"
	"encoding/binary"
	"math/bits"
)

// hash8 is the 8-bit block header checksum of § 7.1, computed over the 8
// header bytes with the checksum byte (offset 7, the top byte of the
// little-endian word) treated as zero.
func hash8(hdr []byte) uint8 {
	v := binary.LittleEndian.Uint64(hdr[:8]) &^ (0xFF << 56)
	h := (v ^ hashGolden64) * hashGolden64
	return uint8(h >> 56)
}

// hash16 is the 16-bit file header checksum of § 7.1, computed over the 16
// header bytes with the checksum bytes (offsets 14..15, the top halfword of
// the second word) treated as zero. The two halves are chained, not summed.
func hash16(hdr []byte) uint16 {
	v1 := binary.LittleEndian.Uint64(hdr[0:8])
	v2 := binary.LittleEndian.Uint64(hdr[8:16]) &^ (0xFFFF << 48)
	h := (v1 ^ hashMult64) * hashMult64
	h = (h + v2 + hashGolden64) * hashGolden64
	return uint16(h >> 48)
}

// digestCombine folds one block checksum into the archive digest (§ 7.3).
func digestCombine(acc uint64, blockChecksum uint32) uint64 {
	a := acc ^ (uint64(blockChecksum)+1)*hashGolden64
	hi, lo := bits.Mul64(a, hashXorShift64)
	return lo ^ hi
}

// uintBytes returns the fewest bytes holding v; 0 takes one byte (§ 8).
func uintBytes(v uint64) int {
	n := (bits.Len64(v) + 7) / 8
	if n == 0 {
		return 1
	}
	return n
}

// putUintLE stores the low n bytes of v, little-endian.
func putUintLE(dst []byte, v uint64, n int) {
	for i := range n {
		dst[i] = byte(v)
		v >>= 8
	}
}

// fileHeader holds the fields of a validated file header (§ 3).
type fileHeader struct {
	blockSize   int
	hasChecksum bool
	hasDict     bool
	hasSeek     bool
	dictID      uint32
}

// parseFileHeader validates the 16-byte file header at the start of b.
// The checks follow the order of the reference decoder, so that each
// malformed input reports the same error class.
func parseFileHeader(b []byte) (fileHeader, error) {
	var h fileHeader
	if len(b) < fileHeaderSize {
		return h, ErrTruncated
	}
	if binary.LittleEndian.Uint32(b) != magicWord {
		return h, ErrBadMagic
	}
	if b[4] != formatVersion {
		return h, ErrBadVersion
	}
	flags := b[6]
	if binary.LittleEndian.Uint16(b[14:]) != hash16(b) ||
		flags&flagChecksumAlgoMask != checksumAlgoRapidHash ||
		flags&flagReserved != 0 {
		return h, ErrBadHeader
	}
	// Reserved bytes 7..13, minus the dict_id (7..10) when it is present.
	first := 7
	if flags&flagHasDictionary != 0 {
		first = 11
	}
	for _, c := range b[first:14] {
		if c != 0 {
			return h, ErrBadHeader
		}
	}
	code := b[5]
	if code < blockSizeMinLog2 || code > blockSizeMaxLog2 {
		return h, ErrBadBlockSize
	}
	h.blockSize = 1 << code
	h.hasChecksum = flags&flagHasChecksum != 0
	h.hasDict = flags&flagHasDictionary != 0
	h.hasSeek = flags&flagHasSeekTable != 0
	if h.hasDict {
		h.dictID = binary.LittleEndian.Uint32(b[7:])
	}
	return h, nil
}

// parseBlockHeader validates the 8-byte block header at the start of b and
// returns its type and compressed payload size (§ 4.1). b must hold at
// least blockHeaderSize bytes.
func parseBlockHeader(b []byte) (typ byte, compSize uint32, err error) {
	if b[7] != hash8(b) {
		return 0, 0, ErrBadHeader
	}
	if b[1]|b[2] != 0 { // Block Flags and Reserved
		return 0, 0, ErrBadHeader
	}
	return b[0], binary.LittleEndian.Uint32(b[3:]), nil
}

// makeBlockHeader builds the one valid header for a block of the given type
// and payload size, checksum included. Used for the EOF and SEK headers,
// which a decoder compares byte for byte (§ 5.4, § 5.5).
func makeBlockHeader(typ byte, compSize uint32) [blockHeaderSize]byte {
	var h [blockHeaderSize]byte
	h[0] = typ
	binary.LittleEndian.PutUint32(h[3:], compSize)
	h[7] = hash8(h[:])
	return h
}

// seekTableBytes is the size T of a seek table describing n blocks,
// block header excluded (§ 5.5).
func seekTableBytes(n uint64) uint64 {
	return (n+seekGroup-1)/seekGroup*seekAnchorSize + n*seekEntrySize
}

// checkSeekHeader compares the bytes at the start of b with the one SEK
// header a frame of outSize decoded bytes admits, and returns the size of
// the table that follows it (§ 5.5, "Sequential Reading"). A differing byte
// is corruption; a matching but short prefix is a truncation.
func checkSeekHeader(b []byte, outSize uint64, blockSize int) (uint64, error) {
	n := (outSize + uint64(blockSize) - 1) / uint64(blockSize)
	t := seekTableBytes(n)
	want := makeBlockHeader(blockSEK, uint32(t^(t>>32)))
	m := min(len(b), blockHeaderSize)
	if !bytes.Equal(b[:m], want[:m]) {
		return 0, ErrCorrupt
	}
	if len(b) < blockHeaderSize {
		return 0, ErrTruncated
	}
	return t, nil
}

// footerLayout describes the one footer a frame implies (§ 8).
type footerLayout struct {
	skip           int    // digest bytes: 8 with checksums, else 0
	nd             int    // bytes of original_source_size
	nf             int    // bytes of compressed_frame_size
	len            int    // total footer bytes, digest included
	compressedSize uint64 // the whole frame, footer included
}

// makeFooterLayout computes the footer of a frame whose first prefix bytes
// precede it and which decodes to srcSize bytes. compressed_frame_size
// counts its own bytes, so nf is the fewest that hold the total.
func makeFooterLayout(prefix, srcSize uint64, hasChecksum bool) footerLayout {
	var l footerLayout
	if hasChecksum {
		l.skip = digestSize
	}
	l.nd = uintBytes(srcSize)
	base := prefix + uint64(l.skip) + uint64(l.nd) + 1
	l.nf = 1
	for uintBytes(base+uint64(l.nf)) > l.nf {
		l.nf++
	}
	l.compressedSize = base + uint64(l.nf)
	l.len = l.skip + l.nd + l.nf + 1
	return l
}

// encode writes the footer described by l into dst, which must hold
// l.len bytes.
func (l *footerLayout) encode(dst []byte, srcSize, digest uint64) {
	if l.skip > 0 {
		binary.LittleEndian.PutUint64(dst, digest)
	}
	p := dst[l.skip:]
	putUintLE(p, srcSize, l.nd)
	putUintLE(p[l.nd:], l.compressedSize, l.nf)
	p[l.nd+l.nf] = byte((l.nd - 1) | (l.nf-1)<<4)
}

// checkFooter compares the bytes at the start of b, digest aside, with the
// footer the frame implies, and returns the stored digest (0 without
// checksums). A differing byte is corruption; a matching but short prefix
// is a truncation.
func checkFooter(b []byte, l *footerLayout, srcSize uint64) (uint64, error) {
	var want [footerMaxSize]byte
	l.encode(want[:], srcSize, 0)
	n := min(len(b), l.len)
	if n > l.skip && !bytes.Equal(b[l.skip:n], want[l.skip:n]) {
		return 0, ErrCorrupt
	}
	if len(b) < l.len {
		return 0, ErrTruncated
	}
	if l.skip > 0 {
		return binary.LittleEndian.Uint64(b), nil
	}
	return 0, nil
}
