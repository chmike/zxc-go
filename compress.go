package zxc

import (
	"encoding/binary"
	"math/bits"
	"slices"
	"sync"
)

// The encoder follows the reference library v0.15.0 (zxc_compress.c,
// zxc_dispatch.c) decision for decision, so that both write the same
// archive byte for byte from the same input and options: the tests compare
// them (compress_test.go).

// Compress compresses src into a new buffer as one frame (§ 2.1). Without
// options it uses level 3, 512 KiB blocks and block checksums, and writes no
// seek table (see Option).
func Compress(src []byte, opts ...Option) ([]byte, error) {
	return AppendCompress(nil, src, opts...)
}

// AppendCompress is Compress appending the frame to dst, and returning the
// extended buffer. On error it returns dst unchanged.
func AppendCompress(dst, src []byte, opts ...Option) ([]byte, error) {
	cfg := newConfig(opts)
	bs := cfg.blockSize
	if bs < 1<<blockSizeMinLog2 || bs > 1<<blockSizeMaxLog2 || bs&(bs-1) != 0 {
		return dst, ErrBadBlockSize
	}
	if d := cfg.dict; d != nil && d.treeErr != nil && !emptyTable(d.table) {
		return dst, d.treeErr
	}
	enc := newEncoder(cfg)
	start := len(dst)
	nb := (len(src) + bs - 1) / bs
	dst = slices.Grow(dst, compressBound(len(src), bs, cfg.verify, cfg.seekable))

	// File header (§ 3).
	var hdr [fileHeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:], magicWord)
	hdr[4] = formatVersion
	hdr[5] = byte(bits.TrailingZeros(uint(bs)))
	if cfg.verify {
		hdr[6] |= flagHasChecksum | checksumAlgoRapidHash
	}
	if cfg.seekable {
		hdr[6] |= flagHasSeekTable
	}
	if cfg.dict != nil {
		hdr[6] |= flagHasDictionary
		binary.LittleEndian.PutUint32(hdr[7:], cfg.dict.id)
	}
	binary.LittleEndian.PutUint16(hdr[14:], hash16(hdr[:]))
	dst = append(dst, hdr[:]...)

	// Data blocks, then the EOF block (§ 4, § 5.4).
	var sizes []uint32
	if cfg.seekable {
		sizes = make([]uint32, 0, nb)
	}
	var digest uint64
	emit := func(b []byte) { // each block as appended, in order
		if cfg.seekable {
			sizes = append(sizes, uint32(len(b)))
		}
		if cfg.verify {
			digest = digestCombine(digest, binary.LittleEndian.Uint32(b[len(b)-blockChecksumSize:]))
		}
	}
	if w := min(cfg.workers, nb); w > 1 {
		dst = compressParallel(dst, src, bs, nb, w, cfg, enc, emit)
	} else {
		for i := range nb {
			at := len(dst)
			dst = enc.appendBlock(dst, src[i*bs:min((i+1)*bs, len(src))], uint64(i))
			emit(dst[at:])
		}
	}
	eof := makeBlockHeader(blockEOF, 0)
	dst = append(dst, eof[:]...)

	// Seek table (§ 5.5): per group of 64 blocks, the offset of its first
	// block from the start of the frame, then the size of each block.
	if cfg.seekable {
		t := seekTableBytes(uint64(nb))
		sek := makeBlockHeader(blockSEK, uint32(t^(t>>32)))
		dst = append(dst, sek[:]...)
		anchor := uint64(fileHeaderSize)
		for i, n := range sizes {
			if i%seekGroup == 0 {
				dst = binary.LittleEndian.AppendUint64(dst, anchor)
			}
			dst = binary.LittleEndian.AppendUint32(dst, n)
			anchor += uint64(n)
		}
	}

	// Footer (§ 8), covering everything before it.
	l := makeFooterLayout(uint64(len(dst)-start), uint64(len(src)), cfg.verify)
	var foot [footerMaxSize]byte
	l.encode(foot[:], uint64(len(src)), digest)
	return append(dst, foot[:l.len]...), nil
}

// compressParallel appends the nb blocks of src, in blocks of bs, encoded
// by w goroutines, each with its own encoder, enc being the first one's.
// Blocks are independent: the frame is the one a sequential run writes.
// The blocks go by batches of 4 per goroutine, block j of a batch on
// goroutine j % w, into slot buffers reused from batch to batch; emit gets
// each block appended to dst, in order.
func compressParallel(dst, src []byte, bs, nb, w int, cfg config, enc *encoder, emit func([]byte)) []byte {
	encs := make([]*encoder, w)
	encs[0] = enc
	for k := 1; k < w; k++ {
		encs[k] = newEncoder(cfg)
	}
	batch := 4 * w
	slots := make([][]byte, batch)
	var wg sync.WaitGroup
	for first := 0; first < nb; first += batch {
		n := min(batch, nb-first)
		for k := range min(w, n) {
			wg.Add(1)
			go func(k int) {
				defer wg.Done()
				for j := k; j < n; j += w {
					i := first + j
					slots[j] = encs[k].appendBlock(slots[j][:0], src[i*bs:min((i+1)*bs, len(src))], uint64(i))
				}
			}(k)
		}
		wg.Wait()
		for j := range n {
			dst = append(dst, slots[j]...)
			emit(slots[j])
		}
	}
	return dst
}

// compressBound is the largest frame Compress can write for n bytes in
// blocks of bs: every block stored RAW.
func compressBound(n, bs int, checksums, seekable bool) int {
	nb := (n + bs - 1) / bs
	per := blockHeaderSize
	if checksums {
		per += blockChecksumSize
	}
	size := fileHeaderSize + n + nb*per + blockHeaderSize + footerMaxSize
	if seekable {
		size += blockHeaderSize + int(seekTableBytes(uint64(nb)))
	}
	return size
}

// encoder holds the state of one Compress call, reused from block to
// block: the match finder's tables and the streams of the block being
// encoded.
type encoder struct {
	config
	m      matcher
	lits   []byte   // literals of the block
	seqs   []uint32 // PAK sequence words
	toks   []byte   // SPL tokens
	offs   []uint16 // SPL offsets minus 1
	extras []byte   // varint escapes of the lengths
	side   []byte   // per-sequence scratch of splitMatches

	// Levels 6 and 7: the optimal parser's arrays and the Huffman builder.
	dp        []uint32
	parentLen []uint16
	parentOff []uint16
	ends      []int
	huf       hufBuilder
	litTree   encTree
	tokTree   encTree

	// With a dictionary: the window [content | block], and the code
	// lengths and tree of its shared literal table, when dictHuf.
	win      []byte
	dictLen  [hufNumSymbols]uint8
	dictTree encTree
	dictHuf  bool
}

func newEncoder(cfg config) *encoder {
	e := &encoder{config: cfg}
	chunk := cfg.blockSize
	if d := cfg.dict; d != nil {
		// [dictionary | block]: positions up to the next power of 2.
		chunk = 1 << bits.Len(uint(len(d.content)+cfg.blockSize-1))
		e.win = append(make([]byte, 0, len(d.content)+cfg.blockSize), d.content...)
		if !emptyTable(d.table) && d.treeErr == nil {
			e.dictLen = unpackLengths(d.table)
			e.dictHuf = e.dictTree.build(&e.dictLen)
		}
	}
	e.m.init(chunk)
	return e
}

// emptyTable reports whether a shared literal table holds no code: the
// reference treats it as no table.
func emptyTable(t []byte) bool {
	for _, b := range t {
		if b != 0 {
			return false
		}
	}
	return true
}

// appendBlock appends the block blk, the index-th of its frame, as
// zxc_compress_chunk_wrapper does: coded at the level's block type, or RAW
// when coding does not make it smaller, its header included; then its
// checksum when the frame carries them.
func (e *encoder) appendBlock(dst, blk []byte, index uint64) []byte {
	at := len(dst)
	src, start := blk, 0
	if e.dict != nil {
		start = len(e.dict.content)
		e.win = append(e.win[:start], blk...)
		src = e.win
	}
	var ok bool
	if e.level <= 2 {
		dst, ok = e.appendPAK(dst, src, start)
	} else {
		dst, ok = e.appendSPL(dst, src, start)
	}
	if !ok || len(dst)-at >= len(blk) {
		dst = dst[:at]
		h := makeBlockHeader(blockRAW, uint32(len(blk)))
		dst = append(dst, h[:]...)
		dst = append(dst, blk...)
	}
	if e.verify {
		dst = binary.LittleEndian.AppendUint32(dst, blockChecksum(blk, index))
	}
	return dst
}

// appendVarint appends v as a prefix varint (§ 6), as zxc_write_varint
// does, and reports false for a value beyond the 3-byte form.
func appendVarint(dst []byte, v uint32) ([]byte, bool) {
	switch {
	case v < 1<<7:
		return append(dst, byte(v)), true
	case v < 1<<14:
		return append(dst, byte(0x80|v&0x3F), byte(v>>6)), true
	case v < 1<<21:
		return append(dst, byte(0xC0|v&0x1F), byte(v>>5), byte(v>>13)), true
	}
	return dst, false
}
