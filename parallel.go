package zxc

import (
	"encoding/binary"
	"slices"
	"sync"
	"sync/atomic"
)

// Parallel decoding of the blocks of one frame.
//
// Blocks are independent: no match crosses a block boundary, and every
// data block but the last decodes to exactly the block size (§ 4.1), so
// block i lands at i * blockSize in the frame's output. The frame is
// walked once to find its blocks, then the blocks are decoded by several
// goroutines, each straight into its place in dst.
//
// The block decoders copy in 32-byte steps and may write up to wildPad
// bytes past the end of their block, into the start of the next one. Two
// phases keep that from racing: first the even blocks, whose overrun lands
// on odd blocks not decoded yet, which overwrite it; then the odd blocks,
// whose overrun lands on even blocks already done: their first wildPad
// bytes are saved between the phases and put back after. No byte is ever
// written by two goroutines at the same time.
//
// This path only takes frames that decode cleanly. On anything else (a
// malformed header, a block that fails or has an unexpected size, a bad
// checksum, a frame with a dictionary, an output too large to reserve) it
// gives up, and decodeFrame decodes the frame sequentially, which reports
// exactly the error it always did.

// parBlock is one data block of the frame being decoded in parallel.
type parBlock struct {
	typ     byte
	payload []byte
	stored  uint32 // checksum stored after the block, if the frame has them
	n       int    // decoded size
	ok      bool   // decoded, right size, checksum verified if asked
}

// minParBlocks is the smallest number of blocks worth starting goroutines
// for.
const minParBlocks = 4

// decodeFrameParallel decodes the frame at the start of src, whose header
// hdr is already parsed and checked, and appends its output to dst. It
// returns false, with dst unchanged, when the frame should be decoded
// sequentially instead.
func (dec *decoder) decodeFrameParallel(dst, src []byte, hdr *fileHeader) (int, []byte, bool) {
	if hdr.hasDict {
		return 0, dst, false
	}
	ck := 0
	if hdr.hasChecksum {
		ck = blockChecksumSize
	}

	// Walk the block headers up to the EOF block.
	var blocks []parBlock
	pos := fileHeaderSize
	for {
		if len(src)-pos < blockHeaderSize {
			return 0, dst, false
		}
		typ, compSize, err := parseBlockHeader(src[pos:])
		if err != nil {
			return 0, dst, false
		}
		if typ == blockEOF {
			if compSize != 0 {
				return 0, dst, false
			}
			pos += blockHeaderSize
			break
		}
		if typ != blockRAW && typ != blockSPL && typ != blockPAK || compSize > uint32(hdr.blockSize) {
			return 0, dst, false
		}
		size := int(compSize)
		if blockHeaderSize+size+ck > len(src)-pos {
			return 0, dst, false
		}
		b := parBlock{typ: typ, payload: src[pos+blockHeaderSize : pos+blockHeaderSize+size]}
		if ck > 0 {
			b.stored = binary.LittleEndian.Uint32(src[pos+blockHeaderSize+size:])
		}
		blocks = append(blocks, b)
		pos += blockHeaderSize + size + ck
	}
	nb := len(blocks)
	if nb < minParBlocks {
		return 0, dst, false
	}

	// Reserve the output: nb full blocks plus the overrun of the last one,
	// within the same cap as Decompress puts on its reservation.
	room := uint64(nb)*uint64(hdr.blockSize) + wildPad
	if room > 64<<20+32*uint64(len(src)) {
		return 0, dst, false
	}
	start := len(dst)
	dst = slices.Grow(dst, int(room))
	out := dst[start : start+int(room)]
	bs := hdr.blockSize

	workers := min(dec.workers, (nb+1)/2)
	dec.parScratch = slices.Grow(dec.parScratch[:0], workers)[:workers]
	verify := dec.verify && hdr.hasChecksum

	// decode decodes block i into its place in out.
	decode := func(i int, sc *scratch) {
		b := &blocks[i]
		win := out[i*bs : (i+1)*bs+wildPad]
		var n int
		var err error
		switch b.typ {
		case blockRAW:
			n = copy(win[:bs], b.payload)
		case blockPAK:
			n, err = decodePAK(win, 0, b.payload)
		default:
			n, err = decodeSPL(win, 0, b.payload, sc, nil)
		}
		if err != nil || n > bs || n < bs && i < nb-1 {
			return
		}
		if verify && blockChecksum(win[:n], uint64(i)) != b.stored {
			return
		}
		b.n, b.ok = n, true
	}

	// run decodes the blocks first, first+2, first+4, ... on the workers.
	run := func(first int) {
		var next atomic.Int64
		next.Store(int64(first))
		var wg sync.WaitGroup
		for w := range workers {
			wg.Add(1)
			go func(sc *scratch) {
				defer wg.Done()
				for {
					i := int(next.Add(2) - 2)
					if i >= nb {
						return
					}
					decode(i, sc)
				}
			}(&dec.parScratch[w])
		}
		wg.Wait()
	}

	run(0)
	// Save the heads of the even blocks the odd ones may overrun.
	heads := make([][wildPad]byte, (nb+1)/2)
	for i := 2; i < nb; i += 2 {
		copy(heads[i/2][:], out[i*bs:])
	}
	run(1)
	for i := 2; i < nb; i += 2 {
		copy(out[i*bs:], heads[i/2][:min(wildPad, blocks[i].n)])
	}

	var digest uint64
	for i := range blocks {
		if !blocks[i].ok {
			return 0, dst[:start], false
		}
		if hdr.hasChecksum {
			digest = digestCombine(digest, blocks[i].stored)
		}
	}
	frameOut := (nb-1)*bs + blocks[nb-1].n
	n, err := dec.finishFrame(src, pos, uint64(frameOut), hdr, digest)
	if err != nil {
		return 0, dst[:start], false
	}
	return n, dst[:start+frameOut], true
}
