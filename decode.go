package zxc

import (
	"encoding/binary"
	"fmt"
	"slices"
)

// Decompress decodes every frame of src (§ 2.1) and returns the result in
// a new buffer. Without options it verifies the checksums the archive
// carries, uses no dictionary and decodes the blocks of each frame on
// runtime.GOMAXPROCS(0) goroutines (see Option). On error it returns nil:
// partially decoded output is never returned as a valid result (§ 11.3).
func Decompress(src []byte, opts ...Option) ([]byte, error) {
	return AppendDecompress(nil, src, opts...)
}

// AppendDecompress is Decompress appending the result to dst, and
// returning the extended buffer. On error it returns dst unchanged.
func AppendDecompress(dst, src []byte, opts ...Option) ([]byte, error) {
	dec := newDecoder(newConfig(opts))
	start := len(dst)
	if size, ok := frameSizes(src); ok {
		// Size the output once from the footers. They are not trusted yet,
		// so the reservation is capped: a forged size costs at most this
		// much memory, and a larger real output grows as usual.
		limit := 64<<20 + 32*uint64(len(src))
		dst = slices.Grow(dst, int(min(size, limit))+wildPad)
	}
	pos := 0
	for {
		n, out, err := dec.decodeFrame(dst, src[pos:])
		if err != nil {
			return dst[:start], err
		}
		dst = out
		pos += n

		// After each footer: end of input, another frame, or corruption.
		rest := src[pos:]
		if len(rest) == 0 {
			return dst, nil
		}
		if len(rest) < 4 || binary.LittleEndian.Uint32(rest) != magicWord {
			return dst[:start], ErrCorrupt
		}
	}
}

// frameSizes adds up the decompressed sizes the footers of src declare,
// walking the frames back from the end (§ 8). It is a sizing hint: false
// when the footers do not parse, and the decoder checks every one anyway.
func frameSizes(src []byte) (uint64, bool) {
	var total uint64
	for end := len(src); end > 0; {
		if end < fileHeaderSize+blockHeaderSize+3 {
			return 0, false
		}
		L := src[end-1]
		nd, nf := int(L&7)+1, int(L>>4)+1
		if L&0x88 != 0 || nd+nf+1 > end {
			return 0, false
		}
		dsize := leUint(src[end-1-nf-nd : end-1-nf])
		fsize := leUint(src[end-1-nf : end-1])
		if fsize > uint64(end) || fsize < fileHeaderSize || dsize > 1<<62-total {
			return 0, false
		}
		total += dsize
		end -= int(fsize)
	}
	return total, true
}

// decoder holds the state reused across the blocks and frames of one
// Decompress call, or of one Seekable read.
type decoder struct {
	config              // the parameters of the call (options.go)
	sc      scratch     // section buffers
	window  []byte      // [dictionary content, if any | block + wildPad]
	winFor  *Dictionary // the dictionary window was filled with
	winDict bool        // window holds a dictionary prefix

	parScratch []scratch // section buffers of the parallel workers
}

func newDecoder(c config) *decoder { return &decoder{config: c} }

// checkDict verifies that the dictionary the frame names is the one given.
func (dec *decoder) checkDict(hdr *fileHeader) error {
	if !hdr.hasDict {
		return nil
	}
	if dec.dict == nil {
		return fmt.Errorf("%w: archive needs dictionary %#08x", ErrDictRequired, hdr.dictID)
	}
	if dec.dict.id != hdr.dictID {
		return fmt.Errorf("%w: archive needs %#08x, got %#08x", ErrDictMismatch, hdr.dictID, dec.dict.id)
	}
	return dec.dict.treeErr
}

// decodeBlock decodes one data block of the given type and payload and
// appends its output to dst. hdr is the header of the block's frame.
func (dec *decoder) decodeBlock(dst []byte, typ byte, payload []byte, hdr *fileHeader) ([]byte, error) {
	switch typ {
	case blockRAW:
		return append(dst, payload...), nil
	case blockSPL, blockPAK:
	default:
		// SEK is not a data block: inside the block walk it is as unknown
		// as any undefined type (§ 10.3).
		return dst, ErrBadBlockType
	}

	// The decoders write a window of one block plus the wild-copy padding
	// and stop at the block size (§ 11.1). The window is dst itself when it
	// has the room and no dictionary is involved. Otherwise it is a scratch
	// buffer, whose prefix holds the dictionary content if any, so that
	// matches can reach into it (§ 12.2); the block is copied out after.
	// That is the case of a last block shorter than the block size in a
	// buffer sized to the output: dst is never reallocated for padding.
	var out []byte
	base := 0
	direct := !hdr.hasDict && cap(dst)-len(dst) >= hdr.blockSize+wildPad
	if direct {
		out = dst[len(dst) : len(dst)+hdr.blockSize+wildPad]
	} else {
		var content []byte
		if hdr.hasDict {
			content = dec.dict.content
		}
		base = len(content)
		need := base + hdr.blockSize + wildPad
		// The decoders never write below base, so the prefix stays intact
		// from block to block; a Dictionary is immutable, so its pointer
		// identifies the content (nil for none).
		if winFor := dec.dict; !hdr.hasDict {
			winFor = nil
			if len(dec.window) < need || dec.winFor != nil || dec.winDict {
				dec.window = make([]byte, need)
				dec.winFor, dec.winDict = nil, false
			}
		} else if len(dec.window) < need || dec.winFor != winFor || !dec.winDict {
			dec.window = make([]byte, need)
			copy(dec.window, content)
			dec.winFor, dec.winDict = winFor, true
		}
		out = dec.window[:need]
	}

	var n int
	var err error
	if typ == blockPAK {
		n, err = decodePAK(out, base, payload)
	} else {
		n, err = decodeSPL(out, base, payload, &dec.sc, dec.dict)
	}
	if err != nil {
		return dst, err
	}
	if direct {
		return dst[:len(dst)+n], nil
	}
	return append(dst, out[base:base+n]...), nil
}

// decodeFrame decodes the single frame at the start of src, appending its
// output to dst. It returns the number of bytes of src the frame occupies.
func (dec *decoder) decodeFrame(dst, src []byte) (int, []byte, error) {
	hdr, err := parseFileHeader(src)
	if err != nil {
		return 0, dst, err
	}
	if err := dec.checkDict(&hdr); err != nil {
		return 0, dst, err
	}
	if dec.workers > 1 {
		if n, out, ok := dec.decodeFrameParallel(dst, src, &hdr); ok {
			return n, out, nil
		}
	}

	frameStart := len(dst)
	pos := fileHeaderSize
	var blockIndex, digest uint64
	checksumSize := 0
	if hdr.hasChecksum {
		checksumSize = blockChecksumSize
	}

	// Block walk: only the EOF block may end it (§ 11.1).
	for {
		if len(src)-pos < blockHeaderSize {
			return 0, dst, ErrTruncated
		}
		typ, compSize, err := parseBlockHeader(src[pos:])
		if err != nil {
			return 0, dst, err
		}
		if typ == blockEOF {
			// Flags, Reserved and the checksum are already checked; the
			// one valid EOF header also has a zero payload size (§ 5.4).
			if compSize != 0 {
				return 0, dst, ErrBadHeader
			}
			pos += blockHeaderSize
			break
		}

		// A data block never exceeds the block size (§ 4.1). This bound
		// also keeps the int conversions below safe on 32-bit hosts.
		if compSize > uint32(hdr.blockSize) {
			return 0, dst, ErrBadBlockSize
		}
		size := int(compSize)
		advance := blockHeaderSize + size + checksumSize
		if advance > len(src)-pos {
			return 0, dst, ErrTruncated
		}
		payload := src[pos+blockHeaderSize : pos+blockHeaderSize+size]

		blockStart := len(dst)
		if dst, err = dec.decodeBlock(dst, typ, payload, &hdr); err != nil {
			return 0, dst, err
		}

		if hdr.hasChecksum {
			stored := binary.LittleEndian.Uint32(src[pos+blockHeaderSize+size:])
			if dec.verify {
				if err := verifyBlockChecksum(dst[blockStart:], blockIndex, stored); err != nil {
					return 0, dst, err
				}
			}
			digest = digestCombine(digest, stored)
		}
		blockIndex++
		pos += advance
	}

	n, err := dec.finishFrame(src, pos, uint64(len(dst)-frameStart), &hdr, digest)
	if err != nil {
		return 0, dst, err
	}
	return n, dst, nil
}

// finishFrame checks what follows the EOF block at src[pos:], the SEK
// header and table if the frame has one, then the footer, for a frame that
// decoded to frameOut bytes and whose block checksums fold to digest. It
// returns the size of the whole frame.
func (dec *decoder) finishFrame(src []byte, pos int, frameOut uint64, hdr *fileHeader, digest uint64) (int, error) {
	// The file header says whether a SEK block follows the EOF block; a
	// sequential decoder checks its header and skips the table (§ 5.5).
	if hdr.hasSeek {
		t, err := checkSeekHeader(src[pos:], frameOut, hdr.blockSize)
		if err != nil {
			return 0, err
		}
		pos += blockHeaderSize
		if t > uint64(len(src)-pos) {
			return 0, ErrTruncated
		}
		pos += int(t)
	}

	// The footer is the one the frame implies, compared byte for byte (§ 8).
	l := makeFooterLayout(uint64(pos), frameOut, hdr.hasChecksum)
	stored, err := checkFooter(src[pos:], &l, frameOut)
	if err != nil {
		return 0, err
	}
	if dec.verify && hdr.hasChecksum && stored != digest {
		return 0, ErrBadChecksum
	}
	return pos + l.len, nil
}

// verifyBlockChecksum checks a decoded block against its stored checksum,
// fold32(rapidhash(block, index)) (§ 7.2). The seed binds the block to its
// position: a block moved elsewhere in the frame fails its own check.
func verifyBlockChecksum(block []byte, index uint64, stored uint32) error {
	if got := blockChecksum(block, index); got != stored {
		return fmt.Errorf("%w: block %d: stored %#08x, computed %#08x", ErrBadChecksum, index, stored, got)
	}
	return nil
}
