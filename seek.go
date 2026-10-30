package zxc

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// Seek table layout (§ 5.5): groups of 64 blocks, each an 8-byte anchor
// followed by one 4-byte on-disk size per block.
const seekGroupBytes = seekAnchorSize + seekGroup*seekEntrySize

// A Seekable gives random access to the decompressed content of a seekable
// archive (one written with zxc -S, § 5.5): ReadAt decodes only the blocks
// the requested range touches.
//
// Every frame of the archive must carry a seek table. Checksums are
// verified unless WithChecksums(false) says otherwise; the archive digest is not, since a range read
// does not see every block (§ 7.3).
//
// A Seekable implements io.ReaderAt and is safe for concurrent use.
type Seekable struct {
	src    []byte
	frames []seekFrame
	size   int64 // decompressed size, all frames
	cfg    config
	pool   sync.Pool // *decoder, one per concurrent ReadAt
}

// seekFrame describes one frame of the archive (§ 2.1).
type seekFrame struct {
	hdr        fileHeader
	base       int64  // offset of the frame in the archive
	eofOff     int64  // EOF block header, relative to base like the anchors
	tableOff   int64  // first group of the table, absolute
	numBlocks  int64  // data blocks
	size       int64  // decompressed size
	decompBase int64  // decompressed offset of the frame's first byte
	entryMax   uint32 // largest legal block on disk
}

// OpenSeekable parses the footers and seek tables of a seekable archive
// held in src, walking the frames back from the end. It reads no data
// block; ReadAt decodes them on demand. src must stay unchanged while the
// Seekable is in use.
func OpenSeekable(src []byte, opts ...Option) (*Seekable, error) {
	s := &Seekable{src: src, cfg: newConfig(opts)}
	s.cfg.workers = 1 // a read decodes its blocks itself
	if len(src) == 0 {
		return nil, ErrTruncated
	}
	// The first header speaks first: junk is a bad magic word, not a
	// broken footer.
	if _, err := parseFileHeader(src); err != nil {
		return nil, err
	}
	var frames []seekFrame
	for end := int64(len(src)); end > 0; {
		f, err := parseSeekFrame(src, end)
		if err != nil {
			return nil, err
		}
		frames = append(frames, f)
		end = f.base
	}
	// Walked back: put them in archive order and number their bytes.
	for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
		frames[i], frames[j] = frames[j], frames[i]
	}
	for i := range frames {
		frames[i].decompBase = s.size
		if frames[i].size > 1<<62-s.size {
			return nil, corruptf("decompressed size overflows")
		}
		s.size += frames[i].size
	}
	s.frames = frames
	s.pool.New = func() any { return newDecoder(s.cfg) }
	return s, nil
}

// Size returns the decompressed size of the whole archive.
func (s *Seekable) Size() int64 { return s.size }

// parseSeekFrame parses the frame that ends at src[end-1]: its footer, read
// back from the end (§ 8), its header, and the geometry of its seek table
// (§ 5.5, "Backward Reading").
func parseSeekFrame(src []byte, end int64) (seekFrame, error) {
	var f seekFrame
	const minFrame = fileHeaderSize + blockHeaderSize + 3 // header, EOF block, shortest footer
	if end < minFrame {
		return f, ErrTruncated
	}

	// Footer: L gives the lengths of the two sizes, each minimal.
	L := src[end-1]
	if L&0x88 != 0 {
		return f, corruptf("footer lengths byte %#02x", L)
	}
	nd, nf := int64(L&7)+1, int64(L>>4)+1
	if nd+nf+1 > end {
		return f, ErrTruncated
	}
	dsize := leUint(src[end-1-nf-nd : end-1-nf])
	fsize := leUint(src[end-1-nf : end-1])
	if int64(uintBytes(dsize)) != nd || int64(uintBytes(fsize)) != nf ||
		(nf > 1 && int64(uintBytes(fsize-1)) < nf) {
		return f, corruptf("footer sizes not minimal")
	}
	if fsize < minFrame || fsize > uint64(end) {
		return f, corruptf("frame size %d out of range", fsize)
	}
	f.base = end - int64(fsize)
	frame := int64(fsize)

	hdr, err := parseFileHeader(src[f.base:end])
	if err != nil {
		if err == ErrBadMagic && f.base != 0 {
			return f, corruptf("frame at %d has no magic word", f.base)
		}
		return f, err
	}
	if !hdr.hasSeek {
		return f, fmt.Errorf("zxc: frame at offset %d has no seek table", f.base)
	}
	f.hdr = hdr
	footerLen := nd + nf + 1
	if hdr.hasChecksum {
		footerLen += digestSize
	}
	bs := int64(hdr.blockSize)
	// A frame holds at least 8 bytes per block: that bounds the block count
	// and the size before any other arithmetic on them.
	nb := dsize / uint64(bs)
	if dsize%uint64(bs) != 0 {
		nb++
	}
	if nb > uint64(frame)/blockHeaderSize {
		return f, corruptf("decompressed size %d impossible for the frame", dsize)
	}
	f.size = int64(dsize) // < 2^63: at most frame/8 blocks of 2 MiB
	f.numBlocks = int64(nb)

	// Layout: [header 16][data blocks][EOF 8][SEK 8 + T][footer].
	sekTotal := int64(blockHeaderSize) + int64(seekTableBytes(uint64(f.numBlocks)))
	if sekTotal+footerLen > frame-fileHeaderSize-blockHeaderSize {
		return f, corruptf("seek table does not fit the frame")
	}
	f.eofOff = frame - footerLen - sekTotal - blockHeaderSize
	f.tableOff = f.base + f.eofOff + 2*blockHeaderSize
	f.entryMax = uint32(blockHeaderSize + hdr.blockSize)
	if hdr.hasChecksum {
		f.entryMax += blockChecksumSize
	}
	// numBlocks blocks of 8 to entryMax bytes must fill the data area.
	area := f.eofOff - fileHeaderSize
	if area < f.numBlocks*blockHeaderSize || area > f.numBlocks*int64(f.entryMax) {
		return f, corruptf("data area of %d bytes cannot hold %d blocks", area, f.numBlocks)
	}

	// The EOF and SEK headers ahead of the table, each in its one valid form.
	if err := checkSeekTail(src, &f); err != nil {
		return f, err
	}
	return f, nil
}

// checkSeekTail checks the EOF block header and the SEK block header that
// precede the frame's table.
func checkSeekTail(src []byte, f *seekFrame) error {
	at := f.base + f.eofOff
	eof := makeBlockHeader(blockEOF, 0)
	if string(src[at:at+blockHeaderSize]) != string(eof[:]) {
		return corruptf("no EOF block before the seek table")
	}
	if _, err := checkSeekHeader(src[at+blockHeaderSize:at+2*blockHeaderSize], uint64(f.size), f.hdr.blockSize); err != nil {
		return err
	}
	return nil
}

// leUint reads a little-endian unsigned integer of 1 to 8 bytes.
func leUint(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// blockSpan locates block k of frame f: its offset in the archive and its
// on-disk size, read from its group of the seek table. The whole group is
// checked (§ 5.5, step 7): anchor inside the data area (exactly 16 for the
// first group), every size in [8, entryMax], the group ending within the
// data area and, for the last group, exactly on the EOF block.
func (s *Seekable) blockSpan(f *seekFrame, k int64) (int64, uint32, error) {
	g := k / seekGroup
	lastGroup := (f.numBlocks - 1) / seekGroup
	cnt := int64(seekGroup)
	if g == lastGroup {
		cnt = f.numBlocks - g*seekGroup
	}
	at := f.tableOff + g*seekGroupBytes
	grp := s.src[at : at+seekAnchorSize+cnt*seekEntrySize]

	pos := int64(binary.LittleEndian.Uint64(grp))
	if (g == 0 && pos != fileHeaderSize) || pos < fileHeaderSize || pos > f.eofOff {
		return 0, 0, corruptf("seek table group %d: anchor %d out of range", g, pos)
	}
	var start int64
	var size uint32
	for j := range cnt {
		sz := binary.LittleEndian.Uint32(grp[seekAnchorSize+j*seekEntrySize:])
		if sz < blockHeaderSize || sz > f.entryMax {
			return 0, 0, corruptf("seek table group %d: block size %d out of range", g, sz)
		}
		if g*seekGroup+j == k {
			start, size = pos, sz
		}
		pos += int64(sz)
	}
	if pos > f.eofOff || (g == lastGroup && pos != f.eofOff) {
		return 0, 0, corruptf("seek table group %d does not end on its blocks", g)
	}
	return f.base + start, size, nil
}

// ReadAt decodes len(p) bytes of the decompressed content starting at off.
// As io.ReaderAt requires, it returns io.EOF with fewer bytes when the
// range runs past the end, and an error otherwise only when the archive is
// corrupt or the dictionary is missing.
func (s *Seekable) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("zxc: negative offset %d", off)
	}
	if off >= s.size {
		if len(p) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > s.size-off {
		want = int(s.size - off)
	}
	dec := s.pool.Get().(*decoder)
	defer s.pool.Put(dec)

	n := 0
	fi := s.frameOf(off)
	var block []byte
	for n < want {
		f := &s.frames[fi]
		rel := off + int64(n) - f.decompBase
		if rel >= f.size {
			fi++ // next frame; empty frames are skipped too
			continue
		}
		if err := dec.checkDict(&f.hdr); err != nil {
			return n, err
		}
		bs := int64(f.hdr.blockSize)
		k := rel / bs
		var err error
		if block, err = s.decodeSeekBlock(dec, f, k, block[:0]); err != nil {
			return n, err
		}
		n += copy(p[n:want], block[rel-k*bs:])
	}
	if want < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// frameOf returns the index of the frame holding decompressed offset off,
// which must be below the size.
func (s *Seekable) frameOf(off int64) int {
	lo, hi := 0, len(s.frames)
	for lo < hi { // first frame starting past off; the one before holds it
		mid := int(uint(lo+hi) >> 1)
		if s.frames[mid].decompBase <= off {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo - 1
}

// decodeSeekBlock decodes block k of frame f, appending it to dst.
func (s *Seekable) decodeSeekBlock(dec *decoder, f *seekFrame, k int64, dst []byte) ([]byte, error) {
	start, size, err := s.blockSpan(f, k)
	if err != nil {
		return dst, err
	}
	b := s.src[start : start+int64(size)]
	typ, compSize, err := parseBlockHeader(b)
	if err != nil {
		return dst, err
	}
	// The block found there must be the one the entry describes.
	onDisk := int64(blockHeaderSize) + int64(compSize)
	if f.hdr.hasChecksum {
		onDisk += blockChecksumSize
	}
	if onDisk != int64(size) {
		return dst, corruptf("block %d: seek entry says %d bytes, header %d", k, size, onDisk)
	}
	if compSize > uint32(f.hdr.blockSize) {
		return dst, ErrBadBlockSize
	}
	payload := b[blockHeaderSize : blockHeaderSize+compSize]
	if dst, err = dec.decodeBlock(dst, typ, payload, &f.hdr); err != nil {
		return dst, err
	}
	// Every block decodes to the block size, the last one to the rest.
	bs := int64(f.hdr.blockSize)
	if want := min(bs, f.size-k*bs); int64(len(dst)) != want {
		return dst, corruptf("block %d decodes to %d bytes, want %d", k, len(dst), want)
	}
	if f.hdr.hasChecksum && dec.verify {
		stored := binary.LittleEndian.Uint32(b[blockHeaderSize+compSize:])
		if err := verifyBlockChecksum(dst, uint64(k), stored); err != nil {
			return dst, err
		}
	}
	return dst, nil
}
