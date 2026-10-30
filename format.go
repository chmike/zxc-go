// Package zxc is a native Go decoder for the ZXC compressed format,
// format version 9, as specified in docs/FORMAT.md of
// https://github.com/hellobertrand/zxc.
//
// Section numbers in comments (§ n) refer to that document.
package zxc

import "errors"

// File and block layout constants (§ 3, § 4, § 13).
const (
	magicWord     = 0x9CB02EF5
	formatVersion = 9

	fileHeaderSize    = 16
	blockHeaderSize   = 8
	blockChecksumSize = 4
	digestSize        = 8
	footerMaxSize     = digestSize + 8 + 8 + 1 // digest, two 8-byte sizes, L

	blockSizeMinLog2 = 12 // 4 KiB
	blockSizeMaxLog2 = 21 // 2 MiB
)

// File header flags (§ 3.1).
const (
	flagHasChecksum       = 0x80
	flagHasDictionary     = 0x40
	flagHasSeekTable      = 0x20
	flagReserved          = 0x10
	flagChecksumAlgoMask  = 0x0F
	checksumAlgoRapidHash = 0
)

// Block types (§ 4.1).
const (
	blockRAW = 0
	blockSPL = 1
	blockPAK = 2
	blockSEK = 254
	blockEOF = 255
)

// Seek table geometry (§ 5.5).
const (
	seekGroup      = 64
	seekAnchorSize = 8
	seekEntrySize  = 4
)

// Hash constants (§ 7.1, § 7.3).
const (
	hashGolden64   = 0x9E3779B97F4A7C15
	hashMult64     = 0xD2D84A61D2D84A61
	hashXorShift64 = 0x2545F4914F6CDD1D
)

// Errors returned by the decoder. They follow the error classes of § 11.1;
// test them with errors.Is.
var (
	ErrTruncated      = errors.New("zxc: truncated input")
	ErrBadMagic       = errors.New("zxc: bad magic word")
	ErrBadVersion     = errors.New("zxc: unsupported format version")
	ErrBadHeader      = errors.New("zxc: corrupt header")
	ErrBadBlockSize   = errors.New("zxc: invalid block size")
	ErrBadBlockType   = errors.New("zxc: unknown block type")
	ErrCorrupt        = errors.New("zxc: corrupt data")
	ErrBadChecksum    = errors.New("zxc: checksum mismatch")
	ErrDictRequired   = errors.New("zxc: dictionary required")
	ErrDictMismatch   = errors.New("zxc: wrong dictionary")
	ErrNotImplemented = errors.New("zxc: not implemented yet")
)
