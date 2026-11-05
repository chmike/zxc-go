package zxc

import "runtime"

// An Option sets a parameter of Compress, AppendCompress, Decompress,
// AppendDecompress or OpenSeekable; an option a function has no use for is
// ignored (WithLevel by Decompress, for example). Without options they use
// the defaults:
//   - checksums written on compression and verified on decompression,
//     when the archive carries them (WithChecksums);
//   - no dictionary (WithDictionary);
//   - the blocks of a frame encoded or decoded by runtime.GOMAXPROCS(0)
//     goroutines (WithParallel);
//   - compression level 3 (WithLevel), 512 KiB blocks (WithBlockSize), no
//     seek table (WithSeekable).
//
// Options apply in order: when one is given twice, the last one counts.
type Option func(*config)

// config holds the parameters the options set.
type config struct {
	verify  bool        // write, or check, the archive digest and block checksums
	dict    *Dictionary // nil without one
	workers int         // goroutines for the blocks of a frame; 1 = sequential

	level     int  // compression level, 1 to 7
	blockSize int  // compression block size; checked by Compress
	seekable  bool // write a seek table
}

// Compression defaults, those of the reference library.
const (
	defaultLevel     = 3
	maxLevel         = 7
	defaultBlockSize = 512 << 10
)

// newConfig returns the defaults with opts applied.
func newConfig(opts []Option) config {
	c := config{verify: true, level: defaultLevel, blockSize: defaultBlockSize}
	for _, o := range opts {
		o(&c)
	}
	if c.workers <= 0 {
		c.workers = runtime.GOMAXPROCS(0)
	}
	if c.level <= 0 {
		c.level = defaultLevel
	}
	c.level = min(c.level, maxLevel)
	return c
}

// WithChecksums sets whether Compress writes the checksums of the archive,
// and whether decompression verifies them: the per-block checksums (§ 7.2)
// and the archive digest (§ 7.3). The default is true. Archives written
// without checksums are never verified, whatever this option says.
func WithChecksums(verify bool) Option {
	return func(c *config) { c.verify = verify }
}

// WithDictionary gives the dictionary to compress with, or the one the
// archive was compressed with (§ 12). An archive that names a dictionary
// cannot be decoded without it (ErrDictRequired), nor with another one
// (ErrDictMismatch); decompression ignores it for archives compressed
// without a dictionary. The default is none.
func WithDictionary(d *Dictionary) Option {
	return func(c *config) { c.dict = d }
}

// WithParallel sets the number of goroutines that encode or decode the
// blocks of a frame: 1 works sequentially, 0 or less selects
// runtime.GOMAXPROCS(0), the default. The output and the errors do not
// depend on it. It has no effect on OpenSeekable, whose reads decode their
// blocks sequentially.
func WithParallel(n int) Option {
	return func(c *config) { c.workers = n }
}

// WithLevel sets the compression level, from 1 (fastest) to 7 (densest);
// 0 or less selects the default, 3, and a level above 7 is taken as 7, as
// the reference library does. Levels 1 and 2 write PAK blocks, the others
// SPL blocks, with Huffman-coded literals from level 6 and tokens at 7.
func WithLevel(level int) Option {
	return func(c *config) { c.level = level }
}

// WithBlockSize sets the size of the blocks Compress cuts the input into: a
// power of 2 from 4 KiB to 2 MiB, the default being 512 KiB. Any other size
// makes Compress fail with ErrBadBlockSize.
func WithBlockSize(n int) Option {
	return func(c *config) { c.blockSize = n }
}

// WithSeekable sets whether Compress appends a seek table, which
// OpenSeekable needs for random access (§ 5.5). The default is false.
func WithSeekable(on bool) Option {
	return func(c *config) { c.seekable = on }
}
