package zxc

import "runtime"

// An Option sets a parameter of Decompress, AppendDecompress or
// OpenSeekable. Without options they use the defaults:
//   - checksums verified, when the archive carries them (WithChecksums);
//   - no dictionary (WithDictionary);
//   - the blocks of a frame decoded by runtime.GOMAXPROCS(0) goroutines
//     (WithParallel).
//
// Options apply in order: when one is given twice, the last one counts.
type Option func(*config)

// config holds the parameters the options set.
type config struct {
	verify  bool        // check the archive digest and block checksums
	dict    *Dictionary // nil without one
	workers int         // goroutines for the blocks of a frame; 1 = sequential
}

// newConfig returns the defaults with opts applied.
func newConfig(opts []Option) config {
	c := config{verify: true}
	for _, o := range opts {
		o(&c)
	}
	if c.workers <= 0 {
		c.workers = runtime.GOMAXPROCS(0)
	}
	return c
}

// WithChecksums sets whether the checksums of the archive are verified:
// the per-block checksums (§ 7.2) and the archive digest (§ 7.3). The
// default is true. Archives written without checksums are never verified,
// whatever this option says.
func WithChecksums(verify bool) Option {
	return func(c *config) { c.verify = verify }
}

// WithDictionary gives the dictionary the archive was compressed with, if
// any (§ 12). An archive that names a dictionary cannot be decoded
// without it (ErrDictRequired), nor with another one (ErrDictMismatch). It
// is ignored for archives compressed without a dictionary. The default is
// none.
func WithDictionary(d *Dictionary) Option {
	return func(c *config) { c.dict = d }
}

// WithParallel sets the number of goroutines that decode the blocks of a
// frame: 1 decodes sequentially, 0 or less selects runtime.GOMAXPROCS(0),
// the default. The output and the errors do not depend on it. It has no
// effect on OpenSeekable, whose reads decode their blocks sequentially.
func WithParallel(n int) Option {
	return func(c *config) { c.workers = n }
}
