// Command zxcgo compresses and decompresses ZXC archives with the native Go
// codec, with the options of the reference zxc CLI:
//
//	zxcgo [-1..-7] [-B size] [-N] [-S] [-D dict.zxd] [-T n] [-k] [-f] [-c] [-o out] file
//	zxcgo -d [-D dict.zxd] [-T n] [-k] [-f] [-c] [-o out] file.zxc
//	zxcgo -b seconds [-1..-7] [-B size] [-C] [-D dict.zxd] [-T n] file
//
// Compression writes file.zxc, decompression file without its .zxc suffix
// (file.out without one), unless -o names the output or -c sends it to
// standard output. As with zxc, the input is removed once the output is
// written, unless -k keeps it, and an existing output is only replaced with
// -f.
//
// -1 to -7 set the level, 3 by default. -B sets the block size, a power of
// 2 from 4K to 2M (suffixes K and M), 512K by default. Checksums are
// written, and verified on decompression, unless -N; with -b, as with zxc
// -b, only when -C asks for them. -S appends a seek table. -D gives the
// dictionary to compress with, or that the archive was compressed with.
// -T sets the number of goroutines, 0 (the default) for every CPU, 1 for a
// sequential run.
//
// -b compresses the file in memory repeatedly for the given number of
// seconds, then decompresses the archive likewise, checks that it gives
// the file back, and prints the throughputs of the best runs in MB/s of
// uncompressed data (1 MB = 10^6 bytes), as zxc -b does.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chmike/zxc-go"
)

func main() {
	var levels [8]*bool
	for l := 1; l <= 7; l++ {
		levels[l] = flag.Bool(strconv.Itoa(l), false, "compression level "+strconv.Itoa(l))
	}
	decompress := flag.Bool("d", false, "decompress")
	bench := flag.Float64("b", 0, "benchmark in memory for this many `seconds`")
	blockSize := flag.String("B", "512K", "block `size`, 4K to 2M")
	noChecksum := flag.Bool("N", false, "no checksums (compression), no verification (decompression)")
	checksum := flag.Bool("C", false, "checksums, the default except with -b")
	seekable := flag.Bool("S", false, "append a seek table")
	dictPath := flag.String("D", "", "`.zxd` dictionary")
	threads := flag.Int("T", 0, "goroutines (0 = all CPUs, 1 = sequential)")
	keep := flag.Bool("k", false, "keep the input file")
	force := flag.Bool("f", false, "replace an existing output file")
	stdout := flag.Bool("c", false, "write to standard output")
	output := flag.String("o", "", "output `file`")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: zxcgo [options] file\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	in := flag.Arg(0)

	level := 0
	for l := 1; l <= 7; l++ {
		if *levels[l] {
			level = l // the last one given wins, as with zxc
		}
	}
	bs, err := parseSize(*blockSize)
	if err != nil {
		fail(err)
	}
	// As with zxc: checksums unless -N, except that -b goes without them
	// unless -C asks for them.
	sums := !*noChecksum && (*bench == 0 || *checksum)
	opts := []zxc.Option{
		zxc.WithLevel(level), zxc.WithBlockSize(bs), zxc.WithChecksums(sums),
		zxc.WithSeekable(*seekable), zxc.WithParallel(*threads),
	}
	if *dictPath != "" {
		b, err := os.ReadFile(*dictPath)
		if err != nil {
			fail(err)
		}
		d, err := zxc.LoadDictionary(b)
		if err != nil {
			fail(fmt.Errorf("%s: %w", *dictPath, err))
		}
		opts = append(opts, zxc.WithDictionary(d))
	}

	src, err := os.ReadFile(in)
	if err != nil {
		fail(err)
	}
	if *bench > 0 {
		runBench(in, src, opts, time.Duration(*bench*float64(time.Second)))
		return
	}

	var out []byte
	name := *output
	if *decompress {
		out, err = zxc.Decompress(src, opts...)
		if name == "" {
			name = strings.TrimSuffix(in, ".zxc")
			if name == in {
				name = in + ".out"
			}
		}
	} else {
		out, err = zxc.Compress(src, opts...)
		if name == "" {
			name = in + ".zxc"
		}
	}
	if err != nil {
		fail(fmt.Errorf("%s: %w", in, err))
	}
	if *stdout {
		if _, err := os.Stdout.Write(out); err != nil {
			fail(err)
		}
		return
	}
	if err := writeFile(name, out, *force); err != nil {
		fail(err)
	}
	if !*keep {
		if err := os.Remove(in); err != nil {
			fail(err)
		}
	}
}

// runBench measures compression, then decompression, in memory, each for
// d, and prints the best runs.
func runBench(name string, src []byte, opts []zxc.Option, d time.Duration) {
	var z []byte
	var err error
	cbest, citers := measure(d, func() {
		if z, err = zxc.AppendCompress(z[:0], src, opts...); err != nil {
			fail(err)
		}
	})
	var out []byte
	dbest, diters := measure(d, func() {
		if out, err = zxc.AppendDecompress(out[:0], z, opts...); err != nil {
			fail(err)
		}
	})
	if !bytes.Equal(out, src) {
		fail(errors.New("round trip failed: the decompressed data differ from the input"))
	}
	mbs := func(t time.Duration) float64 { return float64(len(src)) / t.Seconds() / 1e6 }
	fmt.Printf("%s: %d bytes\n", name, len(src))
	fmt.Printf("Compressed: %d bytes (ratio %.3f)\n", len(z), float64(len(src))/float64(max(len(z), 1)))
	fmt.Printf("Compress  : %.3f MB/s (%d iters)\n", mbs(cbest), citers)
	fmt.Printf("Decompress: %.3f MB/s (%d iters)\n", mbs(dbest), diters)
}

// measure runs f repeatedly for d, once at least, and returns the shortest
// run and the number of runs.
func measure(d time.Duration, f func()) (time.Duration, int) {
	best := time.Duration(1<<63 - 1)
	n := 0
	for start := time.Now(); n == 0 || time.Since(start) < d; n++ {
		t0 := time.Now()
		f()
		best = min(best, time.Since(t0))
	}
	return best, n
}

// parseSize parses a block size: bytes, or a number followed by K or M.
func parseSize(arg string) (int, error) {
	s, mult := arg, 1
	switch {
	case strings.HasSuffix(s, "K"), strings.HasSuffix(s, "k"):
		mult, s = 1<<10, s[:len(s)-1]
	case strings.HasSuffix(s, "M"), strings.HasSuffix(s, "m"):
		mult, s = 1<<20, s[:len(s)-1]
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid block size %q", arg)
	}
	return n * mult, nil
}

// writeFile writes b to name, refusing to replace a file unless force.
func writeFile(name string, b []byte, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !force {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(name, flags, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s exists; use -f to replace it", name)
		}
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "zxcgo:", err)
	os.Exit(1)
}
