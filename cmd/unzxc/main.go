// Command unzxc decompresses a ZXC archive with the native Go decoder.
//
//	unzxc [-skip-checksums] [-dict file.zxd] [-T n] archive.zxc [output]
//	unzxc -bench 5s [-T n] archive.zxc
//
// -dict gives the .zxd dictionary an archive was compressed with
// (zxc -D); as with zxc, it is never looked up automatically.
//
// -T sets the number of goroutines that decode the blocks of a frame:
// 0, the default, uses every CPU; 1 decodes sequentially.
//
// Without an output file it writes to standard output. With -bench it
// decodes the archive in memory repeatedly for the given duration and
// prints the throughput in MB/s of decompressed output (1 MB = 10^6 bytes,
// as zxc -b and lzbench report it), with the best of the runs.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/chmike/zxc-go"
)

func main() {
	bench := flag.Duration("bench", 0, "benchmark in-memory decoding for this long")
	skip := flag.Bool("skip-checksums", false, "do not verify checksums")
	dictPath := flag.String("dict", "", "`.zxd` dictionary the archive was compressed with")
	threads := flag.Int("T", 0, "goroutines decoding the blocks (0 = all CPUs, 1 = sequential)")
	flag.Parse()
	if flag.NArg() < 1 || flag.NArg() > 2 {
		fmt.Fprintln(os.Stderr, "usage: unzxc [-bench 5s] [-skip-checksums] [-dict file.zxd] [-T n] archive.zxc [output]")
		os.Exit(2)
	}
	src, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fail(err)
	}
	opts := []zxc.Option{zxc.WithChecksums(!*skip), zxc.WithParallel(*threads)}
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
	out, err := zxc.Decompress(src, opts...)
	if err != nil {
		fail(err)
	}

	if *bench > 0 {
		iters := 0
		best := time.Duration(1<<63 - 1)
		for start := time.Now(); time.Since(start) < *bench; iters++ {
			t0 := time.Now()
			if out, err = zxc.AppendDecompress(out[:0], src, opts...); err != nil {
				fail(err)
			}
			best = min(best, time.Since(t0))
		}
		fmt.Printf("%s: %d -> %d bytes (ratio %.3f), decompress %.1f MB/s (best of %d)\n",
			flag.Arg(0), len(src), len(out), float64(len(out))/float64(len(src)),
			float64(len(out))/best.Seconds()/1e6, iters)
		return
	}

	w := os.Stdout
	if flag.NArg() == 2 {
		if w, err = os.Create(flag.Arg(1)); err != nil {
			fail(err)
		}
	}
	if _, err := w.Write(out); err != nil {
		fail(err)
	}
	if err := w.Close(); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "unzxc:", err)
	os.Exit(1)
}
