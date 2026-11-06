# zxc-go

A native Go encoder and decoder for the [ZXC](https://libzxc.org/)
compressed format, version 9. No cgo. The reference implementation, in C,
is [hellobertrand/zxc](https://github.com/hellobertrand/zxc).

The encoder writes the very same bytes as the reference library v0.15.0,
at every level and with every option. On amd64 and arm64 the hot loops
are in assembly; single-threaded, compression runs as fast as the C
library or faster at every level, and decompression within about 1 % of
it (see [Throughput](#throughput)). `-tags purego` builds a version in
plain, bounds-checked Go.

## Status

The decoder reads every archive the reference `zxc` 0.15 writes: all
levels (1 to 7), with or without checksums, dictionaries, seek tables and
concatenated frames. It passes the 17 valid and 34 invalid vectors of the
reference conformance suite.

The encoder covers the same features: levels 1 to 7, block sizes from
4 KiB to 2 MiB, checksums, dictionaries and seek tables, with the blocks
of a frame compressed in parallel. Its output is byte for byte that of
the reference library v0.15.0, which the tests check against the `zxc`
CLI of that version.

Checksums are written and verified by default (the `zxc` CLI writes them
by default too); `WithChecksums(false)`, `zxcgo -N` or
`unzxc -skip-checksums` turns them off. Archives written without
checksums are never verified. A seekable read verifies the checksums of
the blocks it decodes, never the archive digest.

## Usage

```sh
go get github.com/chmike/zxc-go
```

```go
import "github.com/chmike/zxc-go" // package zxc

archive, err := zxc.Compress(data)                  // level 3, 512 KiB blocks, checksums
archive, err = zxc.Compress(data, zxc.WithLevel(7)) // densest
out, err := zxc.Decompress(archive)

// Appending to a buffer, e.g. to reuse it from one call to the next.
buf, err = zxc.AppendCompress(buf[:0], data)
buf, err = zxc.AppendDecompress(buf[:0], archive)

// With a dictionary, e.g. one made by zxc; the archive then needs it.
zxd, _ := os.ReadFile("dictionary.zxd")
dict, err := zxc.LoadDictionary(zxd)
archive, err = zxc.Compress(data, zxc.WithDictionary(dict))
out, err = zxc.Decompress(archive, zxc.WithDictionary(dict))

// Random access into an archive with a seek table (zxc -S).
archive, err = zxc.Compress(data, zxc.WithSeekable(true))
s, err := zxc.OpenSeekable(archive) // implements io.ReaderAt
p := make([]byte, 4096)
n, err := s.ReadAt(p, 123456789)
```

Options, all optional; an option a function has no use for is ignored,
and when one is given twice the last one counts:

| Option | Default | Effect |
|---|---|---|
| `WithLevel(n)` | `3` | compression level, 1 (fastest) to 7 (densest); a level above 7 is taken as 7, as the reference library does |
| `WithBlockSize(n)` | 512 KiB | block size of compression, a power of 2 from 4 KiB to 2 MiB; any other size fails with `ErrBadBlockSize` |
| `WithChecksums(bool)` | `true` | write the block checksums and the archive digest; verify them on decompression |
| `WithSeekable(bool)` | `false` | append a seek table, which `OpenSeekable` needs |
| `WithDictionary(*Dictionary)` | none | the dictionary to compress with, or the one the archive was compressed with |
| `WithParallel(n)` | `runtime.GOMAXPROCS(0)` | goroutines compressing or decoding the blocks of a frame; 1 = sequential |

The blocks of a frame are independent, so the output and the errors are
the same whatever the number of goroutines: compression gives the same
archive, and a frame that does not decode cleanly in parallel (an error,
a frame with a dictionary) is decoded again sequentially, which reports
the error. `OpenSeekable` takes the same options; `WithParallel` has no
effect there, each `ReadAt` decoding its own blocks, and a `Seekable` is
safe for concurrent reads.

`zxc.ArchiveDictID` tells which dictionary an archive needs;
`zxc.NewRawDictionary` builds one from raw content, as the reference
library API accepts.

Command-line tools:

```sh
go install github.com/chmike/zxc-go/cmd/zxcgo@latest
zxcgo -5 file                   # compress to file.zxc, level 5; removes file unless -k
zxcgo -d file.zxc               # decompress to file
zxcgo -b 5 -1 file              # in-memory compression and decompression throughput
zxcgo -h                        # the other options, those of the zxc CLI

go install github.com/chmike/zxc-go/cmd/unzxc@latest
unzxc archive.zxc output              # decompress
unzxc -dict d.zxd archive.zxc output  # with a dictionary
unzxc -bench 5s archive.zxc           # in-memory throughput, all CPUs
unzxc -bench 5s -T 1 archive.zxc      # the same, single thread
```

`zxcgo` takes the options of the reference `zxc` CLI (`-1` to `-7`, `-d`,
`-b`, `-B`, `-N`, `-C`, `-S`, `-D`, `-T`, `-k`, `-f`, `-c`, `-o`), and its
`-b` output has the same format as `zxc -b`.

## Two builds

- Default build: the fast paths of the PAK and SPL decoders go through
  `unsafe` pointers, without Go's bounds checks (`fast_unsafe.go`), and on
  amd64 and arm64 the PAK and SPL loops, the Huffman sections and the
  rapidhash loop are in assembly, as are the encoder's parsers (each one
  the whole parse of a block, the match finder inline), its match
  splitting and its RLE literal coder. Each of these tests exactly the
  bounds of its accesses before making them; the comments in
  `fast_unsafe.go`, `pakrun_asm.go`, `huffman_asm.go`, `compress_asm.go`
  and the assembly files give the proofs, and the Go entry points check
  their invariants. On amd64 the decoder's assembly needs SSSE3 (and
  POPCNT for the Huffman sections, BMI2 for rapidhash), detected at run
  time, with a Go fallback; the encoder's needs SSE2 only.
- `-tags purego`: ordinary Go only, every access bounds-checked by Go
  (`fast_safe.go`); slower, for platforms or users that want no `unsafe`
  and no assembly.

Everything else (headers, slow paths, error handling, the encoder's
choices made once per block) is shared and checked in both builds. The
tests compare the fast paths and the assembly with reference decoders and
encoders that use only checked code.

## Throughput

Single thread, MB/s of uncompressed data (10^6 bytes), best of 5 s per
figure, measured with `bench/bench.sh`. Compression is measured with
`zxc -b` and `zxcgo -b`, without checksums (their `-b` default);
decompression with `bench/cbench.c`, a driver of the C buffer API, and
`unzxc`.

Inputs:

- corpus: 100 MiB of a tar of the Go source tree, made by the script;
- silesia: `silesia.tar` of the
  [Silesia corpus](https://sun.aei.polsl.pl/~sdeor/index.php?page=silesia),
  211957760 bytes.

Levels 1-2 use PAK blocks, 3-5 SPL blocks, 6 SPL blocks with
Huffman-coded literals, 7 with Huffman-coded literals and tokens.

### Compression

Apple M2: C v0.15.0, Apple clang 21.0.0, `-O3 -mcpu=native`; Go go1.27.3
darwin/arm64.

| Level | corpus C | Go | Go / C | purego / C | silesia C | Go | Go / C | purego / C |
|---|---|---|---|---|---|---|---|---|
| 1 | 727.5 | 798.1 | 109.7 % | 66.9 % | 844.6 | 936.9 | 110.9 % | 68.4 % |
| 2 | 560.2 | 619.3 | 110.6 % | 67.7 % | 555.0 | 620.5 | 111.8 % | 67.6 % |
| 3 | 278.6 | 280.6 | 100.7 % | 68.1 % | 252.6 | 252.9 | 100.1 % | 67.0 % |
| 4 | 215.2 | 217.8 | 101.2 % | 69.1 % | 183.8 | 183.2 | 99.7 % | 69.3 % |
| 5 | 136.6 | 137.4 | 100.6 % | 71.5 % | 110.1 | 110.7 | 100.6 % | 72.4 % |
| 6 | 15.9 | 16.6 | 104.1 % | 78.4 % | 14.1 | 14.7 | 104.7 % | 80.3 % |
| 7 | 11.1 | 11.5 | 103.4 % | 83.0 % | 9.4 | 9.6 | 102.7 % | 82.4 % |

AMD Ryzen AI 9 HX PRO 370, Linux: C v0.15.0, gcc 15.2.0,
`-O3 -march=native`; Go go1.27.3 linux/amd64.

| Level | corpus C | Go | Go / C | purego / C | silesia C | Go | Go / C | purego / C |
|---|---|---|---|---|---|---|---|---|
| 1 | 914.2 | 939.2 | 102.7 % | 63.1 % | 1087.4 | 1102.6 | 101.4 % | 63.3 % |
| 2 | 713.9 | 741.8 | 103.9 % | 62.7 % | 725.3 | 753.7 | 103.9 % | 62.4 % |
| 3 | 332.3 | 344.3 | 103.6 % | 66.9 % | 310.8 | 317.2 | 102.1 % | 66.3 % |
| 4 | 257.7 | 265.9 | 103.2 % | 68.4 % | 221.1 | 229.9 | 104.0 % | 68.2 % |
| 5 | 159.8 | 167.8 | 105.0 % | 73.7 % | 131.9 | 140.8 | 106.7 % | 74.6 % |
| 6 | 21.3 | 22.0 | 103.1 % | 78.5 % | 18.8 | 19.6 | 104.3 % | 79.1 % |
| 7 | 15.0 | 15.3 | 101.6 % | 80.9 % | 12.6 | 12.9 | 102.3 % | 81.1 % |

The figures vary by about 1 % from run to run.

### Decompression

Apple M2: C v0.15.0-35-g227ba53 (35 commits after v0.15.0), Apple clang
21.0.0, `-O3 -mcpu=native`; Go go1.27.3 darwin/arm64; the corpus,
compressed by the reference `zxc` CLI with its default options (checksums
on, 512 KiB blocks).

Checksums not verified:

| Level | Ratio | C | Go | Go / C | Go purego | purego / C |
|---|---|---|---|---|---|---|
| 1 | 1.886 | 10955 | 11185 | 102.1 % | 4833 | 44.1 % |
| 2 | 2.118 | 10050 | 10142 | 100.9 % | 4081 | 40.6 % |
| 3 | 2.558 | 8280 | 8235 | 99.5 % | 3079 | 37.2 % |
| 4 | 2.711 | 7903 | 7946 | 100.5 % | 2933 | 37.1 % |
| 5 | 2.912 | 7746 | 7825 | 101.0 % | 2932 | 37.9 % |
| 6 | 3.393 | 6062 | 6006 | 99.1 % | 2015 | 33.2 % |
| 7 | 3.651 | 5103 | 5123 | 100.4 % | 1491 | 29.2 % |

Checksums verified:

| Level | Ratio | C | Go | Go / C | Go purego | purego / C |
|---|---|---|---|---|---|---|
| 1 | 1.886 | 8952 | 9067 | 101.3 % | 4166 | 46.5 % |
| 2 | 2.118 | 8327 | 8395 | 100.8 % | 3637 | 43.7 % |
| 3 | 2.558 | 7074 | 7028 | 99.3 % | 2815 | 39.8 % |
| 4 | 2.711 | 6799 | 6837 | 100.6 % | 2696 | 39.7 % |
| 5 | 2.912 | 6675 | 6736 | 100.9 % | 2693 | 40.3 % |
| 6 | 3.393 | 5384 | 5345 | 99.3 % | 1898 | 35.3 % |
| 7 | 3.651 | 4616 | 4639 | 100.5 % | 1424 | 30.8 % |

The default Go build is within about 1 % of the C library at every level,
which is the run-to-run variation of these figures.

### Running the benchmark

`bench/bench.sh` measures the C library, the default Go build and the
`purego` build: decompression with and without checksum verification,
and compression. It needs Go, a C compiler, CMake and the reference
sources:

```sh
git clone https://github.com/hellobertrand/zxc ../zxc
cmake -S ../zxc -B ../zxc/build -DCMAKE_BUILD_TYPE=Release
cmake --build ../zxc/build -j
bench/bench.sh ../zxc                  # or: bench/bench.sh ZXC_DIR ZXC_BUILD_DIR
bench/bench.sh -m c ../zxc             # compression only (-m d: decompression only)
bench/bench.sh -i silesia.tar ../zxc   # another input than the corpus
```

It makes the corpus once (`zxcbench/corpus.bin`, the first 100 MiB of a
tar of the Go source tree of the toolchain in use), compresses it at
every level with the `zxc` CLI of the build directory, builds
`bench/cbench.c`, `unzxc` and `zxcgo`, then prints and saves a Markdown
report. The archives are kept per version of the C library and per input,
so that several versions can be measured on the same input.
`bench/bench.sh -h` lists the options.

## Tests

Copy `tests/conformance/v9` of the reference repository to `testdata/v9`,
or set `ZXC_CONFORMANCE_DIR`. The tests that compare the encoder's output
with the reference library need the `zxc` CLI of v0.15.0: put it at
`zxcbench/bin/zxc-v0.15.0-$GOARCH` (`$GOARCH` being `amd64` or `arm64`),
or set `ZXC_CLI` to it; without it they are skipped. Then:

```sh
go test ./...
go test -tags purego ./...
go test -fuzz FuzzDecompress -fuzztime 60s  # whole archives
go test -fuzz FuzzBlock -fuzztime 60s       # PAK/SPL block decoders
go test -fuzz FuzzPAK -fuzztime 60s         # PAK assembly vs reference
go test -fuzz FuzzSPL -fuzztime 60s         # SPL assembly vs reference
go test -fuzz FuzzHuffman -fuzztime 60s     # PivCo decoder vs reference walk
go test -fuzz FuzzParallel -fuzztime 60s    # parallel vs sequential decode
go test -fuzz FuzzSeekable -fuzztime 60s    # random access
go test -fuzz FuzzRapidLoop -fuzztime 60s   # rapidhash assembly vs Go
go test -fuzz FuzzCompress -fuzztime 60s    # compression round trip
go test -fuzz FuzzEncAsm -fuzztime 60s      # encoder assembly vs Go
ZXC_BENCH_FILE=archive.zxc go test -bench Decompress
```

Besides the conformance vectors, the Huffman tests run on random code
trees through a small PivCo encoder written from the specification, and
the Huffman and encoder assembly also runs against guard pages, which
fault on any read or write past the bounds the proofs allow.

## Source layout

| File | Content |
|---|---|
| `format.go` | constants, errors |
| `header.go` | file and block headers, footer, header checksums |
| `options.go` | `Option` and the `With...` functions |
| `decode.go` | `Decompress`, `AppendDecompress`, frame walk, block dispatch |
| `parallel.go` | blocks of a frame decoded by several goroutines |
| `lz.go` | PAK and SPL blocks, RLE literals |
| `fast_unsafe.go`, `fast_safe.go` | fast paths of the PAK/SPL loops: default, `-tags purego` |
| `pakrun_asm.go`, `pak_amd64.s`, `pak_arm64.s` | PAK loop in assembly |
| `spl_amd64.s`, `spl_arm64.s` | SPL loop in assembly |
| `pakrun_amd64.go`, `pakrun_arm64.go`, `pakrun_unsafe.go` | CPU feature tests; Go loop on other platforms |
| `huffman.go` | PivCo-Huffman sections |
| `huffman_asm.go`, `huffman_amd64.s`, `huffman_arm64.s` | Huffman section decoder and kernels in assembly |
| `huffman_dec_amd64.go`, `huffman_dec_arm64.go`, `huffman_noasm.go` | their feature tests and fallbacks |
| `rapidhash.go` | block checksums (rapidhash v3) |
| `rapidhash_amd64.s`, `rapidhash_arm64.s`, `rapidhash_*.go` | rapidhash main loop in assembly, Go fallback |
| `compress.go` | `Compress`, `AppendCompress`, frame, blocks, parallel compression |
| `compress_match.go` | match finder: hash tables, chains, level parameters |
| `compress_pak.go` | PAK blocks (levels 1-2) |
| `compress_spl.go` | SPL blocks (levels 3-7): lazy parser, match splitting, RLE and Huffman choices |
| `compress_opt.go` | optimal parser (levels 6-7) |
| `compress_huf.go` | Huffman code lengths and PivCo tables of the encoder |
| `compress_asm.go`, `compress_amd64.s`, `compress_arm64.s` | encoder parsers and kernels in assembly |
| `compress_noasm.go` | their fallbacks: the Go code runs |
| `copy.go`, `varint.go` | helpers |
| `dict.go` | dictionaries |
| `seek.go` | `Seekable`, random access |
| `cmd/zxcgo` | command-line tool: compression, decompression, benchmark |
| `cmd/unzxc` | command-line tool: decompression |
| `bench/` | benchmark script and C driver |

## License

BSD 3-Clause, as the reference library; see [LICENSE](LICENSE).
`rapidhash.go` and the rapidhash assembly are a port of
[rapidhash](https://github.com/Nicoshev/rapidhash) by Nicolas De Carli
(MIT license). The ZXC format and its reference implementation are by
Bertrand Lebonnois and contributors.
