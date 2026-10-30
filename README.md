# zxc-go

A native Go decoder for the [ZXC](https://libzxc.org/) compressed format,
version 9. No cgo. The reference implementation, in C, is
[hellobertrand/zxc](https://github.com/hellobertrand/zxc).

On amd64 and arm64 the hot loops are in assembly, and single-threaded
decoding runs as fast as the C library, or slightly faster, at every
level (see [Throughput](#throughput)). `-tags purego` builds a version in
plain, bounds-checked Go.

## Status

The decoder reads every archive the reference `zxc` 0.15 writes: all
levels (1 to 7), with or without checksums, dictionaries, seek tables and
concatenated frames. It passes the 17 valid and 34 invalid vectors of the
reference conformance suite.

Checksums are verified by default when the archive carries them (the
`zxc` CLI writes them by default); `WithChecksums(false)` or
`unzxc -skip-checksums` turns verification off. A seekable read verifies
the checksums of the blocks it decodes, never the archive digest.

There is no encoder.

## Usage

```sh
go get github.com/chmike/zxc-go
```

```go
import "github.com/chmike/zxc-go" // package zxc

out, err := zxc.Decompress(archive)

// Appending to a buffer, e.g. to reuse it from one archive to the next.
buf, err = zxc.AppendDecompress(buf[:0], archive)

// An archive compressed with zxc -D needs its dictionary.
zxd, _ := os.ReadFile("dictionary.zxd")
dict, err := zxc.LoadDictionary(zxd)
out, err = zxc.Decompress(archive, zxc.WithDictionary(dict))

// Random access into an archive compressed with zxc -S.
s, err := zxc.OpenSeekable(archive) // implements io.ReaderAt
p := make([]byte, 4096)
n, err := s.ReadAt(p, 123456789)
```

Options, all optional; without them `Decompress` verifies the checksums
the archive carries, uses no dictionary and decodes on all CPUs:

| Option | Default | Effect |
|---|---|---|
| `WithChecksums(bool)` | `true` | verify the block checksums and the archive digest |
| `WithDictionary(*Dictionary)` | none | the dictionary the archive was compressed with |
| `WithParallel(n)` | `runtime.GOMAXPROCS(0)` | goroutines decoding the blocks of a frame; 1 = sequential |

The blocks of a frame are independent, so the output and the errors are
the same whatever the number of goroutines: a frame that does not decode
cleanly in parallel (an error, a frame with a dictionary) is decoded again
sequentially, which reports the error. `OpenSeekable` takes the same
options; `WithParallel` has no effect there, each `ReadAt` decoding its
own blocks, and a `Seekable` is safe for concurrent reads.

`zxc.ArchiveDictID` tells which dictionary an archive needs;
`zxc.NewRawDictionary` builds one from raw content, as the reference
library API accepts.

Command-line tool:

```sh
go install github.com/chmike/zxc-go/cmd/unzxc@latest
unzxc archive.zxc output              # decompress
unzxc -dict d.zxd archive.zxc output  # with a dictionary
unzxc -bench 5s archive.zxc           # in-memory throughput, all CPUs
unzxc -bench 5s -T 1 archive.zxc      # the same, single thread
```

## Two builds

- Default build: the fast paths of the PAK and SPL decoders go through
  `unsafe` pointers, without Go's bounds checks (`fast_unsafe.go`), and on
  amd64 and arm64 the PAK and SPL loops, the Huffman sections and the
  rapidhash loop are in assembly. Each of these tests exactly the bounds of
  its accesses before making them; the comments in `fast_unsafe.go`,
  `pakrun_asm.go`, `huffman_asm.go` and the assembly files give the
  proofs, and the Go entry points check their invariants. On amd64 the
  assembly needs SSSE3 (and POPCNT for the Huffman sections, BMI2 for
  rapidhash), detected at run time, with a Go fallback.
- `-tags purego`: ordinary Go only, every access bounds-checked by Go
  (`fast_safe.go`); slower, for platforms or users that want no `unsafe`
  and no assembly.

Everything else (headers, slow paths, error handling) is shared and
checked in both builds. The tests compare the fast paths and the assembly
with reference decoders that use only checked code.

## Throughput

Single thread, Apple M2, MB/s of decompressed output, best of 5 s per
figure, measured with `bench/bench.sh`:

- C: reference library at v0.15.0-35-g227ba53 (35 commits after v0.15.0),
  Apple clang 21.0.0, `-O3 -mcpu=native`;
- Go: go1.27.3 darwin/arm64;
- corpus: 100 MiB of a tar of the Go source tree, compressed by the
  reference `zxc` CLI with its default options (checksums on, 512 KiB
  blocks).

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

Levels 1-2 use PAK blocks, 3-5 SPL blocks, 6 SPL blocks with
Huffman-coded literals, 7 with Huffman-coded literals and tokens.

### Running the benchmark

`bench/bench.sh` measures the C library, the default Go build and the
`purego` build, with and without checksum verification, on a machine with
Go, a C compiler, CMake and the reference sources:

```sh
git clone https://github.com/hellobertrand/zxc ../zxc
cmake -S ../zxc -B ../zxc/build -DCMAKE_BUILD_TYPE=Release
cmake --build ../zxc/build -j
bench/bench.sh ../zxc            # or: bench/bench.sh ZXC_DIR ZXC_BUILD_DIR
```

It makes the corpus once (`zxcbench/corpus.bin`, the first 100 MiB of a
tar of the Go source tree of the toolchain in use), compresses it at
every level with the `zxc` CLI of the build directory, builds
`bench/cbench.c` (a single-thread driver of the C buffer API) and
`unzxc`, then prints and saves a Markdown report. The archives are kept
per version of the C library, so that several versions can be measured
on the same corpus. `bench/bench.sh -h` lists the options.

## Tests

Copy `tests/conformance/v9` of the reference repository to `testdata/v9`,
or set `ZXC_CONFORMANCE_DIR`, then:

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
ZXC_BENCH_FILE=archive.zxc go test -bench Decompress
```

Besides the conformance vectors, the Huffman tests run on random code
trees through a small PivCo encoder written from the specification, and
the Huffman assembly also runs against guard pages, which fault on any
read or write past the bounds the proofs allow.

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
| `copy.go`, `varint.go` | helpers |
| `dict.go` | dictionaries |
| `seek.go` | `Seekable`, random access |
| `cmd/unzxc` | command-line tool |
| `bench/` | benchmark script and C driver |

## License

BSD 3-Clause, as the reference library; see [LICENSE](LICENSE).
`rapidhash.go` and the rapidhash assembly are a port of
[rapidhash](https://github.com/Nicoshev/rapidhash) by Nicolas De Carli
(MIT license). The ZXC format and its reference implementation are by
Bertrand Lebonnois and contributors.
