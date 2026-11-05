#!/usr/bin/env bash
# bench.sh: single-thread decompression benchmark of zxc-go against the
# reference C library, at every level, with and without checksum
# verification, for the default Go build (assembly) and -tags purego.
#
# Usage:
#   bench/bench.sh [-s seconds] [-l "levels"] [-w workdir] ZXC_DIR [ZXC_BUILD_DIR]
#
#   ZXC_DIR        source tree of the C library (https://github.com/hellobertrand/zxc):
#                  its headers are taken from ZXC_DIR/include
#   ZXC_BUILD_DIR  its CMake build directory, holding libzxc.a and the zxc
#                  CLI (default ZXC_DIR/build), made for example with
#                    cmake -S ZXC_DIR -B ZXC_DIR/build -DCMAKE_BUILD_TYPE=Release
#                    cmake --build ZXC_DIR/build -j
#   -s seconds     duration of each measurement (default 5)
#   -l "levels"    levels to measure (default "1 2 3 4 5 6 7")
#   -w workdir     where the corpus, archives, binaries and results go
#                  (default ./zxcbench)
#
# Environment: CC (default cc), CFLAGS (default -O3 plus -march=native, or
# -mcpu=native on arm64), GO (default go).
#
# The corpus, workdir/corpus.bin, is the first 100 MiB of a tar of the Go
# source tree of the Go toolchain in use; it is made once and kept: delete
# it to make a new one, which also deletes the archives made from it. The archives are made with the zxc CLI of the build
# directory, with its default options (checksums on, 512 KiB blocks), in a
# directory named after its version, so that several versions of the C
# library can be measured on the same corpus. Each throughput is the best
# of the runs made in the given time, in MB/s of decompressed output
# (10^6 bytes), as zxc -b and lzbench report it.
#
# Written for bash 3.2 (macOS) and later.

set -eu

seconds=5
levels="1 2 3 4 5 6 7"
work=zxcbench

usage() {
	sed -n '2,/^$/s/^# \{0,1\}//p' "$0" >&2
	exit 2
}

while getopts "s:l:w:h" opt; do
	case $opt in
	s) seconds=$OPTARG ;;
	l) levels=$OPTARG ;;
	w) work=$OPTARG ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] && [ $# -le 2 ] || usage

fail() {
	echo "bench.sh: $*" >&2
	exit 1
}

abspath() { (cd "$1" && pwd); }

zxc_dir=$(abspath "$1") || fail "no directory $1"
zxc_build=$(abspath "${2:-$zxc_dir/build}") || fail "no build directory ${2:-$zxc_dir/build}"
repo=$(abspath "$(dirname "$0")/..")
CC=${CC:-cc}
GO=${GO:-go}

[ -f "$zxc_dir/include/zxc.h" ] || fail "$zxc_dir/include/zxc.h not found: ZXC_DIR must be the zxc source tree"
lib=$(find "$zxc_build" -name libzxc.a -type f | head -n 1)
zxc=$(find "$zxc_build" -name zxc -type f -perm -u+x | head -n 1)
if [ -z "$lib" ] || [ -z "$zxc" ]; then
	fail "libzxc.a or the zxc CLI not found under $zxc_build; build them with
  cmake -S $zxc_dir -B $zxc_build -DCMAKE_BUILD_TYPE=Release
  cmake --build $zxc_build -j"
fi

if [ -z "${CFLAGS:-}" ]; then
	case $(uname -m) in
	arm64 | aarch64) CFLAGS="-O3 -mcpu=native" ;;
	*) CFLAGS="-O3 -march=native" ;;
	esac
fi

mkdir -p "$work"
work=$(abspath "$work")
bin=$work/bin
mkdir -p "$bin"

# The binaries.
# cbench follows the API of the library: decompression contexts after
# v0.15.0, an options struct before.
api=
if grep -q zxc_dctx_set_param "$zxc_dir"/include/*.h; then
	api=-DZXC_DCTX_API
fi
cbench=$bin/cbench-$("$GO" env GOARCH)
echo "building $(basename "$cbench") and unzxc ..."
# shellcheck disable=SC2086 # CFLAGS holds several flags
"$CC" $CFLAGS $api -I"$zxc_dir/include" "$repo/bench/cbench.c" "$lib" -lpthread -lm -o "$cbench"
(cd "$repo" && "$GO" build -o "$bin/unzxc" ./cmd/unzxc)
(cd "$repo" && "$GO" build -tags purego -o "$bin/unzxc-purego" ./cmd/unzxc)

# The corpus.
corpus=$work/corpus.bin
corpus_size=104857600
if [ ! -f "$corpus" ]; then
	goroot=$("$GO" env GOROOT)
	echo "making $corpus from $goroot/src ..."
	rm -rf "$work"/archives-*
	# head stops reading at 100 MiB, which ends tar with SIGPIPE: expected.
	(tar cf - -C "$goroot" src 2>/dev/null || true) | head -c $corpus_size >"$corpus.tmp"
	mv "$corpus.tmp" "$corpus"
fi
n=$(wc -c <"$corpus" | tr -d ' ')
[ "$n" -eq $corpus_size ] || echo "note: $corpus holds $n bytes, not $corpus_size"

# The archives, one directory per version of the zxc CLI.
version=$("$zxc" -V 2>&1 | head -n 1)
label=$(echo "$version" | sed -n 's/.* v\([0-9][0-9A-Za-z.+-]*\).*/\1/p')
[ -n "$label" ] || label=unknown
if git -C "$zxc_dir" rev-parse --git-dir >/dev/null 2>&1; then
	label=$(git -C "$zxc_dir" describe --always --dirty)
fi
arch=$work/archives-$label
mkdir -p "$arch"
for l in $levels; do
	a=$arch/corpus.l$l.zxc
	if [ ! -f "$a" ]; then
		echo "compressing level $l ..."
		"$zxc" -"$l" -k -f -q -o "$a" "$corpus"
	fi
done

# One measurement: prints the MB/s figure of a cbench or unzxc line.
mbs() {
	"$@" | sed -n 's/.*decompress \([0-9.]*\) MB\/s.*/\1/p'
}

pct() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.1f %%", 100 * a / b }'; }

cpu() {
	case $(uname -s) in
	Darwin) sysctl -n machdep.cpu.brand_string ;;
	*) sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo 2>/dev/null | head -n 1 ;;
	esac
}

zxcgo=$(git -C "$repo" describe --always --dirty 2>/dev/null || echo "not a git checkout")
out=$work/results-$label-$(date +%Y%m%d-%H%M%S).md
{
	echo "# zxc-go benchmark, $(date '+%Y-%m-%d %H:%M')"
	echo
	echo "- machine: $(uname -sm), $(cpu)"
	echo "- C: $version ($label), $("$CC" --version 2>&1 | head -n 1), cbench built with $CFLAGS"
	echo "- Go: $("$GO" version), zxc-go $zxcgo"
	echo "- corpus: $n bytes, best of ${seconds} s per figure, single thread, MB/s"
	echo
} >"$out"

table() { # title, then the rows
	{
		echo "## $1"
		echo
		echo "| Level | Ratio | C | Go | Go / C | Go purego | purego / C |"
		echo "|---|---|---|---|---|---|---|"
		cat
		echo
	} >>"$out"
}

rows_off=
rows_on=
for l in $levels; do
	a=$arch/corpus.l$l.zxc
	echo "measuring level $l ..."
	ratio=$(awk -v a="$n" -v b="$(wc -c <"$a" | tr -d ' ')" 'BEGIN { printf "%.3f", a / b }')
	c0=$(mbs "$cbench" "$a" 0 "$seconds")
	g0=$(mbs "$bin/unzxc" -bench "${seconds}s" -T 1 -skip-checksums "$a")
	p0=$(mbs "$bin/unzxc-purego" -bench "${seconds}s" -T 1 -skip-checksums "$a")
	c1=$(mbs "$cbench" "$a" 1 "$seconds")
	g1=$(mbs "$bin/unzxc" -bench "${seconds}s" -T 1 "$a")
	p1=$(mbs "$bin/unzxc-purego" -bench "${seconds}s" -T 1 "$a")
	rows_off="$rows_off| $l | $ratio | $c0 | $g0 | $(pct "$g0" "$c0") | $p0 | $(pct "$p0" "$c0") |
"
	rows_on="$rows_on| $l | $ratio | $c1 | $g1 | $(pct "$g1" "$c1") | $p1 | $(pct "$p1" "$c1") |
"
done
printf '%s' "$rows_off" | table "Checksums not verified"
printf '%s' "$rows_on" | table "Checksums verified"

echo
cat "$out"
echo "(saved in $out)"
