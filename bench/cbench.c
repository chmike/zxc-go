// cbench: single-thread benchmark of the reference ZXC decoder through the
// buffer API (zxc_decompress), measured like "unzxc -bench": the archive is
// loaded in memory, decoded repeatedly, and the best run is reported.
//
// Build:  bench/bench.sh builds it; by hand:
//         cc -O3 -march=native -I<zxc>/include cbench.c <zxc>/build/libzxc.a -lpthread -lm -o cbench
//         (on Apple Silicon: -mcpu=native instead of -march=native)
// Usage:  ./cbench archive.zxc [verify 0|1] [seconds]
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "zxc.h"

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s archive.zxc [verify 0|1] [seconds]\n", argv[0]);
        return 2;
    }
    const int verify = argc > 2 ? atoi(argv[2]) : 0;
    const double seconds = argc > 3 ? atof(argv[3]) : 3;

    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 1; }
    fseek(f, 0, SEEK_END);
    const long n = ftell(f);
    rewind(f);
    unsigned char* src = malloc(n);
    if (!src || fread(src, 1, n, f) != (size_t)n) { fprintf(stderr, "read failed\n"); return 1; }
    fclose(f);

    const uint64_t size = zxc_get_decompressed_size(src, n);
    const size_t cap = size + (4 << 20); // room for the wild-copy margin
    unsigned char* dst = malloc(cap);
    if (!dst) { fprintf(stderr, "out of memory\n"); return 1; }

    const zxc_decompress_opts_t opts = {.n_threads = 1, .checksum_enabled = verify};
    double best = 1e30;
    int iters = 0;
    int64_t r = 0;
    for (const double end = now() + seconds; now() < end; iters++) {
        const double t = now();
        r = zxc_decompress(src, n, dst, cap, &opts);
        const double d = now() - t;
        if (r < 0) { fprintf(stderr, "decompress error %lld\n", (long long)r); return 1; }
        if (d < best) best = d;
    }
    printf("%s: %ld -> %lld bytes, checksums %s, decompress %.1f MB/s (best of %d)\n",
           argv[1], n, (long long)r, verify ? "verified" : "skipped", r / best / 1e6, iters);
    return 0;
}
