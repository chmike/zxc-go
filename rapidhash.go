package zxc

import (
	"encoding/binary"
	"math/bits"
)

// Port of rapidhash v3 by Nicolas De Carli (MIT licence), the block
// checksum of ZXC (§ 7.2), in the configuration the reference library
// builds: RAPIDHASH_COMPACT and RAPIDHASH_FAST, default secret.
// See https://github.com/Nicoshev/rapidhash.

var rapidSecret = [8]uint64{
	0x2d358dccaa6c78a5,
	0x8bb84b93962eacc9,
	0x4b33a62ed433d4a3,
	0x4d5a2da51de1aa47,
	0xa0761d6478bd642f,
	0xe7037ed1a0b428db,
	0x90ed1765281c388c,
	0xaaaaaaaaaaaaaaaa,
}

// rapidMum returns the low and high halves of the 128-bit product a*b.
func rapidMum(a, b uint64) (lo, hi uint64) {
	hi, lo = bits.Mul64(a, b)
	return lo, hi
}

// rapidMix returns the xor of the two halves of the 128-bit product a*b.
func rapidMix(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	return lo ^ hi
}

func le64(p []byte) uint64 { return binary.LittleEndian.Uint64(p) }
func le32(p []byte) uint64 { return uint64(binary.LittleEndian.Uint32(p)) }

// rapidhash returns the 64-bit rapidhash of p with the given seed.
func rapidhash(p []byte, seed uint64) uint64 {
	s := &rapidSecret
	seed ^= rapidMix(seed^s[2], s[1])
	var a, b uint64
	n := len(p)
	if n <= 16 {
		switch {
		case n >= 8:
			seed ^= uint64(n)
			a, b = le64(p), le64(p[n-8:])
		case n >= 4:
			seed ^= uint64(n)
			a, b = le32(p), le32(p[n-4:])
		case n > 0:
			a = uint64(p[0])<<45 | uint64(p[n-1])
			b = uint64(p[n>>1])
		}
		a ^= s[1]
		b ^= seed
		a, b = rapidMum(a, b)
		return rapidMix(a^s[7], b^s[1]^uint64(n))
	}

	// o is the read position, r the number of bytes left after it.
	o, r := 0, n
	if r > 112 {
		if haveRapidLoopAsm {
			seed, o = rapidLoopAsm(p, seed)
		} else {
			seed, o = rapidLoopGo(p, seed)
		}
		r = n - o
	}
	if r > 16 {
		q := p[o:]
		seed = rapidMix(le64(q[0:])^s[2], le64(q[8:])^seed)
		if r > 32 {
			seed = rapidMix(le64(q[16:])^s[2], le64(q[24:])^seed)
			if r > 48 {
				seed = rapidMix(le64(q[32:])^s[1], le64(q[40:])^seed)
				if r > 64 {
					seed = rapidMix(le64(q[48:])^s[1], le64(q[56:])^seed)
					if r > 80 {
						seed = rapidMix(le64(q[64:])^s[2], le64(q[72:])^seed)
						if r > 96 {
							seed = rapidMix(le64(q[80:])^s[1], le64(q[88:])^seed)
						}
					}
				}
			}
		}
	}
	// The last 16 bytes of the input. With r < 16 they reach back into
	// bytes already consumed, as in the C code (n > 16 here, so they exist).
	a = le64(p[n-16:]) ^ uint64(r)
	b = le64(p[n-8:])
	a ^= s[1]
	b ^= seed
	a, b = rapidMum(a, b)
	return rapidMix(a^s[7], b^s[1]^uint64(r))
}

// rapidLoopGo is the main loop of rapidhash, for len(p) > 112: seven
// independent lanes over 112-byte steps while more than 112 bytes remain,
// then folded into one. It returns the folded seed and the number of bytes
// consumed, which leaves 1 to 112 bytes. rapidLoopAsm, where the platform
// has one, computes the same thing.
func rapidLoopGo(p []byte, seed uint64) (uint64, int) {
	s := &rapidSecret
	see1, see2, see3 := seed, seed, seed
	see4, see5, see6 := seed, seed, seed
	o, r := 0, len(p)
	for {
		q := p[o : o+112]
		seed = rapidMix(le64(q[0:])^s[0], le64(q[8:])^seed)
		see1 = rapidMix(le64(q[16:])^s[1], le64(q[24:])^see1)
		see2 = rapidMix(le64(q[32:])^s[2], le64(q[40:])^see2)
		see3 = rapidMix(le64(q[48:])^s[3], le64(q[56:])^see3)
		see4 = rapidMix(le64(q[64:])^s[4], le64(q[72:])^see4)
		see5 = rapidMix(le64(q[80:])^s[5], le64(q[88:])^see5)
		see6 = rapidMix(le64(q[96:])^s[6], le64(q[104:])^see6)
		o += 112
		r -= 112
		if r <= 112 {
			break
		}
	}
	seed ^= see1
	see2 ^= see3
	see4 ^= see5
	seed ^= see6
	see2 ^= see4
	seed ^= see2
	return seed, o
}

// blockChecksum is the per-block checksum of § 7.2: rapidhash of the
// decoded block seeded with its position in the frame, folded to 32 bits.
func blockChecksum(block []byte, index uint64) uint32 {
	h := rapidhash(block, index)
	return uint32(h ^ h>>32)
}
