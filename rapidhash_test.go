package zxc

import "testing"

// rapidhashInput is the deterministic buffer the reference vectors below
// were computed on with the C rapidhash.h of the zxc repository
// (xorshift64 bytes, seed 0x123456789abcdef).
func rapidhashInput() []byte {
	buf := make([]byte, 4096)
	x := uint64(0x123456789abcdef)
	for i := range buf {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		buf[i] = byte(x)
	}
	return buf
}

// Lengths chosen at every branch boundary of rapidhash: 4, 8, 16, the
// 16-byte steps up to 112, the 112-byte loop and its remainders.
var rapidhashVectors = []struct {
	n          int
	seed, want uint64
}{
	{0, 0, 0x338dc4be2cecdae},
	{0, 0x7, 0x4e02fb0b4ea60a26},
	{0, 0x9e3779b97f4a7c15, 0xe173cb3d9efa2720},
	{1, 0, 0x17d43752fad7b371},
	{1, 0x7, 0xb240f6891a20c091},
	{1, 0x9e3779b97f4a7c15, 0xd1c0679b11be29b3},
	{3, 0, 0x41cb56c0f418e9bc},
	{3, 0x7, 0x3b2afb364d4c475d},
	{3, 0x9e3779b97f4a7c15, 0x41d9f25be14206e3},
	{4, 0, 0xa83387c822911ae7},
	{4, 0x7, 0x19a127385fc79ace},
	{4, 0x9e3779b97f4a7c15, 0x4bbff826b7734b03},
	{7, 0, 0xdbdbece98be2e663},
	{7, 0x7, 0x4ac27e23671c43e4},
	{7, 0x9e3779b97f4a7c15, 0xa0b6e2184a5a1d85},
	{8, 0, 0xfe55d07d5ecb6044},
	{8, 0x7, 0x32826a4ba212935b},
	{8, 0x9e3779b97f4a7c15, 0x2810f42acec48f65},
	{15, 0, 0x39e563d74a2b836e},
	{15, 0x7, 0x913882154626a73e},
	{15, 0x9e3779b97f4a7c15, 0x5e5bec2e3a41d612},
	{16, 0, 0x8770dfdeb742eb5d},
	{16, 0x7, 0xf17bcb483ff57bde},
	{16, 0x9e3779b97f4a7c15, 0xda702de22d0e6c40},
	{17, 0, 0xec93b63de0deace1},
	{17, 0x7, 0x515160da2ec5ce0b},
	{17, 0x9e3779b97f4a7c15, 0x7ae513c78ece984a},
	{32, 0, 0x3356dcb5b21044ea},
	{32, 0x7, 0x89ca268123072d90},
	{32, 0x9e3779b97f4a7c15, 0x9e587eda9bd87c60},
	{33, 0, 0x1a0cd5da5ad2a6c1},
	{33, 0x7, 0x2f47579b580ef8ad},
	{33, 0x9e3779b97f4a7c15, 0x9acf9bf279cf2763},
	{48, 0, 0x5a9afd4e3b9d1b5f},
	{48, 0x7, 0x41a60f99ad356155},
	{48, 0x9e3779b97f4a7c15, 0x925561fa01c4b58b},
	{49, 0, 0x20bbbfad3fd5df5a},
	{49, 0x7, 0x22eacac18fa4d871},
	{49, 0x9e3779b97f4a7c15, 0xa657d59e9ce70ec1},
	{64, 0, 0x260ff83d12464890},
	{64, 0x7, 0xdd7f19388000a87d},
	{64, 0x9e3779b97f4a7c15, 0x4acb568d6ffb0e0f},
	{65, 0, 0x2e81e304e2b0db9d},
	{65, 0x7, 0xee9fc8f92310cb95},
	{65, 0x9e3779b97f4a7c15, 0x9ab8c4c31c245686},
	{80, 0, 0xf1ff70490c52f254},
	{80, 0x7, 0x9530b398ceb397cf},
	{80, 0x9e3779b97f4a7c15, 0x7ce9780c52de3e6d},
	{81, 0, 0xc40ad12a9a214b91},
	{81, 0x7, 0xd2371629d9c8464f},
	{81, 0x9e3779b97f4a7c15, 0x37ed10b5855a28ae},
	{96, 0, 0x8c2ff9fd3b6fe891},
	{96, 0x7, 0xd0d26447638079bb},
	{96, 0x9e3779b97f4a7c15, 0x327d603480ffd9a9},
	{97, 0, 0x3fa880a6a16afad4},
	{97, 0x7, 0x255a760185781fb6},
	{97, 0x9e3779b97f4a7c15, 0xf9377977a490bb36},
	{112, 0, 0x6cc552d3904131da},
	{112, 0x7, 0x492bde665d08807b},
	{112, 0x9e3779b97f4a7c15, 0xdd44c599e7140d15},
	{113, 0, 0x97aab3ec565c8c54},
	{113, 0x7, 0x9d70a9384223be19},
	{113, 0x9e3779b97f4a7c15, 0x3fe71f330a5cdca5},
	{128, 0, 0x928f8fc611f4a5d9},
	{128, 0x7, 0xcd20161e14760a17},
	{128, 0x9e3779b97f4a7c15, 0xa2487fd646448e03},
	{224, 0, 0x2366d8c10d610313},
	{224, 0x7, 0x8b240ee659118b18},
	{224, 0x9e3779b97f4a7c15, 0x26c45d7bc7381db7},
	{225, 0, 0x5552878929149158},
	{225, 0x7, 0xcefdba34d071559b},
	{225, 0x9e3779b97f4a7c15, 0x9a3ee0e567cf717c},
	{226, 0, 0x8c39dc7e96e6961e},
	{226, 0x7, 0xdc1693d6d204321c},
	{226, 0x9e3779b97f4a7c15, 0xf4a1fba434dd1788},
	{240, 0, 0x14f2bdfe430e7d5d},
	{240, 0x7, 0xe58757c04cee487b},
	{240, 0x9e3779b97f4a7c15, 0x1c368e12246f279a},
	{337, 0, 0x6c7b4267d5c997ff},
	{337, 0x7, 0x388c23fb16790024},
	{337, 0x9e3779b97f4a7c15, 0x79611e89c071b47c},
	{500, 0, 0xac8396414a622bf0},
	{500, 0x7, 0xa7d1acb0494b0624},
	{500, 0x9e3779b97f4a7c15, 0x4bb86814ca6ae9b7},
	{600, 0, 0x894cc336bc8e8a57},
	{600, 0x7, 0xe3705b39e3aae205},
	{600, 0x9e3779b97f4a7c15, 0x6676091bb911e85f},
	{4096, 3, 0x594a8781b0f18fbd},
}

func TestRapidhash(t *testing.T) {
	buf := rapidhashInput()
	for _, v := range rapidhashVectors {
		if got := rapidhash(buf[:v.n], v.seed); got != v.want {
			t.Errorf("rapidhash(len %d, seed %#x) = %#x, want %#x", v.n, v.seed, got, v.want)
		}
	}
	// FORMAT.md § 14: block 0 of the worked example.
	if got := blockChecksum([]byte("Hello ZXC\n"), 0); got != 0x75A1BB90 {
		t.Errorf("blockChecksum(Hello ZXC) = %#08x, want 0x75a1bb90", got)
	}
}

func BenchmarkRapidhash(b *testing.B) {
	buf := make([]byte, 512<<10) // one default-size block
	copy(buf, rapidhashInput())
	b.SetBytes(int64(len(buf)))
	for range b.N {
		_ = rapidhash(buf, 1)
	}
}

// TestRapidLoopAsm holds the assembly main loop, where there is one, to
// the Go loop on every length from 113 to 3 steps past it, and every
// alignment of the start.
func TestRapidLoopAsm(t *testing.T) {
	if !haveRapidLoopAsm {
		t.Skip("no assembly main loop on this platform or CPU")
	}
	buf := rapidhashInput()
	for off := range 8 {
		for n := 113; n <= 4*112+16 && off+n <= len(buf); n++ {
			p := buf[off : off+n]
			for _, seed := range []uint64{0, 7, 0x9e3779b97f4a7c15} {
				gh, gn := rapidLoopGo(p, seed)
				ah, an := rapidLoopAsm(p, seed)
				if gh != ah || gn != an {
					t.Fatalf("off %d len %d seed %#x: asm (%#x, %d), Go (%#x, %d)", off, n, seed, ah, an, gh, gn)
				}
			}
		}
	}
}

// FuzzRapidLoop compares the assembly main loop with the Go one on
// arbitrary inputs.
func FuzzRapidLoop(f *testing.F) {
	f.Add(uint64(1), rapidhashInput()[:300])
	f.Fuzz(func(t *testing.T, seed uint64, p []byte) {
		if !haveRapidLoopAsm || len(p) <= 112 {
			return
		}
		gh, gn := rapidLoopGo(p, seed)
		ah, an := rapidLoopAsm(p, seed)
		if gh != ah || gn != an {
			t.Fatalf("len %d seed %#x: asm (%#x, %d), Go (%#x, %d)", len(p), seed, ah, an, gh, gn)
		}
	})
}

// BenchmarkRapidhashGo measures rapidhash with the main loop in Go, for
// comparison with BenchmarkRapidhash where the assembly is in use.
func BenchmarkRapidhashGo(b *testing.B) {
	buf := make([]byte, 512<<10)
	copy(buf, rapidhashInput())
	b.SetBytes(int64(len(buf)))
	for range b.N {
		s, o := rapidLoopGo(buf, 1)
		_ = s + uint64(o)
	}
}
