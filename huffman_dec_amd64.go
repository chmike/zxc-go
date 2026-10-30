//go:build !purego

package zxc

// The whole Huffman section decoder is in assembly on amd64
// (huffman_amd64.s), called through decodeFast. Besides the SSSE3 of the
// kernels, it counts bits with POPCNT (CPUID leaf 1, ECX bit 23), which
// every x86-64 CPU with SSSE3 since about 2008 has; without both, decode
// keeps its Go passes.
var haveHufDecodeAsm = havePakAsm && func() bool {
	_, _, ecx, _ := cpuid(1, 0)
	return ecx&(1<<23) != 0
}()

// hufDecodeAsm decodes the section of st; it returns 0 when done, nonzero
// when it hands the section back to the Go decoder.
//
//go:noescape
func hufDecodeAsm(st *hufState) int
