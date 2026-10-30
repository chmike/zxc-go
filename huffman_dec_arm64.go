//go:build !purego

package zxc

// The whole Huffman section decoder is in assembly on arm64
// (huffman_arm64.s), called through decodeFast.
const haveHufDecodeAsm = true

// hufDecodeAsm decodes the section of st; it returns 0 when done, nonzero
// when it hands the section back to the Go decoder.
//
//go:noescape
func hufDecodeAsm(st *hufState) int
