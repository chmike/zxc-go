//go:build purego || !(amd64 || arm64)

package zxc

// No assembly kernels here: the Huffman decoder runs in Go.
const haveHufAsm = false

func mergeFast(dst, ch []byte, l, r int, run []byte) (int, int, int) { return 0, l, r }

func flatFast(dst, run []byte, D uint8, tbl []byte) int { return 0 }

func (hd *hufDecoder) decodeFast(t *hufTree, body []byte, n int, out []byte) bool { return false }
