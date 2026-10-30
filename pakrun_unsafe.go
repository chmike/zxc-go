//go:build !purego && !(amd64 || arm64)

package zxc

// pakRun runs the PAK fast path from sequence byte offset i, extras
// position e, and returns the new sequence offset, output and literal
// positions, and extras position. Here the fast path is pakFast, which
// reads no varint, so e comes back unchanged.
func pakRun(o *lzOutput, seqs, extras []byte, i, e int) (int, int, int, int) {
	i, d, l := pakFast(o, seqs, i)
	return i, d, l, e
}

// splRun runs the SPL fast path for offsets of width w bytes from
// sequence i, extras position e, and returns the new sequence index,
// output and literal positions, and extras position. Here the fast path is
// splFast8 or splFast16, which read no varint, so e comes back unchanged.
func splRun(o *lzOutput, tokens, offs, extras []byte, w, i, e int) (int, int, int, int) {
	var d, l int
	if w == 1 {
		i, d, l = splFast8(o, tokens, offs, i)
	} else {
		i, d, l = splFast16(o, tokens, offs, i)
	}
	return i, d, l, e
}
