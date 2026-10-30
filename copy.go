package zxc

import "encoding/binary"

// copy16, copy24 and copy32 move 16, 24 or 32 bytes from src to dst: all
// loads first, then all stores, so overlapping spans are copied as a block.
// Both slices must hold that many bytes.
//
// They are written with explicit 8-byte words because the compiler turns a
// [32]byte assignment into a DUFFCOPY through a stack temporary, several
// times slower here.
func copy16(dst, src []byte) {
	_, _ = src[15], dst[15]
	a := binary.LittleEndian.Uint64(src)
	b := binary.LittleEndian.Uint64(src[8:])
	binary.LittleEndian.PutUint64(dst, a)
	binary.LittleEndian.PutUint64(dst[8:], b)
}

func copy24(dst, src []byte) {
	_, _ = src[23], dst[23]
	a := binary.LittleEndian.Uint64(src)
	b := binary.LittleEndian.Uint64(src[8:])
	c := binary.LittleEndian.Uint64(src[16:])
	binary.LittleEndian.PutUint64(dst, a)
	binary.LittleEndian.PutUint64(dst[8:], b)
	binary.LittleEndian.PutUint64(dst[16:], c)
}

func copy32(dst, src []byte) {
	_, _ = src[31], dst[31]
	a := binary.LittleEndian.Uint64(src)
	b := binary.LittleEndian.Uint64(src[8:])
	c := binary.LittleEndian.Uint64(src[16:])
	e := binary.LittleEndian.Uint64(src[24:])
	binary.LittleEndian.PutUint64(dst, a)
	binary.LittleEndian.PutUint64(dst[8:], b)
	binary.LittleEndian.PutUint64(dst[16:], c)
	binary.LittleEndian.PutUint64(dst[24:], e)
}
