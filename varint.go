package zxc

// readVarint decodes the prefix varint (§ 6) starting at e[i] and returns
// its value and the index just past it.
//
// The number of leading 1 bits of the first byte gives the number of bytes
// that follow. Only the 1-, 2- and 3-byte forms are defined in format v9;
// a longer prefix (first byte >= 0xE0) and a varint running past the end of
// the extras section are corrupt data.
func readVarint(e []byte, i int) (uint32, int, error) {
	if i >= len(e) {
		return 0, i, corruptf("varint past the extras section")
	}
	b0 := uint32(e[i])
	switch {
	case b0 < 0x80: // 0xxxxxxx
		return b0, i + 1, nil
	case b0 < 0xC0: // 10xxxxxx xxxxxxxx
		if i+2 > len(e) {
			return 0, i, corruptf("varint past the extras section")
		}
		return b0&0x3F | uint32(e[i+1])<<6, i + 2, nil
	case b0 < 0xE0: // 110xxxxx xxxxxxxx xxxxxxxx
		if i+3 > len(e) {
			return 0, i, corruptf("varint past the extras section")
		}
		return b0&0x1F | uint32(e[i+1])<<5 | uint32(e[i+2])<<13, i + 3, nil
	}
	return 0, i, corruptf("varint prefix %#02x longer than 3 bytes", b0)
}
