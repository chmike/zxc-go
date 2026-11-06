//go:build purego || !(arm64 || amd64)

package zxc

// No assembly parser here: the encoder runs in Go.
const havePakEncAsm = false

func (e *encoder) pakParseFast(src []byte, start int, p *lzParams) bool { return false }

func (e *encoder) splParseFast(src []byte, start int, p *lzParams) (uint16, bool) { return 0, false }

func (e *encoder) splitFast(toks []byte, offs []uint16, extras []byte, limit int) ([]byte, []uint16, []byte, bool) {
	return toks, offs, extras, false
}

func rleFast(dst, lits []byte, write bool) (int, []byte) {
	if write {
		at := len(dst)
		dst = appendRLE(dst, lits)
		return len(dst) - at, dst
	}
	return rleSize(lits), dst
}

func (e *encoder) optParseFast(src []byte, start int, p *lzParams, litCost uint32) bool { return false }
