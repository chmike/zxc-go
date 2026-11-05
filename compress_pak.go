package zxc

import "encoding/binary"

// PAK block encoder (§ 5.3), levels 1 and 2: zxc_encode_block_ghi of the
// reference library.

// PAK sequence word fields (§ 5.3): literal length, match length minus
// lzMinMatch, offset minus 1; a length of pakLenMask (lz.go) or more
// stores pakLenMask and the excess goes to the extras as a varint.
const (
	pakLLShift = 24
	pakMLShift = 16
	pakOffMask = 0xFFFF
)

// appendPAK appends the block src[start:] as a PAK block, header included,
// src[:start] being the dictionary content, and reports false when a
// length cannot be coded, the block then going out RAW.
func (e *encoder) appendPAK(dst, src []byte, start int) ([]byte, bool) {
	p := lzParamTable[e.level]
	if p.minOffset > 1 && shortDistBound(src[start:]) {
		p.minOffset = 1
	}
	m := &e.m
	m.newBlock()
	m.seedDict(src, start, e.level >= 3)

	iend := len(src)
	ip, anchor := start, start
	searchLimit := iend - lzSearchMargin
	lits, seqs, extras := e.lits[:0], e.seqs[:0], e.extras[:0]
	ok := true

	for ip < searchLimit {
		step := p.stepBase + (ip-anchor)>>p.stepShift
		if ip+step >= searchLimit {
			step = 1
		}
		mt := m.findBestMatch(src, ip, iend, searchLimit, anchor, e.level, &p, 0)
		if mt.ref < 0 {
			ip += step
			continue
		}
		ip -= mt.backtrack
		ll := ip - anchor
		ml := mt.len - lzMinMatch
		off := ip - mt.ref
		lits = append(lits, src[anchor:ip]...)
		seqs = append(seqs, uint32(min(ll, pakLenMask))<<pakLLShift|
			uint32(min(ml, pakLenMask))<<pakMLShift|uint32(off-1)&pakOffMask)
		if ll >= pakLenMask {
			extras, ok = appendVarint(extras, uint32(ll-pakLenMask))
		}
		if ok && ml >= pakLenMask {
			extras, ok = appendVarint(extras, uint32(ml-pakLenMask))
		}
		if !ok {
			break
		}
		ip += mt.len
		anchor = ip
	}
	e.lits, e.seqs, e.extras = lits, seqs, extras
	if !ok {
		return dst, false
	}
	lits = append(lits, src[anchor:]...)
	e.lits = lits

	// [header 8][sub-header 12][literals][sequence words][extras][padding]
	// The padding makes the sections behind the literals span 32 bytes at
	// least, for the decoder's wide literal copies.
	behind := 4*len(seqs) + len(extras)
	pad := max(litSlack-behind, 0)
	payload := 12 + len(lits) + behind + pad
	h := makeBlockHeader(blockPAK, uint32(payload))
	dst = append(dst, h[:]...)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(seqs)))
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(lits)))
	dst = append(dst, encRAW, 0, 0, 0) // literal, token, match length and offset encodings
	dst = append(dst, lits...)
	for _, s := range seqs {
		dst = binary.LittleEndian.AppendUint32(dst, s)
	}
	dst = append(dst, extras...)
	dst = append(dst, make([]byte, pad)...)
	return dst, true
}
