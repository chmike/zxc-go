//go:build !purego && (amd64 || arm64)

package zxc

import "unsafe"

// pakState is the state the assembly PAK loop (pak_amd64.s, pak_arm64.s)
// reads on entry and writes back on exit. The assembly uses the field offsets in
// its comments; TestPakStateLayout checks them.
type pakState struct {
	out    unsafe.Pointer // 0: output window
	lits   unsafe.Pointer // 8: literal section
	seqs   unsafe.Pointer // 16: sequence words
	ext    unsafe.Pointer // 24: extras section
	nSeq   int            // 32: bytes of whole sequence words
	nExt   int            // 40: bytes of extras
	i      int            // 48: next sequence, byte offset into seqs
	d      int            // 56: output position
	l      int            // 64: literal position
	e      int            // 72: extras position
	limit  int            // 80: block end in out
	litEnd int            // 88: number of literals
}

// pakRunAsm decodes PAK sequences from st.i until it meets one it should
// not take, and leaves st at that sequence. See pak_amd64.s and
// pak_arm64.s. It runs only when havePakAsm is true.
//
//go:noescape
func pakRunAsm(st *pakState)

// pakRun runs the assembly PAK loop, or pakFast on a CPU without the
// instructions it needs, from sequence byte offset i, extras position e,
// and returns the new sequence offset, output and literal
// positions, and extras position.
//
// The loop takes every sequence, varints included, while it fits: it stops
// on a sequence that would pass the block size or the literals, an offset
// reaching before the window, or a varint that is malformed or runs past
// the extras. It leaves that sequence, extras position included, to the
// checked path in decodePAK, which reports the error if there is one.
//
// Proof of its accesses. The test below makes these invariants hold on
// entry, and the loop keeps them:
//
//	len(out) >= limit + wildPad     0 <= d <= limit
//	len(lits) >= litEnd + wildPad   0 <= l <= litEnd
//	0 <= i, i%4 == 0, nSeq = len(seqs) &^ 3, 0 <= e <= nExt = len(extras)
//
// The sequence word is read at seqs[i, i+3] with i < nSeq. A varint is read
// at extras[e, e+n) only after testing e+n <= nExt, n being the length its
// first byte announces (1 to 3; a longer prefix stops the loop). A
// sequence it then takes has d+ll+ml <= limit, l+ll <= litEnd and
// 1 <= off <= d+ll, with ll and ml below 2^22 from the varint bound, so
// the sums cannot wrap.
//
// The batch path gets the same three facts without testing them per
// sequence. It starts a batch only with i+16 <= nSeq, d <= limit - 4*513
// and l <= litEnd - 4*254, and leaves it for the single path on any
// varint, so each of its at most 4 sequences has ll <= 254 and
// ml <= 259 = 254+5: after k of them d grows by at most 513k and l by at
// most 254k, which keeps d+ll+ml <= limit and l+ll <= litEnd for the
// next. It tests off <= d+ll only while d < 65536 at the batch start;
// past that, off <= 65536 <= d already.
//
// Copies move 32 bytes at a time and pass their length by at most 31
// bytes:
//   - literals write out[d, d+ll+31] and read lits[l, l+ll+31];
//   - with d' = d+ll, the match writes out[d', d'+ml+31]; with off >= 32
//     it reads out[d'-off, d'-off+ml+31], each 32-byte read ending at or
//     before the write it feeds; with off < 32 it reads the 32 bytes at
//     out[d'-off] once, then stores a pattern built from its first off
//     bytes, which are already decoded;
//
// and d+ll+31 <= limit+31, d'+ml+31 <= limit+31, l+ll+31 <= litEnd+31 keep
// all of it inside out and lits.
func pakRun(o *lzOutput, seqs, extras []byte, i, e int) (int, int, int, int) {
	st := pakState{
		out:    unsafe.Pointer(unsafe.SliceData(o.out)),
		lits:   unsafe.Pointer(unsafe.SliceData(o.lits)),
		seqs:   unsafe.Pointer(unsafe.SliceData(seqs)),
		ext:    unsafe.Pointer(unsafe.SliceData(extras)),
		nSeq:   len(seqs) &^ 3,
		nExt:   len(extras),
		i:      i,
		d:      o.d,
		l:      o.l,
		e:      e,
		limit:  o.limit,
		litEnd: o.litEnd,
	}
	if st.limit < 0 || st.d < 0 || st.d > st.limit || len(o.out) < st.limit+wildPad ||
		st.litEnd < 0 || st.l < 0 || st.l > st.litEnd || len(o.lits) < st.litEnd+wildPad ||
		i < 0 || i%4 != 0 || e < 0 || e > len(extras) {
		panic("zxc: pakRun invariants violated")
	}
	if !havePakAsm {
		i, d, l := pakFast(o, seqs, i)
		return i, d, l, e
	}
	if i < st.nSeq {
		pakRunAsm(&st)
	}
	return st.i, st.d, st.l, st.e
}

// splState is the state the assembly SPL loop (spl_amd64.s, spl_arm64.s)
// reads on entry and writes back on exit. The assembly uses the field
// offsets in its comments; TestSplStateLayout checks them.
type splState struct {
	out    unsafe.Pointer // 0: output window
	lits   unsafe.Pointer // 8: literals
	toks   unsafe.Pointer // 16: tokens
	ext    unsafe.Pointer // 24: extras section
	offs   unsafe.Pointer // 32: offsets
	nTok   int            // 40: number of tokens (sequences)
	nExt   int            // 48: bytes of extras
	i      int            // 56: next sequence
	d      int            // 64: output position
	l      int            // 72: literal position
	e      int            // 80: extras position
	limit  int            // 88: block end in out
	litEnd int            // 96: number of literals
	w      int            // 104: offset width, 1 or 2 bytes
}

// splRunAsm8 and splRunAsm16 decode SPL sequences with 1- and 2-byte
// offsets from st.i until they meet one they should not take, and leave st
// at that sequence. See spl_amd64.s and spl_arm64.s. They run only when
// havePakAsm is true.
//
//go:noescape
func splRunAsm8(st *splState)

//go:noescape
func splRunAsm16(st *splState)

// splRun runs the assembly SPL loop, or splFast8 and splFast16 on a CPU
// without the instructions it needs, for offsets of width w bytes from
// sequence i, extras position e, and returns the new sequence index,
// output and literal positions, and extras position.
//
// The loop is the PAK loop of pakRun with another way of reading a
// sequence: the token byte tokens[i] holds LL in its high nibble and ML-5
// in its low one, 15 announcing a varint in the extras for either, and the
// offset minus one is read at offs[w*i, w*i+w). The proof of pakRun
// carries over with these changes:
//   - tokens[i] is read with i < nTok = len(tokens), and offs[w*i,
//     w*i+w) with len(offs) >= w*nTok, which the entry test checks;
//   - without a varint, ll <= 14 and ml <= 19, so a batch of 4 sequences
//     needs d <= limit - 4*33 and l <= litEnd - 4*14;
//   - offsets are at most 65536 with either width, so the offset test can
//     go once d >= 65536, as in PAK.
func splRun(o *lzOutput, tokens, offs, extras []byte, w, i, e int) (int, int, int, int) {
	if !havePakAsm {
		var d, l int
		if w == 1 {
			i, d, l = splFast8(o, tokens, offs, i)
		} else {
			i, d, l = splFast16(o, tokens, offs, i)
		}
		return i, d, l, e
	}
	st := splState{
		out:    unsafe.Pointer(unsafe.SliceData(o.out)),
		lits:   unsafe.Pointer(unsafe.SliceData(o.lits)),
		toks:   unsafe.Pointer(unsafe.SliceData(tokens)),
		ext:    unsafe.Pointer(unsafe.SliceData(extras)),
		offs:   unsafe.Pointer(unsafe.SliceData(offs)),
		nTok:   len(tokens),
		nExt:   len(extras),
		i:      i,
		d:      o.d,
		l:      o.l,
		e:      e,
		limit:  o.limit,
		litEnd: o.litEnd,
		w:      w,
	}
	if st.limit < 0 || st.d < 0 || st.d > st.limit || len(o.out) < st.limit+wildPad ||
		st.litEnd < 0 || st.l < 0 || st.l > st.litEnd || len(o.lits) < st.litEnd+wildPad ||
		w != 1 && w != 2 || len(offs) < w*len(tokens) ||
		i < 0 || e < 0 || e > len(extras) {
		panic("zxc: splRun invariants violated")
	}
	if i < st.nTok {
		if w == 1 {
			splRunAsm8(&st)
		} else {
			splRunAsm16(&st)
		}
	}
	return st.i, st.d, st.l, st.e
}
