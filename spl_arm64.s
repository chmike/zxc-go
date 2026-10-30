//go:build !purego

#include "textflag.h"

// SPL sequence loop for arm64, called through splRun (pakrun_asm.go),
// which checks the invariants this code relies on; its comment and the one
// of pakRun give the proof of the accesses.
//
// The same loop as pak_arm64.s, batch and single paths, copies and short
// periods included, but for the way a sequence is read: the token byte
// holds LL in its high nibble and ML-5 in its low one, 15 announcing a
// varint for either, and the offset minus one comes from the offset
// stream, 1 byte wide (splRunAsm8) or 2 (splRunAsm16): one function per
// width, the two identical but for FETCH8 and FETCH16 and the stride of
// the offset pointer. A batch of 4 sequences needs 4*33 bytes of room in
// the output and 4*14 literals.
//
// A batch is unrolled and laid out like the reference decoder's: the
// common case of each of its 4 sequences runs straight through, with no
// taken branch, and the rare ones jump out of line and back, the offset
// test (before 64 KiB of output) and the short periods. The token and
// offset pointers advance once per batch; a sequence that leaves the batch
// sets them to itself on the way out and goes to the single path, the
// sequences before it staying done. A sequence without a varint has ll <=
// 14 and ml <= 19: one 16-byte copy moves its literals, one 32-byte copy
// its match, and a match of period below 32 is a single store of its
// 32-byte pattern. A sequence with a varint decodes it out of line, like
// the reference decoder: it stays in the batch if it leaves room for the r
// sequences after it, d+ll+ml <= limit - 33r and l+ll <= litEnd - 14r,
// which keeps the batch bounds of those, and copies with the loops of any
// length; otherwise, or on a malformed varint, it goes to the single path
// with the extras position it started from. A sequence whose only varint
// is on ml, the common case, takes a shorter path of its own (mvar): ll <=
// 14 keeps the 16-byte literal copy and the batch literal bound, a 1-byte
// varint is read in line, and the one test left is that the match leaves
// room for the sequences after it.
//
// Registers:
//   R0  *splState           R8  &out[d]          R16 ll
//   R1  out                 R9  &lits[l]         R17 ml field (mb)
//   R2  batch: nExt         R10 e                R19 off
//   R3  &offs[w*i]          R11 &out[limit]      R21 ml
//   R4  extras              R12 &lits[litEnd]
//   R5  &toks[nTok]         R13 &out[limit - 4*33], 0 if negative
//   R7  &toks[i]            R14 &lits[litEnd - 4*14], 0 if negative
//   R6  batch: offset test off (d >= 64 KiB); single: nExt, reloaded
//   R26 e at the start of a sequence with a varint
//   R15 token; R20 R22 R23 R24 R25 scratch; V0-V5 copies.

// FETCH8 and FETCH16 read the token at R7 into R16 (ll) and R17 (ml
// field), and the offset at R3, plus one, into R19: offs[i] or
// offs[2i, 2i+1].
#define FETCH8 \
	MOVBU	(R7), R15; \
	LSR	$4, R15, R16; \
	AND	$15, R15, R17; \
	MOVBU	(R3), R19; \
	ADD	$1, R19

#define FETCH16 \
	MOVBU	(R7), R15; \
	LSR	$4, R15, R16; \
	AND	$15, R15, R17; \
	MOVHU	(R3), R19; \
	ADD	$1, R19

// func splRunAsm8(st *splState)
TEXT ·splRunAsm8(SB), NOSPLIT, $0-8
	MOVD	st+0(FP), R0
	MOVD	0(R0), R1
	MOVD	24(R0), R4
	MOVD	80(R0), R10
	MOVD	16(R0), R24
	MOVD	40(R0), R5
	ADD	R24, R5
	MOVD	56(R0), R7
	ADD	R24, R7
	MOVD	32(R0), R3
	MOVD	56(R0), R25
	ADD	R25, R3
	MOVD	64(R0), R8
	ADD	R1, R8
	MOVD	8(R0), R25
	MOVD	72(R0), R9
	ADD	R25, R9
	MOVD	88(R0), R24
	ADD	R1, R24, R11
	SUBS	$(4*33), R24, R24
	ADD	R1, R24, R13
	CSEL	LT, ZR, R13, R13
	MOVD	96(R0), R24
	ADD	R25, R24, R12
	SUBS	$(4*14), R24, R24
	ADD	R25, R24, R14
	CSEL	LT, ZR, R14, R14
	MOVD	$65536, R22
	ADD	R1, R22

loop:
	CMP	R5, R7
	BHS	done

	// Batch of 4, if it fits.
	ADD	$4, R7, R24
	CMP	R5, R24
	BHI	single
	CMP	R13, R8
	BHI	single
	CMP	R14, R9
	BHI	single
	SUB	$4, R5, R6
	CMP	R22, R8
	BLO	pbatchseq

qbatchseq:
	// Batch past 64 KiB of output: no offset test.

	// Sequence 0 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVWU	(R7), R15
	UBFX	$4, R15, $4, R16
	UBFX	$0, R15, $4, R17
	CMP	$15, R16
	BEQ	qvar0
	CMP	$15, R17
	BEQ	qmvar0
	MOVBU	0(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
qok0:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qshort0
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
qdone0:
	ADD	R21, R8

	// Sequence 1 of the batch, straight-line: ll <= 14, ml <= 19.
	UBFX	$12, R15, $4, R16
	UBFX	$8, R15, $4, R17
	CMP	$15, R16
	BEQ	qvar1
	CMP	$15, R17
	BEQ	qmvar1
	MOVBU	1(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
qok1:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qshort1
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
qdone1:
	ADD	R21, R8

	// Sequence 2 of the batch, straight-line: ll <= 14, ml <= 19.
	UBFX	$20, R15, $4, R16
	UBFX	$16, R15, $4, R17
	CMP	$15, R16
	BEQ	qvar2
	CMP	$15, R17
	BEQ	qmvar2
	MOVBU	2(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
qok2:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qshort2
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
qdone2:
	ADD	R21, R8

	// Sequence 3 of the batch, straight-line: ll <= 14, ml <= 19.
	UBFX	$28, R15, $4, R16
	UBFX	$24, R15, $4, R17
	CMP	$15, R16
	BEQ	qvar3
	CMP	$15, R17
	BEQ	qmvar3
	MOVBU	3(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
qok3:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qshort3
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
qdone3:
	ADD	R21, R8
	ADD	$4, R7
	ADD	$4, R3
	CMP	R6, R7
	BHI	loop
	CMP	R13, R8
	BHI	loop
	CMP	R14, R9
	BLS	qbatchseq
	B	loop

qesc0:
	// A varint, or an offset to check: sequence 0 goes to the single path.
	ADD	$0, R7
	ADD	$0, R3
	B	single
qshort0:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	qdone0

qesc1:
	// A varint, or an offset to check: sequence 1 goes to the single path.
	ADD	$1, R7
	ADD	$1, R3
	B	single
qshort1:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	qdone1

qesc2:
	// A varint, or an offset to check: sequence 2 goes to the single path.
	ADD	$2, R7
	ADD	$2, R3
	B	single
qshort2:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	qdone2

qesc3:
	// A varint, or an offset to check: sequence 3 goes to the single path.
	ADD	$3, R7
	ADD	$3, R3
	B	single
qshort3:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	qdone3

qmvar0:
	// Sequence 0: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 3 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	qvfail0
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	qmvl0
	ADD	$1, R10
qmvv0:
	ADD	R20, R17
	MOVBU	0(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(3*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail0
qmvok0:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh0
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone0
	MOVD	$32, R24
qmvm0:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qmvm0
	B	qdone0
qmvl0:
	CMP	$0xC0, R20
	BLO	qmv20
	CMP	$0xE0, R20
	BHS	qvfail0
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qmvv0
qmv20:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qmvv0

qvar0:
	// Sequence 0 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 3 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	qvlo0
	CMP	R2, R10
	BGE	qvfail0
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qva0_1
	CMP	$0xC0, R20
	BLO	qva0_2
	CMP	$0xE0, R20
	BHS	qvfail0
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qva0_x
qva0_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qva0_x
qva0_1:
	ADD	$1, R10
qva0_x:
	ADD	R20, R16
qvlo0:
	CMP	$15, R17
	BNE	qvmo0
	CMP	R2, R10
	BGE	qvfail0
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qvb0_1
	CMP	$0xC0, R20
	BLO	qvb0_2
	CMP	$0xE0, R20
	BHS	qvfail0
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qvb0_x
qvb0_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qvb0_x
qvb0_1:
	ADD	$1, R10
qvb0_x:
	ADD	R20, R17
qvmo0:
	MOVBU	0(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(3*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail0
	SUB	R9, R12, R25
	SUB	$(3*14), R25
	CMP	R25, R16
	BGT	qvfail0
qvok0:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	qvld0
	MOVD	$32, R24
qvll0:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	qvll0
qvld0:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh0
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone0
	MOVD	$32, R24
qvml0:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qvml0
	B	qdone0
qvsh0:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
qvsl0:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	qvsl0
	B	qdone0
qvfail0:
	// Not here: the single path takes sequence 0, extras position restored.
	MOVD	R26, R10
	ADD	$0, R7
	ADD	$0, R3
	B	single

qmvar1:
	// Sequence 1: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 2 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	qvfail1
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	qmvl1
	ADD	$1, R10
qmvv1:
	ADD	R20, R17
	MOVBU	1(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(2*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail1
qmvok1:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh1
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone1
	MOVD	$32, R24
qmvm1:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qmvm1
	B	qdone1
qmvl1:
	CMP	$0xC0, R20
	BLO	qmv21
	CMP	$0xE0, R20
	BHS	qvfail1
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qmvv1
qmv21:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qmvv1

qvar1:
	// Sequence 1 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 2 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	qvlo1
	CMP	R2, R10
	BGE	qvfail1
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qva1_1
	CMP	$0xC0, R20
	BLO	qva1_2
	CMP	$0xE0, R20
	BHS	qvfail1
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qva1_x
qva1_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qva1_x
qva1_1:
	ADD	$1, R10
qva1_x:
	ADD	R20, R16
qvlo1:
	CMP	$15, R17
	BNE	qvmo1
	CMP	R2, R10
	BGE	qvfail1
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qvb1_1
	CMP	$0xC0, R20
	BLO	qvb1_2
	CMP	$0xE0, R20
	BHS	qvfail1
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qvb1_x
qvb1_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qvb1_x
qvb1_1:
	ADD	$1, R10
qvb1_x:
	ADD	R20, R17
qvmo1:
	MOVBU	1(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(2*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail1
	SUB	R9, R12, R25
	SUB	$(2*14), R25
	CMP	R25, R16
	BGT	qvfail1
qvok1:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	qvld1
	MOVD	$32, R24
qvll1:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	qvll1
qvld1:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh1
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone1
	MOVD	$32, R24
qvml1:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qvml1
	B	qdone1
qvsh1:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
qvsl1:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	qvsl1
	B	qdone1
qvfail1:
	// Not here: the single path takes sequence 1, extras position restored.
	MOVD	R26, R10
	ADD	$1, R7
	ADD	$1, R3
	B	single

qmvar2:
	// Sequence 2: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 1 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	qvfail2
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	qmvl2
	ADD	$1, R10
qmvv2:
	ADD	R20, R17
	MOVBU	2(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(1*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail2
qmvok2:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh2
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone2
	MOVD	$32, R24
qmvm2:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qmvm2
	B	qdone2
qmvl2:
	CMP	$0xC0, R20
	BLO	qmv22
	CMP	$0xE0, R20
	BHS	qvfail2
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qmvv2
qmv22:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qmvv2

qvar2:
	// Sequence 2 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 1 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	qvlo2
	CMP	R2, R10
	BGE	qvfail2
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qva2_1
	CMP	$0xC0, R20
	BLO	qva2_2
	CMP	$0xE0, R20
	BHS	qvfail2
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qva2_x
qva2_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qva2_x
qva2_1:
	ADD	$1, R10
qva2_x:
	ADD	R20, R16
qvlo2:
	CMP	$15, R17
	BNE	qvmo2
	CMP	R2, R10
	BGE	qvfail2
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qvb2_1
	CMP	$0xC0, R20
	BLO	qvb2_2
	CMP	$0xE0, R20
	BHS	qvfail2
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qvb2_x
qvb2_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qvb2_x
qvb2_1:
	ADD	$1, R10
qvb2_x:
	ADD	R20, R17
qvmo2:
	MOVBU	2(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(1*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail2
	SUB	R9, R12, R25
	SUB	$(1*14), R25
	CMP	R25, R16
	BGT	qvfail2
qvok2:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	qvld2
	MOVD	$32, R24
qvll2:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	qvll2
qvld2:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh2
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone2
	MOVD	$32, R24
qvml2:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qvml2
	B	qdone2
qvsh2:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
qvsl2:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	qvsl2
	B	qdone2
qvfail2:
	// Not here: the single path takes sequence 2, extras position restored.
	MOVD	R26, R10
	ADD	$2, R7
	ADD	$2, R3
	B	single

qmvar3:
	// Sequence 3: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 0 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	qvfail3
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	qmvl3
	ADD	$1, R10
qmvv3:
	ADD	R20, R17
	MOVBU	3(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(0*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail3
qmvok3:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh3
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone3
	MOVD	$32, R24
qmvm3:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qmvm3
	B	qdone3
qmvl3:
	CMP	$0xC0, R20
	BLO	qmv23
	CMP	$0xE0, R20
	BHS	qvfail3
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qmvv3
qmv23:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qmvv3

qvar3:
	// Sequence 3 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 0 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	qvlo3
	CMP	R2, R10
	BGE	qvfail3
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qva3_1
	CMP	$0xC0, R20
	BLO	qva3_2
	CMP	$0xE0, R20
	BHS	qvfail3
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qva3_x
qva3_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qva3_x
qva3_1:
	ADD	$1, R10
qva3_x:
	ADD	R20, R16
qvlo3:
	CMP	$15, R17
	BNE	qvmo3
	CMP	R2, R10
	BGE	qvfail3
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qvb3_1
	CMP	$0xC0, R20
	BLO	qvb3_2
	CMP	$0xE0, R20
	BHS	qvfail3
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qvb3_x
qvb3_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qvb3_x
qvb3_1:
	ADD	$1, R10
qvb3_x:
	ADD	R20, R17
qvmo3:
	MOVBU	3(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(0*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail3
	SUB	R9, R12, R25
	SUB	$(0*14), R25
	CMP	R25, R16
	BGT	qvfail3
qvok3:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	qvld3
	MOVD	$32, R24
qvll3:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	qvll3
qvld3:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh3
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone3
	MOVD	$32, R24
qvml3:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qvml3
	B	qdone3
qvsh3:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
qvsl3:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	qvsl3
	B	qdone3
qvfail3:
	// Not here: the single path takes sequence 3, extras position restored.
	MOVD	R26, R10
	ADD	$3, R7
	ADD	$3, R3
	B	single


pbatchseq:
	// Batch below 64 KiB of output: off > d+ll leaves a sequence to
	// the single path.

	// Sequence 0 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVWU	(R7), R15
	UBFX	$4, R15, $4, R16
	UBFX	$0, R15, $4, R17
	CMP	$15, R16
	BEQ	pvar0
	CMP	$15, R17
	BEQ	pmvar0
	MOVBU	0(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pesc0
pok0:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pshort0
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
pdone0:
	ADD	R21, R8

	// Sequence 1 of the batch, straight-line: ll <= 14, ml <= 19.
	UBFX	$12, R15, $4, R16
	UBFX	$8, R15, $4, R17
	CMP	$15, R16
	BEQ	pvar1
	CMP	$15, R17
	BEQ	pmvar1
	MOVBU	1(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pesc1
pok1:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pshort1
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
pdone1:
	ADD	R21, R8

	// Sequence 2 of the batch, straight-line: ll <= 14, ml <= 19.
	UBFX	$20, R15, $4, R16
	UBFX	$16, R15, $4, R17
	CMP	$15, R16
	BEQ	pvar2
	CMP	$15, R17
	BEQ	pmvar2
	MOVBU	2(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pesc2
pok2:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pshort2
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
pdone2:
	ADD	R21, R8

	// Sequence 3 of the batch, straight-line: ll <= 14, ml <= 19.
	UBFX	$28, R15, $4, R16
	UBFX	$24, R15, $4, R17
	CMP	$15, R16
	BEQ	pvar3
	CMP	$15, R17
	BEQ	pmvar3
	MOVBU	3(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pesc3
pok3:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pshort3
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
pdone3:
	ADD	R21, R8
	ADD	$4, R7
	ADD	$4, R3
	CMP	R6, R7
	BHI	loop
	CMP	R13, R8
	BHI	loop
	CMP	R14, R9
	BHI	loop
	CMP	R22, R8
	BLO	pbatchseq
	B	qbatchseq

pesc0:
	// A varint, or an offset to check: sequence 0 goes to the single path.
	ADD	$0, R7
	ADD	$0, R3
	B	single
pshort0:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	pdone0

pesc1:
	// A varint, or an offset to check: sequence 1 goes to the single path.
	ADD	$1, R7
	ADD	$1, R3
	B	single
pshort1:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	pdone1

pesc2:
	// A varint, or an offset to check: sequence 2 goes to the single path.
	ADD	$2, R7
	ADD	$2, R3
	B	single
pshort2:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	pdone2

pesc3:
	// A varint, or an offset to check: sequence 3 goes to the single path.
	ADD	$3, R7
	ADD	$3, R3
	B	single
pshort3:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	pdone3

pmvar0:
	// Sequence 0: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 3 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	pvfail0
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	pmvl0
	ADD	$1, R10
pmvv0:
	ADD	R20, R17
	MOVBU	0(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(3*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail0
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail0
pmvok0:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh0
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone0
	MOVD	$32, R24
pmvm0:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pmvm0
	B	pdone0
pmvl0:
	CMP	$0xC0, R20
	BLO	pmv20
	CMP	$0xE0, R20
	BHS	pvfail0
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pmvv0
pmv20:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pmvv0

pvar0:
	// Sequence 0 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 3 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	pvlo0
	CMP	R2, R10
	BGE	pvfail0
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pva0_1
	CMP	$0xC0, R20
	BLO	pva0_2
	CMP	$0xE0, R20
	BHS	pvfail0
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pva0_x
pva0_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pva0_x
pva0_1:
	ADD	$1, R10
pva0_x:
	ADD	R20, R16
pvlo0:
	CMP	$15, R17
	BNE	pvmo0
	CMP	R2, R10
	BGE	pvfail0
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pvb0_1
	CMP	$0xC0, R20
	BLO	pvb0_2
	CMP	$0xE0, R20
	BHS	pvfail0
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pvb0_x
pvb0_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pvb0_x
pvb0_1:
	ADD	$1, R10
pvb0_x:
	ADD	R20, R17
pvmo0:
	MOVBU	0(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(3*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail0
	SUB	R9, R12, R25
	SUB	$(3*14), R25
	CMP	R25, R16
	BGT	pvfail0
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail0
pvok0:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	pvld0
	MOVD	$32, R24
pvll0:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	pvll0
pvld0:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh0
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone0
	MOVD	$32, R24
pvml0:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pvml0
	B	pdone0
pvsh0:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
pvsl0:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	pvsl0
	B	pdone0
pvfail0:
	// Not here: the single path takes sequence 0, extras position restored.
	MOVD	R26, R10
	ADD	$0, R7
	ADD	$0, R3
	B	single

pmvar1:
	// Sequence 1: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 2 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	pvfail1
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	pmvl1
	ADD	$1, R10
pmvv1:
	ADD	R20, R17
	MOVBU	1(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(2*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail1
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail1
pmvok1:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh1
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone1
	MOVD	$32, R24
pmvm1:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pmvm1
	B	pdone1
pmvl1:
	CMP	$0xC0, R20
	BLO	pmv21
	CMP	$0xE0, R20
	BHS	pvfail1
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pmvv1
pmv21:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pmvv1

pvar1:
	// Sequence 1 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 2 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	pvlo1
	CMP	R2, R10
	BGE	pvfail1
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pva1_1
	CMP	$0xC0, R20
	BLO	pva1_2
	CMP	$0xE0, R20
	BHS	pvfail1
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pva1_x
pva1_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pva1_x
pva1_1:
	ADD	$1, R10
pva1_x:
	ADD	R20, R16
pvlo1:
	CMP	$15, R17
	BNE	pvmo1
	CMP	R2, R10
	BGE	pvfail1
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pvb1_1
	CMP	$0xC0, R20
	BLO	pvb1_2
	CMP	$0xE0, R20
	BHS	pvfail1
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pvb1_x
pvb1_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pvb1_x
pvb1_1:
	ADD	$1, R10
pvb1_x:
	ADD	R20, R17
pvmo1:
	MOVBU	1(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(2*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail1
	SUB	R9, R12, R25
	SUB	$(2*14), R25
	CMP	R25, R16
	BGT	pvfail1
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail1
pvok1:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	pvld1
	MOVD	$32, R24
pvll1:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	pvll1
pvld1:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh1
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone1
	MOVD	$32, R24
pvml1:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pvml1
	B	pdone1
pvsh1:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
pvsl1:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	pvsl1
	B	pdone1
pvfail1:
	// Not here: the single path takes sequence 1, extras position restored.
	MOVD	R26, R10
	ADD	$1, R7
	ADD	$1, R3
	B	single

pmvar2:
	// Sequence 2: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 1 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	pvfail2
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	pmvl2
	ADD	$1, R10
pmvv2:
	ADD	R20, R17
	MOVBU	2(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(1*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail2
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail2
pmvok2:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh2
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone2
	MOVD	$32, R24
pmvm2:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pmvm2
	B	pdone2
pmvl2:
	CMP	$0xC0, R20
	BLO	pmv22
	CMP	$0xE0, R20
	BHS	pvfail2
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pmvv2
pmv22:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pmvv2

pvar2:
	// Sequence 2 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 1 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	pvlo2
	CMP	R2, R10
	BGE	pvfail2
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pva2_1
	CMP	$0xC0, R20
	BLO	pva2_2
	CMP	$0xE0, R20
	BHS	pvfail2
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pva2_x
pva2_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pva2_x
pva2_1:
	ADD	$1, R10
pva2_x:
	ADD	R20, R16
pvlo2:
	CMP	$15, R17
	BNE	pvmo2
	CMP	R2, R10
	BGE	pvfail2
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pvb2_1
	CMP	$0xC0, R20
	BLO	pvb2_2
	CMP	$0xE0, R20
	BHS	pvfail2
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pvb2_x
pvb2_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pvb2_x
pvb2_1:
	ADD	$1, R10
pvb2_x:
	ADD	R20, R17
pvmo2:
	MOVBU	2(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(1*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail2
	SUB	R9, R12, R25
	SUB	$(1*14), R25
	CMP	R25, R16
	BGT	pvfail2
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail2
pvok2:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	pvld2
	MOVD	$32, R24
pvll2:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	pvll2
pvld2:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh2
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone2
	MOVD	$32, R24
pvml2:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pvml2
	B	pdone2
pvsh2:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
pvsl2:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	pvsl2
	B	pdone2
pvfail2:
	// Not here: the single path takes sequence 2, extras position restored.
	MOVD	R26, R10
	ADD	$2, R7
	ADD	$2, R3
	B	single

pmvar3:
	// Sequence 3: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 0 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	pvfail3
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	pmvl3
	ADD	$1, R10
pmvv3:
	ADD	R20, R17
	MOVBU	3(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(0*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail3
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail3
pmvok3:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh3
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone3
	MOVD	$32, R24
pmvm3:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pmvm3
	B	pdone3
pmvl3:
	CMP	$0xC0, R20
	BLO	pmv23
	CMP	$0xE0, R20
	BHS	pvfail3
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pmvv3
pmv23:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pmvv3

pvar3:
	// Sequence 3 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 0 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	pvlo3
	CMP	R2, R10
	BGE	pvfail3
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pva3_1
	CMP	$0xC0, R20
	BLO	pva3_2
	CMP	$0xE0, R20
	BHS	pvfail3
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pva3_x
pva3_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pva3_x
pva3_1:
	ADD	$1, R10
pva3_x:
	ADD	R20, R16
pvlo3:
	CMP	$15, R17
	BNE	pvmo3
	CMP	R2, R10
	BGE	pvfail3
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pvb3_1
	CMP	$0xC0, R20
	BLO	pvb3_2
	CMP	$0xE0, R20
	BHS	pvfail3
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pvb3_x
pvb3_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pvb3_x
pvb3_1:
	ADD	$1, R10
pvb3_x:
	ADD	R20, R17
pvmo3:
	MOVBU	3(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(0*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail3
	SUB	R9, R12, R25
	SUB	$(0*14), R25
	CMP	R25, R16
	BGT	pvfail3
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail3
pvok3:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	pvld3
	MOVD	$32, R24
pvll3:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	pvll3
pvld3:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh3
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone3
	MOVD	$32, R24
pvml3:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pvml3
	B	pdone3
pvsh3:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
pvsl3:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	pvsl3
	B	pdone3
pvfail3:
	// Not here: the single path takes sequence 3, extras position restored.
	MOVD	R26, R10
	ADD	$3, R7
	ADD	$3, R3
	B	single

single:
	FETCH8
	MOVD	R10, R26
	ADD	$5, R17, R21

	// LL == 15: add a varint from the extras.
	CMP	$15, R16
	BNE	llok
	MOVD	48(R0), R6 // nExt
	CMP	R6, R10
	BGE	exit
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	ll1
	CMP	$0xC0, R20
	BLO	ll2
	CMP	$0xE0, R20
	BHS	exit
	ADD	$3, R10, R24
	CMP	R6, R24
	BHI	exit
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	lladd
ll2:
	ADD	$2, R10, R24
	CMP	R6, R24
	BHI	exit
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	lladd
ll1:
	ADD	$1, R10
lladd:
	ADD	R20, R16

llok:
	// ML field == 15: add a varint from the extras.
	CMP	$15, R17
	BNE	mlok
	MOVD	48(R0), R6 // nExt
	CMP	R6, R10
	BGE	exit
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	ml1
	CMP	$0xC0, R20
	BLO	ml2
	CMP	$0xE0, R20
	BHS	exit
	ADD	$3, R10, R24
	CMP	R6, R24
	BHI	exit
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	mladd
ml2:
	ADD	$2, R10, R24
	CMP	R6, R24
	BHI	exit
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	mladd
ml1:
	ADD	$1, R10
mladd:
	ADD	R20, R21

mlok:
	// off > d+ll, ll+ml > limit-d or ll > litEnd-l: leave it to decodeSPL.
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	exit
	SUB	R8, R11, R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BHI	exit
	SUB	R9, R12, R25
	CMP	R25, R16
	BHI	exit

copy:
	// Literals: out[d:] <- lits[l:], 32 bytes at a time.
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	litdone
	MOVD	$32, R24
litloop:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	litloop
litdone:
	ADD	R16, R8
	ADD	R16, R9

	// Match: out[d:] <- out[d-off:].
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	short
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	matchdone
	MOVD	$32, R24
mloop:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	mloop
	B	matchdone

short:
	// Period off < 32: pattern[j] = out[d-off + j%off], j < 32.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
sloop:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	sloop

matchdone:
	ADD	R21, R8
	ADD	$1, R7
	ADD	$1, R3
	B	loop

exit:
	MOVD	R26, R10
done:
	MOVD	16(R0), R24
	SUB	R24, R7
	MOVD	R7, 56(R0)
	SUB	R1, R8
	MOVD	R8, 64(R0)
	MOVD	8(R0), R24
	SUB	R24, R9
	MOVD	R9, 72(R0)
	MOVD	R10, 80(R0)
	RET

// func splRunAsm16(st *splState)
TEXT ·splRunAsm16(SB), NOSPLIT, $0-8
	MOVD	st+0(FP), R0
	MOVD	0(R0), R1
	MOVD	24(R0), R4
	MOVD	80(R0), R10
	MOVD	16(R0), R24
	MOVD	40(R0), R5
	ADD	R24, R5
	MOVD	56(R0), R7
	ADD	R24, R7
	MOVD	32(R0), R3
	MOVD	56(R0), R25
	ADD	R25<<1, R3
	MOVD	64(R0), R8
	ADD	R1, R8
	MOVD	8(R0), R25
	MOVD	72(R0), R9
	ADD	R25, R9
	MOVD	88(R0), R24
	ADD	R1, R24, R11
	SUBS	$(4*33), R24, R24
	ADD	R1, R24, R13
	CSEL	LT, ZR, R13, R13
	MOVD	96(R0), R24
	ADD	R25, R24, R12
	SUBS	$(4*14), R24, R24
	ADD	R25, R24, R14
	CSEL	LT, ZR, R14, R14
	MOVD	$65536, R22
	ADD	R1, R22

loop:
	CMP	R5, R7
	BHS	done

	// Batch of 4, if it fits.
	ADD	$4, R7, R24
	CMP	R5, R24
	BHI	single
	CMP	R13, R8
	BHI	single
	CMP	R14, R9
	BHI	single
	SUB	$4, R5, R6
	CMP	R22, R8
	BLO	pbatchseq

qbatchseq:
	// Batch past 64 KiB of output: no offset test.

	// Sequence 0 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVWU	(R7), R15
	UBFX	$4, R15, $4, R16
	UBFX	$0, R15, $4, R17
	CMP	$15, R16
	BEQ	qvar0
	CMP	$15, R17
	BEQ	qmvar0
	MOVHU	0(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
qok0:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qshort0
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
qdone0:
	ADD	R21, R8

	// Sequence 1 of the batch, straight-line: ll <= 14, ml <= 19.
	UBFX	$12, R15, $4, R16
	UBFX	$8, R15, $4, R17
	CMP	$15, R16
	BEQ	qvar1
	CMP	$15, R17
	BEQ	qmvar1
	MOVHU	2(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
qok1:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qshort1
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
qdone1:
	ADD	R21, R8

	// Sequence 2 of the batch, straight-line: ll <= 14, ml <= 19.
	UBFX	$20, R15, $4, R16
	UBFX	$16, R15, $4, R17
	CMP	$15, R16
	BEQ	qvar2
	CMP	$15, R17
	BEQ	qmvar2
	MOVHU	4(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
qok2:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qshort2
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
qdone2:
	ADD	R21, R8

	// Sequence 3 of the batch, straight-line: ll <= 14, ml <= 19.
	UBFX	$28, R15, $4, R16
	UBFX	$24, R15, $4, R17
	CMP	$15, R16
	BEQ	qvar3
	CMP	$15, R17
	BEQ	qmvar3
	MOVHU	6(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
qok3:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qshort3
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
qdone3:
	ADD	R21, R8
	ADD	$4, R7
	ADD	$8, R3
	CMP	R6, R7
	BHI	loop
	CMP	R13, R8
	BHI	loop
	CMP	R14, R9
	BLS	qbatchseq
	B	loop

qesc0:
	// A varint, or an offset to check: sequence 0 goes to the single path.
	ADD	$0, R7
	ADD	$0, R3
	B	single
qshort0:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	qdone0

qesc1:
	// A varint, or an offset to check: sequence 1 goes to the single path.
	ADD	$1, R7
	ADD	$2, R3
	B	single
qshort1:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	qdone1

qesc2:
	// A varint, or an offset to check: sequence 2 goes to the single path.
	ADD	$2, R7
	ADD	$4, R3
	B	single
qshort2:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	qdone2

qesc3:
	// A varint, or an offset to check: sequence 3 goes to the single path.
	ADD	$3, R7
	ADD	$6, R3
	B	single
qshort3:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	qdone3

qmvar0:
	// Sequence 0: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 3 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	qvfail0
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	qmvl0
	ADD	$1, R10
qmvv0:
	ADD	R20, R17
	MOVHU	0(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(3*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail0
qmvok0:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh0
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone0
	MOVD	$32, R24
qmvm0:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qmvm0
	B	qdone0
qmvl0:
	CMP	$0xC0, R20
	BLO	qmv20
	CMP	$0xE0, R20
	BHS	qvfail0
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qmvv0
qmv20:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qmvv0

qvar0:
	// Sequence 0 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 3 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	qvlo0
	CMP	R2, R10
	BGE	qvfail0
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qva0_1
	CMP	$0xC0, R20
	BLO	qva0_2
	CMP	$0xE0, R20
	BHS	qvfail0
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qva0_x
qva0_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qva0_x
qva0_1:
	ADD	$1, R10
qva0_x:
	ADD	R20, R16
qvlo0:
	CMP	$15, R17
	BNE	qvmo0
	CMP	R2, R10
	BGE	qvfail0
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qvb0_1
	CMP	$0xC0, R20
	BLO	qvb0_2
	CMP	$0xE0, R20
	BHS	qvfail0
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qvb0_x
qvb0_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qvb0_x
qvb0_1:
	ADD	$1, R10
qvb0_x:
	ADD	R20, R17
qvmo0:
	MOVHU	0(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(3*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail0
	SUB	R9, R12, R25
	SUB	$(3*14), R25
	CMP	R25, R16
	BGT	qvfail0
qvok0:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	qvld0
	MOVD	$32, R24
qvll0:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	qvll0
qvld0:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh0
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone0
	MOVD	$32, R24
qvml0:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qvml0
	B	qdone0
qvsh0:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
qvsl0:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	qvsl0
	B	qdone0
qvfail0:
	// Not here: the single path takes sequence 0, extras position restored.
	MOVD	R26, R10
	ADD	$0, R7
	ADD	$0, R3
	B	single

qmvar1:
	// Sequence 1: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 2 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	qvfail1
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	qmvl1
	ADD	$1, R10
qmvv1:
	ADD	R20, R17
	MOVHU	2(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(2*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail1
qmvok1:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh1
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone1
	MOVD	$32, R24
qmvm1:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qmvm1
	B	qdone1
qmvl1:
	CMP	$0xC0, R20
	BLO	qmv21
	CMP	$0xE0, R20
	BHS	qvfail1
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qmvv1
qmv21:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qmvv1

qvar1:
	// Sequence 1 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 2 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	qvlo1
	CMP	R2, R10
	BGE	qvfail1
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qva1_1
	CMP	$0xC0, R20
	BLO	qva1_2
	CMP	$0xE0, R20
	BHS	qvfail1
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qva1_x
qva1_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qva1_x
qva1_1:
	ADD	$1, R10
qva1_x:
	ADD	R20, R16
qvlo1:
	CMP	$15, R17
	BNE	qvmo1
	CMP	R2, R10
	BGE	qvfail1
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qvb1_1
	CMP	$0xC0, R20
	BLO	qvb1_2
	CMP	$0xE0, R20
	BHS	qvfail1
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qvb1_x
qvb1_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qvb1_x
qvb1_1:
	ADD	$1, R10
qvb1_x:
	ADD	R20, R17
qvmo1:
	MOVHU	2(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(2*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail1
	SUB	R9, R12, R25
	SUB	$(2*14), R25
	CMP	R25, R16
	BGT	qvfail1
qvok1:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	qvld1
	MOVD	$32, R24
qvll1:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	qvll1
qvld1:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh1
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone1
	MOVD	$32, R24
qvml1:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qvml1
	B	qdone1
qvsh1:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
qvsl1:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	qvsl1
	B	qdone1
qvfail1:
	// Not here: the single path takes sequence 1, extras position restored.
	MOVD	R26, R10
	ADD	$1, R7
	ADD	$2, R3
	B	single

qmvar2:
	// Sequence 2: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 1 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	qvfail2
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	qmvl2
	ADD	$1, R10
qmvv2:
	ADD	R20, R17
	MOVHU	4(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(1*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail2
qmvok2:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh2
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone2
	MOVD	$32, R24
qmvm2:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qmvm2
	B	qdone2
qmvl2:
	CMP	$0xC0, R20
	BLO	qmv22
	CMP	$0xE0, R20
	BHS	qvfail2
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qmvv2
qmv22:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qmvv2

qvar2:
	// Sequence 2 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 1 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	qvlo2
	CMP	R2, R10
	BGE	qvfail2
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qva2_1
	CMP	$0xC0, R20
	BLO	qva2_2
	CMP	$0xE0, R20
	BHS	qvfail2
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qva2_x
qva2_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qva2_x
qva2_1:
	ADD	$1, R10
qva2_x:
	ADD	R20, R16
qvlo2:
	CMP	$15, R17
	BNE	qvmo2
	CMP	R2, R10
	BGE	qvfail2
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qvb2_1
	CMP	$0xC0, R20
	BLO	qvb2_2
	CMP	$0xE0, R20
	BHS	qvfail2
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qvb2_x
qvb2_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qvb2_x
qvb2_1:
	ADD	$1, R10
qvb2_x:
	ADD	R20, R17
qvmo2:
	MOVHU	4(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(1*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail2
	SUB	R9, R12, R25
	SUB	$(1*14), R25
	CMP	R25, R16
	BGT	qvfail2
qvok2:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	qvld2
	MOVD	$32, R24
qvll2:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	qvll2
qvld2:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh2
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone2
	MOVD	$32, R24
qvml2:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qvml2
	B	qdone2
qvsh2:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
qvsl2:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	qvsl2
	B	qdone2
qvfail2:
	// Not here: the single path takes sequence 2, extras position restored.
	MOVD	R26, R10
	ADD	$2, R7
	ADD	$4, R3
	B	single

qmvar3:
	// Sequence 3: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 0 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	qvfail3
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	qmvl3
	ADD	$1, R10
qmvv3:
	ADD	R20, R17
	MOVHU	6(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(0*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail3
qmvok3:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh3
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone3
	MOVD	$32, R24
qmvm3:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qmvm3
	B	qdone3
qmvl3:
	CMP	$0xC0, R20
	BLO	qmv23
	CMP	$0xE0, R20
	BHS	qvfail3
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qmvv3
qmv23:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qmvv3

qvar3:
	// Sequence 3 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 0 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	qvlo3
	CMP	R2, R10
	BGE	qvfail3
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qva3_1
	CMP	$0xC0, R20
	BLO	qva3_2
	CMP	$0xE0, R20
	BHS	qvfail3
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qva3_x
qva3_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qva3_x
qva3_1:
	ADD	$1, R10
qva3_x:
	ADD	R20, R16
qvlo3:
	CMP	$15, R17
	BNE	qvmo3
	CMP	R2, R10
	BGE	qvfail3
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	qvb3_1
	CMP	$0xC0, R20
	BLO	qvb3_2
	CMP	$0xE0, R20
	BHS	qvfail3
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	qvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	qvb3_x
qvb3_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	qvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	qvb3_x
qvb3_1:
	ADD	$1, R10
qvb3_x:
	ADD	R20, R17
qvmo3:
	MOVHU	6(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(0*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	qvfail3
	SUB	R9, R12, R25
	SUB	$(0*14), R25
	CMP	R25, R16
	BGT	qvfail3
qvok3:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	qvld3
	MOVD	$32, R24
qvll3:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	qvll3
qvld3:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	qvsh3
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	qdone3
	MOVD	$32, R24
qvml3:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	qvml3
	B	qdone3
qvsh3:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
qvsl3:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	qvsl3
	B	qdone3
qvfail3:
	// Not here: the single path takes sequence 3, extras position restored.
	MOVD	R26, R10
	ADD	$3, R7
	ADD	$6, R3
	B	single


pbatchseq:
	// Batch below 64 KiB of output: off > d+ll leaves a sequence to
	// the single path.

	// Sequence 0 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVWU	(R7), R15
	UBFX	$4, R15, $4, R16
	UBFX	$0, R15, $4, R17
	CMP	$15, R16
	BEQ	pvar0
	CMP	$15, R17
	BEQ	pmvar0
	MOVHU	0(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pesc0
pok0:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pshort0
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
pdone0:
	ADD	R21, R8

	// Sequence 1 of the batch, straight-line: ll <= 14, ml <= 19.
	UBFX	$12, R15, $4, R16
	UBFX	$8, R15, $4, R17
	CMP	$15, R16
	BEQ	pvar1
	CMP	$15, R17
	BEQ	pmvar1
	MOVHU	2(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pesc1
pok1:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pshort1
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
pdone1:
	ADD	R21, R8

	// Sequence 2 of the batch, straight-line: ll <= 14, ml <= 19.
	UBFX	$20, R15, $4, R16
	UBFX	$16, R15, $4, R17
	CMP	$15, R16
	BEQ	pvar2
	CMP	$15, R17
	BEQ	pmvar2
	MOVHU	4(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pesc2
pok2:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pshort2
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
pdone2:
	ADD	R21, R8

	// Sequence 3 of the batch, straight-line: ll <= 14, ml <= 19.
	UBFX	$28, R15, $4, R16
	UBFX	$24, R15, $4, R17
	CMP	$15, R16
	BEQ	pvar3
	CMP	$15, R17
	BEQ	pmvar3
	MOVHU	6(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pesc3
pok3:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pshort3
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
pdone3:
	ADD	R21, R8
	ADD	$4, R7
	ADD	$8, R3
	CMP	R6, R7
	BHI	loop
	CMP	R13, R8
	BHI	loop
	CMP	R14, R9
	BHI	loop
	CMP	R22, R8
	BLO	pbatchseq
	B	qbatchseq

pesc0:
	// A varint, or an offset to check: sequence 0 goes to the single path.
	ADD	$0, R7
	ADD	$0, R3
	B	single
pshort0:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	pdone0

pesc1:
	// A varint, or an offset to check: sequence 1 goes to the single path.
	ADD	$1, R7
	ADD	$2, R3
	B	single
pshort1:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	pdone1

pesc2:
	// A varint, or an offset to check: sequence 2 goes to the single path.
	ADD	$2, R7
	ADD	$4, R3
	B	single
pshort2:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	pdone2

pesc3:
	// A varint, or an offset to check: sequence 3 goes to the single path.
	ADD	$3, R7
	ADD	$6, R3
	B	single
pshort3:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	FSTPQ	(F4, F5), (R8)
	B	pdone3

pmvar0:
	// Sequence 0: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 3 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	pvfail0
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	pmvl0
	ADD	$1, R10
pmvv0:
	ADD	R20, R17
	MOVHU	0(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(3*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail0
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail0
pmvok0:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh0
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone0
	MOVD	$32, R24
pmvm0:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pmvm0
	B	pdone0
pmvl0:
	CMP	$0xC0, R20
	BLO	pmv20
	CMP	$0xE0, R20
	BHS	pvfail0
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pmvv0
pmv20:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pmvv0

pvar0:
	// Sequence 0 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 3 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	pvlo0
	CMP	R2, R10
	BGE	pvfail0
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pva0_1
	CMP	$0xC0, R20
	BLO	pva0_2
	CMP	$0xE0, R20
	BHS	pvfail0
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pva0_x
pva0_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pva0_x
pva0_1:
	ADD	$1, R10
pva0_x:
	ADD	R20, R16
pvlo0:
	CMP	$15, R17
	BNE	pvmo0
	CMP	R2, R10
	BGE	pvfail0
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pvb0_1
	CMP	$0xC0, R20
	BLO	pvb0_2
	CMP	$0xE0, R20
	BHS	pvfail0
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pvb0_x
pvb0_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail0
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pvb0_x
pvb0_1:
	ADD	$1, R10
pvb0_x:
	ADD	R20, R17
pvmo0:
	MOVHU	0(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(3*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail0
	SUB	R9, R12, R25
	SUB	$(3*14), R25
	CMP	R25, R16
	BGT	pvfail0
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail0
pvok0:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	pvld0
	MOVD	$32, R24
pvll0:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	pvll0
pvld0:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh0
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone0
	MOVD	$32, R24
pvml0:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pvml0
	B	pdone0
pvsh0:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
pvsl0:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	pvsl0
	B	pdone0
pvfail0:
	// Not here: the single path takes sequence 0, extras position restored.
	MOVD	R26, R10
	ADD	$0, R7
	ADD	$0, R3
	B	single

pmvar1:
	// Sequence 1: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 2 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	pvfail1
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	pmvl1
	ADD	$1, R10
pmvv1:
	ADD	R20, R17
	MOVHU	2(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(2*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail1
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail1
pmvok1:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh1
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone1
	MOVD	$32, R24
pmvm1:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pmvm1
	B	pdone1
pmvl1:
	CMP	$0xC0, R20
	BLO	pmv21
	CMP	$0xE0, R20
	BHS	pvfail1
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pmvv1
pmv21:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pmvv1

pvar1:
	// Sequence 1 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 2 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	pvlo1
	CMP	R2, R10
	BGE	pvfail1
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pva1_1
	CMP	$0xC0, R20
	BLO	pva1_2
	CMP	$0xE0, R20
	BHS	pvfail1
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pva1_x
pva1_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pva1_x
pva1_1:
	ADD	$1, R10
pva1_x:
	ADD	R20, R16
pvlo1:
	CMP	$15, R17
	BNE	pvmo1
	CMP	R2, R10
	BGE	pvfail1
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pvb1_1
	CMP	$0xC0, R20
	BLO	pvb1_2
	CMP	$0xE0, R20
	BHS	pvfail1
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pvb1_x
pvb1_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail1
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pvb1_x
pvb1_1:
	ADD	$1, R10
pvb1_x:
	ADD	R20, R17
pvmo1:
	MOVHU	2(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(2*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail1
	SUB	R9, R12, R25
	SUB	$(2*14), R25
	CMP	R25, R16
	BGT	pvfail1
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail1
pvok1:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	pvld1
	MOVD	$32, R24
pvll1:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	pvll1
pvld1:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh1
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone1
	MOVD	$32, R24
pvml1:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pvml1
	B	pdone1
pvsh1:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
pvsl1:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	pvsl1
	B	pdone1
pvfail1:
	// Not here: the single path takes sequence 1, extras position restored.
	MOVD	R26, R10
	ADD	$1, R7
	ADD	$2, R3
	B	single

pmvar2:
	// Sequence 2: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 1 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	pvfail2
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	pmvl2
	ADD	$1, R10
pmvv2:
	ADD	R20, R17
	MOVHU	4(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(1*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail2
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail2
pmvok2:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh2
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone2
	MOVD	$32, R24
pmvm2:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pmvm2
	B	pdone2
pmvl2:
	CMP	$0xC0, R20
	BLO	pmv22
	CMP	$0xE0, R20
	BHS	pvfail2
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pmvv2
pmv22:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pmvv2

pvar2:
	// Sequence 2 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 1 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	pvlo2
	CMP	R2, R10
	BGE	pvfail2
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pva2_1
	CMP	$0xC0, R20
	BLO	pva2_2
	CMP	$0xE0, R20
	BHS	pvfail2
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pva2_x
pva2_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pva2_x
pva2_1:
	ADD	$1, R10
pva2_x:
	ADD	R20, R16
pvlo2:
	CMP	$15, R17
	BNE	pvmo2
	CMP	R2, R10
	BGE	pvfail2
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pvb2_1
	CMP	$0xC0, R20
	BLO	pvb2_2
	CMP	$0xE0, R20
	BHS	pvfail2
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pvb2_x
pvb2_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail2
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pvb2_x
pvb2_1:
	ADD	$1, R10
pvb2_x:
	ADD	R20, R17
pvmo2:
	MOVHU	4(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(1*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail2
	SUB	R9, R12, R25
	SUB	$(1*14), R25
	CMP	R25, R16
	BGT	pvfail2
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail2
pvok2:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	pvld2
	MOVD	$32, R24
pvll2:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	pvll2
pvld2:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh2
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone2
	MOVD	$32, R24
pvml2:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pvml2
	B	pdone2
pvsh2:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
pvsl2:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	pvsl2
	B	pdone2
pvfail2:
	// Not here: the single path takes sequence 2, extras position restored.
	MOVD	R26, R10
	ADD	$2, R7
	ADD	$4, R3
	B	single

pmvar3:
	// Sequence 3: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 0 sequences after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	R2, R10
	BGE	pvfail3
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BHS	pmvl3
	ADD	$1, R10
pmvv3:
	ADD	R20, R17
	MOVHU	6(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(0*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail3
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail3
pmvok3:
	VLD1	(R9), [V0.B16]
	VST1	[V0.B16], (R8)
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh3
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone3
	MOVD	$32, R24
pmvm3:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pmvm3
	B	pdone3
pmvl3:
	CMP	$0xC0, R20
	BLO	pmv23
	CMP	$0xE0, R20
	BHS	pvfail3
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pmvv3
pmv23:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pmvv3

pvar3:
	// Sequence 3 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 0 after it.
	MOVD	R10, R26
	MOVD	48(R0), R2
	CMP	$15, R16
	BNE	pvlo3
	CMP	R2, R10
	BGE	pvfail3
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pva3_1
	CMP	$0xC0, R20
	BLO	pva3_2
	CMP	$0xE0, R20
	BHS	pvfail3
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pva3_x
pva3_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pva3_x
pva3_1:
	ADD	$1, R10
pva3_x:
	ADD	R20, R16
pvlo3:
	CMP	$15, R17
	BNE	pvmo3
	CMP	R2, R10
	BGE	pvfail3
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	pvb3_1
	CMP	$0xC0, R20
	BLO	pvb3_2
	CMP	$0xE0, R20
	BHS	pvfail3
	ADD	$3, R10, R24
	CMP	R2, R24
	BHI	pvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	pvb3_x
pvb3_2:
	ADD	$2, R10, R24
	CMP	R2, R24
	BHI	pvfail3
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	pvb3_x
pvb3_1:
	ADD	$1, R10
pvb3_x:
	ADD	R20, R17
pvmo3:
	MOVHU	6(R3), R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R8, R11, R25
	SUB	$(0*33), R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BGT	pvfail3
	SUB	R9, R12, R25
	SUB	$(0*14), R25
	CMP	R25, R16
	BGT	pvfail3
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	pvfail3
pvok3:
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	pvld3
	MOVD	$32, R24
pvll3:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	pvll3
pvld3:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	pvsh3
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	pdone3
	MOVD	$32, R24
pvml3:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	pvml3
	B	pdone3
pvsh3:
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
pvsl3:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	pvsl3
	B	pdone3
pvfail3:
	// Not here: the single path takes sequence 3, extras position restored.
	MOVD	R26, R10
	ADD	$3, R7
	ADD	$6, R3
	B	single

single:
	FETCH16
	MOVD	R10, R26
	ADD	$5, R17, R21

	// LL == 15: add a varint from the extras.
	CMP	$15, R16
	BNE	llok
	MOVD	48(R0), R6 // nExt
	CMP	R6, R10
	BGE	exit
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	ll1
	CMP	$0xC0, R20
	BLO	ll2
	CMP	$0xE0, R20
	BHS	exit
	ADD	$3, R10, R24
	CMP	R6, R24
	BHI	exit
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	lladd
ll2:
	ADD	$2, R10, R24
	CMP	R6, R24
	BHI	exit
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	lladd
ll1:
	ADD	$1, R10
lladd:
	ADD	R20, R16

llok:
	// ML field == 15: add a varint from the extras.
	CMP	$15, R17
	BNE	mlok
	MOVD	48(R0), R6 // nExt
	CMP	R6, R10
	BGE	exit
	MOVBU	(R4)(R10), R20
	CMP	$0x80, R20
	BLO	ml1
	CMP	$0xC0, R20
	BLO	ml2
	CMP	$0xE0, R20
	BHS	exit
	ADD	$3, R10, R24
	CMP	R6, R24
	BHI	exit
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	MOVBU	2(R25), R23
	AND	$0x1F, R20
	ORR	R24<<5, R20
	ORR	R23<<13, R20
	ADD	$3, R10
	B	mladd
ml2:
	ADD	$2, R10, R24
	CMP	R6, R24
	BHI	exit
	ADD	R4, R10, R25
	MOVBU	1(R25), R24
	AND	$0x3F, R20
	ORR	R24<<6, R20
	ADD	$2, R10
	B	mladd
ml1:
	ADD	$1, R10
mladd:
	ADD	R20, R21

mlok:
	// off > d+ll, ll+ml > limit-d or ll > litEnd-l: leave it to decodeSPL.
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	exit
	SUB	R8, R11, R25
	ADD	R16, R21, R24
	CMP	R25, R24
	BHI	exit
	SUB	R9, R12, R25
	CMP	R25, R16
	BHI	exit

copy:
	// Literals: out[d:] <- lits[l:], 32 bytes at a time.
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BLS	litdone
	MOVD	$32, R24
litloop:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	litloop
litdone:
	ADD	R16, R8
	ADD	R16, R9

	// Match: out[d:] <- out[d-off:].
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	short
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BLS	matchdone
	MOVD	$32, R24
mloop:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	mloop
	B	matchdone

short:
	// Period off < 32: pattern[j] = out[d-off + j%off], j < 32.
	FLDPQ	(R23), (F0, F1)
	MOVD	$·pakMasks(SB), R24
	ADD	R19<<5, R24, R24
	FLDPQ	(R24), (F2, F3)
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16
	VTBL	V3.B16, [V0.B16, V1.B16], V5.B16
	MOVD	$·pakStrides(SB), R25
	MOVBU	(R25)(R19), R24
	MOVD	$0, R25
sloop:
	ADD	R25, R8, R20
	FSTPQ	(F4, F5), (R20)
	ADD	R24, R25
	CMP	R21, R25
	BLO	sloop

matchdone:
	ADD	R21, R8
	ADD	$1, R7
	ADD	$2, R3
	B	loop

exit:
	MOVD	R26, R10
done:
	MOVD	16(R0), R24
	SUB	R24, R7
	MOVD	R7, 56(R0)
	SUB	R1, R8
	MOVD	R8, 64(R0)
	MOVD	8(R0), R24
	SUB	R24, R9
	MOVD	R9, 72(R0)
	MOVD	R10, 80(R0)
	RET
