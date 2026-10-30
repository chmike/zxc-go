//go:build !purego

#include "textflag.h"

// SPL sequence loop for amd64, called through splRun (pakrun_asm.go),
// which checks the invariants this code relies on; its comment and the one
// of pakRun give the proof of the accesses.
//
// The same loop as pak_amd64.s, batch and single paths, copies and short
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
//   SI &toks[i]   DI &out[d]   BX &lits[l]   R13 &offs[w*i]
//   CX ll         DX ml        R8 off         AX token, then scratch
//   R11 batch: 1 once d >= 64 KiB (no offset test); single: scratch
//   R12 single: e at the sequence start; batch: varint scratch
//   R9 R10 scratch; X0-X6 copies
//
// Frame:
#define OUT 0(SP)       // out
#define LITS 8(SP)      // lits
#define SEQS 16(SP)     // toks
#define SEQEND 24(SP)   // &toks[nTok]
#define LIMITP 32(SP)   // &out[limit]
#define LITENDP 40(SP)  // &lits[litEnd]
#define DMAXP 48(SP)    // &out[limit - 4*33], 0 if negative
#define LMAXP 56(SP)    // &lits[litEnd - 4*14], 0 if negative
#define EXT 64(SP)      // extras
#define NEXT 72(SP)     // nExt
#define OUT64K 80(SP)   // &out[65536]
#define STATE 88(SP)    // *splState
#define EPOS 96(SP)     // e
#define ESAVE 104(SP)   // e at the start of a sequence with a varint, in a batch

// FETCH8 and FETCH16 read the token at SI into CX (ll) and DX (ml field),
// and the offset at R13, plus one, into R8: offs[i] or offs[2i, 2i+1].
#define FETCH8 \
	MOVBLZX	(SI), AX; \
	MOVL	AX, CX; \
	SHRL	$4, CX; \
	MOVL	AX, DX; \
	ANDL	$15, DX; \
	MOVBLZX	(R13), R8; \
	INCL	R8

#define FETCH16 \
	MOVBLZX	(SI), AX; \
	MOVL	AX, CX; \
	SHRL	$4, CX; \
	MOVL	AX, DX; \
	ANDL	$15, DX; \
	MOVWLZX	(R13), R8; \
	INCL	R8

// func splRunAsm8(st *splState)
TEXT ·splRunAsm8(SB), NOSPLIT, $112-8
	MOVQ	st+0(FP), R13
	MOVQ	R13, STATE
	MOVQ	0(R13), AX
	MOVQ	AX, OUT
	MOVQ	8(R13), R9
	MOVQ	R9, LITS
	MOVQ	16(R13), R10
	MOVQ	R10, SEQS
	MOVQ	24(R13), R11
	MOVQ	R11, EXT
	MOVQ	40(R13), R11
	ADDQ	R10, R11
	MOVQ	R11, SEQEND
	MOVQ	48(R13), R11
	MOVQ	R11, NEXT
	MOVQ	56(R13), SI
	ADDQ	R10, SI
	MOVQ	64(R13), DI
	ADDQ	AX, DI
	MOVQ	72(R13), BX
	ADDQ	R9, BX
	MOVQ	80(R13), R11
	MOVQ	R11, EPOS
	LEAQ	65536(AX), R11
	MOVQ	R11, OUT64K

	MOVQ	88(R13), R10        // limit
	LEAQ	(AX)(R10*1), R11
	MOVQ	R11, LIMITP
	LEAQ	-(4*33)(R10), R10
	LEAQ	(AX)(R10*1), R11
	XORL	R12, R12
	TESTQ	R10, R10
	CMOVQLT	R12, R11
	MOVQ	R11, DMAXP

	MOVQ	96(R13), R10        // litEnd
	LEAQ	(R9)(R10*1), R11
	MOVQ	R11, LITENDP
	LEAQ	-(4*14)(R10), R10
	LEAQ	(R9)(R10*1), R11
	XORL	R12, R12
	TESTQ	R10, R10
	CMOVQLT	R12, R11
	MOVQ	R11, LMAXP

	// R13 = &offs[w*i]
	MOVQ	56(R13), R10
	ADDQ	32(R13), R10
	MOVQ	R10, R13

loop:
	CMPQ	SI, SEQEND
	JAE	done

	// Batch of 4, if it fits.
	LEAQ	4(SI), R9
	CMPQ	R9, SEQEND
	JA	single
	CMPQ	DI, DMAXP
	JA	single
	CMPQ	BX, LMAXP
	JA	single
	MOVQ	SEQEND, R11
	SUBQ	$4, R11
	CMPQ	DI, OUT64K
	JB	pbatchseq

qbatchseq:
	// Batch past 64 KiB of output: no offset test.

	// Sequence 0 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	0(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	qvar0
	CMPL	DX, $15
	JEQ	qmvar0
	ADDL	$5, DX
	MOVBLZX	0(R13), R8
	INCL	R8
qok0:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qshort0
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
qdone0:
	ADDQ	DX, DI

	// Sequence 1 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	1(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	qvar1
	CMPL	DX, $15
	JEQ	qmvar1
	ADDL	$5, DX
	MOVBLZX	1(R13), R8
	INCL	R8
qok1:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qshort1
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
qdone1:
	ADDQ	DX, DI

	// Sequence 2 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	2(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	qvar2
	CMPL	DX, $15
	JEQ	qmvar2
	ADDL	$5, DX
	MOVBLZX	2(R13), R8
	INCL	R8
qok2:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qshort2
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
qdone2:
	ADDQ	DX, DI

	// Sequence 3 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	3(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	qvar3
	CMPL	DX, $15
	JEQ	qmvar3
	ADDL	$5, DX
	MOVBLZX	3(R13), R8
	INCL	R8
qok3:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qshort3
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
qdone3:
	ADDQ	DX, DI
	ADDQ	$4, SI
	ADDQ	$4, R13
	CMPQ	SI, R11
	JA	loop
	CMPQ	DI, DMAXP
	JA	loop
	CMPQ	BX, LMAXP
	JBE	qbatchseq
	JMP	loop

qesc0:
	// A varint, or an offset to check: sequence 0 goes to the single path.
	ADDQ	$0, SI
	ADDQ	$0, R13
	JMP	single
qshort0:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	qdone0

qesc1:
	// A varint, or an offset to check: sequence 1 goes to the single path.
	ADDQ	$1, SI
	ADDQ	$1, R13
	JMP	single
qshort1:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	qdone1

qesc2:
	// A varint, or an offset to check: sequence 2 goes to the single path.
	ADDQ	$2, SI
	ADDQ	$2, R13
	JMP	single
qshort2:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	qdone2

qesc3:
	// A varint, or an offset to check: sequence 3 goes to the single path.
	ADDQ	$3, SI
	ADDQ	$3, R13
	JMP	single
qshort3:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	qdone3

qmvar0:
	// Sequence 0: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 3 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail0
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	qmvl0
	INCQ	R10
qmvv0:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVBLZX	0(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(3*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail0
qmvok0:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh0
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone0
	MOVQ	$32, R9
qmvm0:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qmvm0
	JMP	qdone0
qmvl0:
	CMPL	AX, $0xC0
	JB	qmv20
	CMPL	AX, $0xE0
	JAE	qvfail0
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qmvv0
qmv20:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qmvv0

qvar0:
	// Sequence 0 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 3 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	qvlo0
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail0
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qva0_1
	CMPL	AX, $0xC0
	JB	qva0_2
	CMPL	AX, $0xE0
	JAE	qvfail0
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qva0_x
qva0_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qva0_x
qva0_1:
	INCQ	R10
qva0_x:
	ADDQ	AX, CX
qvlo0:
	CMPL	DX, $15
	JNE	qvmo0
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail0
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qvb0_1
	CMPL	AX, $0xC0
	JB	qvb0_2
	CMPL	AX, $0xE0
	JAE	qvfail0
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qvb0_x
qvb0_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qvb0_x
qvb0_1:
	INCQ	R10
qvb0_x:
	ADDQ	AX, DX
qvmo0:
	MOVQ	R10, EPOS
	MOVBLZX	0(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(3*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail0
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(3*14), R9
	CMPQ	CX, R9
	JGT	qvfail0
qvok0:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	qvld0
	MOVQ	$32, R9
qvll0:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	qvll0
qvld0:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh0
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone0
	MOVQ	$32, R9
qvml0:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qvml0
	JMP	qdone0
qvsh0:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
qvsl0:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	qvsl0
	JMP	qdone0
qvfail0:
	// Not here: the single path takes sequence 0, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$0, SI
	ADDQ	$0, R13
	JMP	single

qmvar1:
	// Sequence 1: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 2 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail1
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	qmvl1
	INCQ	R10
qmvv1:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVBLZX	1(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(2*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail1
qmvok1:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh1
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone1
	MOVQ	$32, R9
qmvm1:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qmvm1
	JMP	qdone1
qmvl1:
	CMPL	AX, $0xC0
	JB	qmv21
	CMPL	AX, $0xE0
	JAE	qvfail1
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qmvv1
qmv21:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qmvv1

qvar1:
	// Sequence 1 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 2 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	qvlo1
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail1
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qva1_1
	CMPL	AX, $0xC0
	JB	qva1_2
	CMPL	AX, $0xE0
	JAE	qvfail1
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qva1_x
qva1_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qva1_x
qva1_1:
	INCQ	R10
qva1_x:
	ADDQ	AX, CX
qvlo1:
	CMPL	DX, $15
	JNE	qvmo1
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail1
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qvb1_1
	CMPL	AX, $0xC0
	JB	qvb1_2
	CMPL	AX, $0xE0
	JAE	qvfail1
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qvb1_x
qvb1_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qvb1_x
qvb1_1:
	INCQ	R10
qvb1_x:
	ADDQ	AX, DX
qvmo1:
	MOVQ	R10, EPOS
	MOVBLZX	1(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(2*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail1
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(2*14), R9
	CMPQ	CX, R9
	JGT	qvfail1
qvok1:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	qvld1
	MOVQ	$32, R9
qvll1:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	qvll1
qvld1:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh1
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone1
	MOVQ	$32, R9
qvml1:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qvml1
	JMP	qdone1
qvsh1:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
qvsl1:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	qvsl1
	JMP	qdone1
qvfail1:
	// Not here: the single path takes sequence 1, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$1, SI
	ADDQ	$1, R13
	JMP	single

qmvar2:
	// Sequence 2: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 1 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail2
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	qmvl2
	INCQ	R10
qmvv2:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVBLZX	2(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(1*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail2
qmvok2:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh2
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone2
	MOVQ	$32, R9
qmvm2:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qmvm2
	JMP	qdone2
qmvl2:
	CMPL	AX, $0xC0
	JB	qmv22
	CMPL	AX, $0xE0
	JAE	qvfail2
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qmvv2
qmv22:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qmvv2

qvar2:
	// Sequence 2 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 1 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	qvlo2
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail2
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qva2_1
	CMPL	AX, $0xC0
	JB	qva2_2
	CMPL	AX, $0xE0
	JAE	qvfail2
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qva2_x
qva2_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qva2_x
qva2_1:
	INCQ	R10
qva2_x:
	ADDQ	AX, CX
qvlo2:
	CMPL	DX, $15
	JNE	qvmo2
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail2
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qvb2_1
	CMPL	AX, $0xC0
	JB	qvb2_2
	CMPL	AX, $0xE0
	JAE	qvfail2
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qvb2_x
qvb2_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qvb2_x
qvb2_1:
	INCQ	R10
qvb2_x:
	ADDQ	AX, DX
qvmo2:
	MOVQ	R10, EPOS
	MOVBLZX	2(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(1*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail2
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(1*14), R9
	CMPQ	CX, R9
	JGT	qvfail2
qvok2:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	qvld2
	MOVQ	$32, R9
qvll2:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	qvll2
qvld2:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh2
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone2
	MOVQ	$32, R9
qvml2:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qvml2
	JMP	qdone2
qvsh2:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
qvsl2:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	qvsl2
	JMP	qdone2
qvfail2:
	// Not here: the single path takes sequence 2, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$2, SI
	ADDQ	$2, R13
	JMP	single

qmvar3:
	// Sequence 3: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 0 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail3
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	qmvl3
	INCQ	R10
qmvv3:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVBLZX	3(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(0*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail3
qmvok3:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh3
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone3
	MOVQ	$32, R9
qmvm3:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qmvm3
	JMP	qdone3
qmvl3:
	CMPL	AX, $0xC0
	JB	qmv23
	CMPL	AX, $0xE0
	JAE	qvfail3
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qmvv3
qmv23:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qmvv3

qvar3:
	// Sequence 3 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 0 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	qvlo3
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail3
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qva3_1
	CMPL	AX, $0xC0
	JB	qva3_2
	CMPL	AX, $0xE0
	JAE	qvfail3
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qva3_x
qva3_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qva3_x
qva3_1:
	INCQ	R10
qva3_x:
	ADDQ	AX, CX
qvlo3:
	CMPL	DX, $15
	JNE	qvmo3
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail3
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qvb3_1
	CMPL	AX, $0xC0
	JB	qvb3_2
	CMPL	AX, $0xE0
	JAE	qvfail3
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qvb3_x
qvb3_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qvb3_x
qvb3_1:
	INCQ	R10
qvb3_x:
	ADDQ	AX, DX
qvmo3:
	MOVQ	R10, EPOS
	MOVBLZX	3(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(0*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail3
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(0*14), R9
	CMPQ	CX, R9
	JGT	qvfail3
qvok3:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	qvld3
	MOVQ	$32, R9
qvll3:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	qvll3
qvld3:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh3
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone3
	MOVQ	$32, R9
qvml3:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qvml3
	JMP	qdone3
qvsh3:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
qvsl3:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	qvsl3
	JMP	qdone3
qvfail3:
	// Not here: the single path takes sequence 3, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$3, SI
	ADDQ	$3, R13
	JMP	single


pbatchseq:
	// Batch below 64 KiB of output: off > d+ll leaves a sequence to
	// the single path.

	// Sequence 0 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	0(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	pvar0
	CMPL	DX, $15
	JEQ	pmvar0
	ADDL	$5, DX
	MOVBLZX	0(R13), R8
	INCL	R8
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pesc0
pok0:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pshort0
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
pdone0:
	ADDQ	DX, DI

	// Sequence 1 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	1(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	pvar1
	CMPL	DX, $15
	JEQ	pmvar1
	ADDL	$5, DX
	MOVBLZX	1(R13), R8
	INCL	R8
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pesc1
pok1:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pshort1
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
pdone1:
	ADDQ	DX, DI

	// Sequence 2 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	2(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	pvar2
	CMPL	DX, $15
	JEQ	pmvar2
	ADDL	$5, DX
	MOVBLZX	2(R13), R8
	INCL	R8
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pesc2
pok2:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pshort2
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
pdone2:
	ADDQ	DX, DI

	// Sequence 3 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	3(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	pvar3
	CMPL	DX, $15
	JEQ	pmvar3
	ADDL	$5, DX
	MOVBLZX	3(R13), R8
	INCL	R8
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pesc3
pok3:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pshort3
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
pdone3:
	ADDQ	DX, DI
	ADDQ	$4, SI
	ADDQ	$4, R13
	CMPQ	SI, R11
	JA	loop
	CMPQ	DI, DMAXP
	JA	loop
	CMPQ	BX, LMAXP
	JA	loop
	CMPQ	DI, OUT64K
	JB	pbatchseq
	JMP	qbatchseq

pesc0:
	// A varint, or an offset to check: sequence 0 goes to the single path.
	ADDQ	$0, SI
	ADDQ	$0, R13
	JMP	single
pshort0:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	pdone0

pesc1:
	// A varint, or an offset to check: sequence 1 goes to the single path.
	ADDQ	$1, SI
	ADDQ	$1, R13
	JMP	single
pshort1:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	pdone1

pesc2:
	// A varint, or an offset to check: sequence 2 goes to the single path.
	ADDQ	$2, SI
	ADDQ	$2, R13
	JMP	single
pshort2:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	pdone2

pesc3:
	// A varint, or an offset to check: sequence 3 goes to the single path.
	ADDQ	$3, SI
	ADDQ	$3, R13
	JMP	single
pshort3:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	pdone3

pmvar0:
	// Sequence 0: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 3 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail0
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	pmvl0
	INCQ	R10
pmvv0:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVBLZX	0(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(3*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail0
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail0
pmvok0:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh0
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone0
	MOVQ	$32, R9
pmvm0:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pmvm0
	JMP	pdone0
pmvl0:
	CMPL	AX, $0xC0
	JB	pmv20
	CMPL	AX, $0xE0
	JAE	pvfail0
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pmvv0
pmv20:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pmvv0

pvar0:
	// Sequence 0 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 3 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	pvlo0
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail0
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pva0_1
	CMPL	AX, $0xC0
	JB	pva0_2
	CMPL	AX, $0xE0
	JAE	pvfail0
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pva0_x
pva0_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pva0_x
pva0_1:
	INCQ	R10
pva0_x:
	ADDQ	AX, CX
pvlo0:
	CMPL	DX, $15
	JNE	pvmo0
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail0
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pvb0_1
	CMPL	AX, $0xC0
	JB	pvb0_2
	CMPL	AX, $0xE0
	JAE	pvfail0
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pvb0_x
pvb0_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pvb0_x
pvb0_1:
	INCQ	R10
pvb0_x:
	ADDQ	AX, DX
pvmo0:
	MOVQ	R10, EPOS
	MOVBLZX	0(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(3*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail0
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(3*14), R9
	CMPQ	CX, R9
	JGT	pvfail0
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail0
pvok0:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	pvld0
	MOVQ	$32, R9
pvll0:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	pvll0
pvld0:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh0
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone0
	MOVQ	$32, R9
pvml0:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pvml0
	JMP	pdone0
pvsh0:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
pvsl0:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	pvsl0
	JMP	pdone0
pvfail0:
	// Not here: the single path takes sequence 0, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$0, SI
	ADDQ	$0, R13
	JMP	single

pmvar1:
	// Sequence 1: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 2 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail1
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	pmvl1
	INCQ	R10
pmvv1:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVBLZX	1(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(2*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail1
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail1
pmvok1:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh1
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone1
	MOVQ	$32, R9
pmvm1:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pmvm1
	JMP	pdone1
pmvl1:
	CMPL	AX, $0xC0
	JB	pmv21
	CMPL	AX, $0xE0
	JAE	pvfail1
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pmvv1
pmv21:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pmvv1

pvar1:
	// Sequence 1 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 2 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	pvlo1
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail1
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pva1_1
	CMPL	AX, $0xC0
	JB	pva1_2
	CMPL	AX, $0xE0
	JAE	pvfail1
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pva1_x
pva1_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pva1_x
pva1_1:
	INCQ	R10
pva1_x:
	ADDQ	AX, CX
pvlo1:
	CMPL	DX, $15
	JNE	pvmo1
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail1
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pvb1_1
	CMPL	AX, $0xC0
	JB	pvb1_2
	CMPL	AX, $0xE0
	JAE	pvfail1
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pvb1_x
pvb1_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pvb1_x
pvb1_1:
	INCQ	R10
pvb1_x:
	ADDQ	AX, DX
pvmo1:
	MOVQ	R10, EPOS
	MOVBLZX	1(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(2*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail1
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(2*14), R9
	CMPQ	CX, R9
	JGT	pvfail1
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail1
pvok1:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	pvld1
	MOVQ	$32, R9
pvll1:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	pvll1
pvld1:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh1
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone1
	MOVQ	$32, R9
pvml1:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pvml1
	JMP	pdone1
pvsh1:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
pvsl1:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	pvsl1
	JMP	pdone1
pvfail1:
	// Not here: the single path takes sequence 1, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$1, SI
	ADDQ	$1, R13
	JMP	single

pmvar2:
	// Sequence 2: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 1 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail2
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	pmvl2
	INCQ	R10
pmvv2:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVBLZX	2(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(1*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail2
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail2
pmvok2:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh2
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone2
	MOVQ	$32, R9
pmvm2:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pmvm2
	JMP	pdone2
pmvl2:
	CMPL	AX, $0xC0
	JB	pmv22
	CMPL	AX, $0xE0
	JAE	pvfail2
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pmvv2
pmv22:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pmvv2

pvar2:
	// Sequence 2 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 1 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	pvlo2
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail2
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pva2_1
	CMPL	AX, $0xC0
	JB	pva2_2
	CMPL	AX, $0xE0
	JAE	pvfail2
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pva2_x
pva2_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pva2_x
pva2_1:
	INCQ	R10
pva2_x:
	ADDQ	AX, CX
pvlo2:
	CMPL	DX, $15
	JNE	pvmo2
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail2
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pvb2_1
	CMPL	AX, $0xC0
	JB	pvb2_2
	CMPL	AX, $0xE0
	JAE	pvfail2
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pvb2_x
pvb2_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pvb2_x
pvb2_1:
	INCQ	R10
pvb2_x:
	ADDQ	AX, DX
pvmo2:
	MOVQ	R10, EPOS
	MOVBLZX	2(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(1*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail2
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(1*14), R9
	CMPQ	CX, R9
	JGT	pvfail2
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail2
pvok2:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	pvld2
	MOVQ	$32, R9
pvll2:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	pvll2
pvld2:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh2
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone2
	MOVQ	$32, R9
pvml2:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pvml2
	JMP	pdone2
pvsh2:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
pvsl2:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	pvsl2
	JMP	pdone2
pvfail2:
	// Not here: the single path takes sequence 2, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$2, SI
	ADDQ	$2, R13
	JMP	single

pmvar3:
	// Sequence 3: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 0 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail3
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	pmvl3
	INCQ	R10
pmvv3:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVBLZX	3(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(0*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail3
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail3
pmvok3:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh3
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone3
	MOVQ	$32, R9
pmvm3:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pmvm3
	JMP	pdone3
pmvl3:
	CMPL	AX, $0xC0
	JB	pmv23
	CMPL	AX, $0xE0
	JAE	pvfail3
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pmvv3
pmv23:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pmvv3

pvar3:
	// Sequence 3 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 0 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	pvlo3
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail3
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pva3_1
	CMPL	AX, $0xC0
	JB	pva3_2
	CMPL	AX, $0xE0
	JAE	pvfail3
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pva3_x
pva3_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pva3_x
pva3_1:
	INCQ	R10
pva3_x:
	ADDQ	AX, CX
pvlo3:
	CMPL	DX, $15
	JNE	pvmo3
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail3
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pvb3_1
	CMPL	AX, $0xC0
	JB	pvb3_2
	CMPL	AX, $0xE0
	JAE	pvfail3
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pvb3_x
pvb3_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pvb3_x
pvb3_1:
	INCQ	R10
pvb3_x:
	ADDQ	AX, DX
pvmo3:
	MOVQ	R10, EPOS
	MOVBLZX	3(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(0*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail3
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(0*14), R9
	CMPQ	CX, R9
	JGT	pvfail3
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail3
pvok3:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	pvld3
	MOVQ	$32, R9
pvll3:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	pvll3
pvld3:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh3
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone3
	MOVQ	$32, R9
pvml3:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pvml3
	JMP	pdone3
pvsh3:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
pvsl3:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	pvsl3
	JMP	pdone3
pvfail3:
	// Not here: the single path takes sequence 3, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$3, SI
	ADDQ	$3, R13
	JMP	single

single:
	MOVQ	EPOS, R12
	FETCH8

	// LL == 15: add a varint from the extras.
	CMPL	CX, $15
	JNE	llok
	MOVQ	EPOS, R10
	CMPQ	R10, NEXT
	JAE	exit
	MOVQ	EXT, R9
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	ll1
	CMPL	AX, $0xC0
	JB	ll2
	CMPL	AX, $0xE0
	JAE	exit
	LEAQ	3(R10), R11
	CMPQ	R11, NEXT
	JA	exit
	MOVBLZX	1(R9)(R10*1), R11
	SHLL	$5, R11
	ANDL	$0x1F, AX
	ORL	R11, AX
	MOVBLZX	2(R9)(R10*1), R11
	SHLL	$13, R11
	ORL	R11, AX
	ADDQ	$3, R10
	JMP	lladd
ll2:
	LEAQ	2(R10), R11
	CMPQ	R11, NEXT
	JA	exit
	MOVBLZX	1(R9)(R10*1), R11
	SHLL	$6, R11
	ANDL	$0x3F, AX
	ORL	R11, AX
	ADDQ	$2, R10
	JMP	lladd
ll1:
	INCQ	R10
lladd:
	ADDQ	AX, CX
	MOVQ	R10, EPOS

llok:
	// ML field == 15: add a varint from the extras.
	CMPL	DX, $15
	JNE	mlok
	MOVQ	EPOS, R10
	CMPQ	R10, NEXT
	JAE	exit
	MOVQ	EXT, R9
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	ml1
	CMPL	AX, $0xC0
	JB	ml2
	CMPL	AX, $0xE0
	JAE	exit
	LEAQ	3(R10), R11
	CMPQ	R11, NEXT
	JA	exit
	MOVBLZX	1(R9)(R10*1), R11
	SHLL	$5, R11
	ANDL	$0x1F, AX
	ORL	R11, AX
	MOVBLZX	2(R9)(R10*1), R11
	SHLL	$13, R11
	ORL	R11, AX
	ADDQ	$3, R10
	JMP	mladd
ml2:
	LEAQ	2(R10), R11
	CMPQ	R11, NEXT
	JA	exit
	MOVBLZX	1(R9)(R10*1), R11
	SHLL	$6, R11
	ANDL	$0x3F, AX
	ORL	R11, AX
	ADDQ	$2, R10
	JMP	mladd
ml1:
	INCQ	R10
mladd:
	ADDQ	AX, DX
	MOVQ	R10, EPOS

mlok:
	ADDQ	$5, DX
	// off > d+ll, ll+ml > limit-d or ll > litEnd-l: leave it to decodeSPL.
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	exit
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JA	exit
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	CMPQ	CX, R9
	JA	exit

copy:
	// Literals: out[d:] <- lits[l:], 32 bytes at a time.
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	litdone
	MOVQ	$32, R9
litloop:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	litloop
litdone:
	ADDQ	CX, DI
	ADDQ	CX, BX

	// Match: out[d:] <- out[d-off:].
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	short
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	matchdone
	MOVQ	$32, R9
mloop:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	mloop
	JMP	matchdone

short:
	// Period off < 32: pattern[j] = out[d-off + j%off], j < 32.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
sloop:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	sloop

matchdone:
	ADDQ	DX, DI
	INCQ	SI
	ADDQ	$1, R13
	JMP	loop

exit:
	MOVQ	R12, EPOS
done:
	MOVQ	STATE, R10
	SUBQ	SEQS, SI
	MOVQ	SI, 56(R10)
	SUBQ	OUT, DI
	MOVQ	DI, 64(R10)
	SUBQ	LITS, BX
	MOVQ	BX, 72(R10)
	MOVQ	EPOS, R9
	MOVQ	R9, 80(R10)
	RET

// func splRunAsm16(st *splState)
TEXT ·splRunAsm16(SB), NOSPLIT, $112-8
	MOVQ	st+0(FP), R13
	MOVQ	R13, STATE
	MOVQ	0(R13), AX
	MOVQ	AX, OUT
	MOVQ	8(R13), R9
	MOVQ	R9, LITS
	MOVQ	16(R13), R10
	MOVQ	R10, SEQS
	MOVQ	24(R13), R11
	MOVQ	R11, EXT
	MOVQ	40(R13), R11
	ADDQ	R10, R11
	MOVQ	R11, SEQEND
	MOVQ	48(R13), R11
	MOVQ	R11, NEXT
	MOVQ	56(R13), SI
	ADDQ	R10, SI
	MOVQ	64(R13), DI
	ADDQ	AX, DI
	MOVQ	72(R13), BX
	ADDQ	R9, BX
	MOVQ	80(R13), R11
	MOVQ	R11, EPOS
	LEAQ	65536(AX), R11
	MOVQ	R11, OUT64K

	MOVQ	88(R13), R10        // limit
	LEAQ	(AX)(R10*1), R11
	MOVQ	R11, LIMITP
	LEAQ	-(4*33)(R10), R10
	LEAQ	(AX)(R10*1), R11
	XORL	R12, R12
	TESTQ	R10, R10
	CMOVQLT	R12, R11
	MOVQ	R11, DMAXP

	MOVQ	96(R13), R10        // litEnd
	LEAQ	(R9)(R10*1), R11
	MOVQ	R11, LITENDP
	LEAQ	-(4*14)(R10), R10
	LEAQ	(R9)(R10*1), R11
	XORL	R12, R12
	TESTQ	R10, R10
	CMOVQLT	R12, R11
	MOVQ	R11, LMAXP

	// R13 = &offs[w*i]
	MOVQ	56(R13), R10
	SHLQ	$1, R10
	ADDQ	32(R13), R10
	MOVQ	R10, R13

loop:
	CMPQ	SI, SEQEND
	JAE	done

	// Batch of 4, if it fits.
	LEAQ	4(SI), R9
	CMPQ	R9, SEQEND
	JA	single
	CMPQ	DI, DMAXP
	JA	single
	CMPQ	BX, LMAXP
	JA	single
	MOVQ	SEQEND, R11
	SUBQ	$4, R11
	CMPQ	DI, OUT64K
	JB	pbatchseq

qbatchseq:
	// Batch past 64 KiB of output: no offset test.

	// Sequence 0 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	0(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	qvar0
	CMPL	DX, $15
	JEQ	qmvar0
	ADDL	$5, DX
	MOVWLZX	0(R13), R8
	INCL	R8
qok0:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qshort0
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
qdone0:
	ADDQ	DX, DI

	// Sequence 1 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	1(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	qvar1
	CMPL	DX, $15
	JEQ	qmvar1
	ADDL	$5, DX
	MOVWLZX	2(R13), R8
	INCL	R8
qok1:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qshort1
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
qdone1:
	ADDQ	DX, DI

	// Sequence 2 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	2(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	qvar2
	CMPL	DX, $15
	JEQ	qmvar2
	ADDL	$5, DX
	MOVWLZX	4(R13), R8
	INCL	R8
qok2:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qshort2
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
qdone2:
	ADDQ	DX, DI

	// Sequence 3 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	3(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	qvar3
	CMPL	DX, $15
	JEQ	qmvar3
	ADDL	$5, DX
	MOVWLZX	6(R13), R8
	INCL	R8
qok3:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qshort3
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
qdone3:
	ADDQ	DX, DI
	ADDQ	$4, SI
	ADDQ	$8, R13
	CMPQ	SI, R11
	JA	loop
	CMPQ	DI, DMAXP
	JA	loop
	CMPQ	BX, LMAXP
	JBE	qbatchseq
	JMP	loop

qesc0:
	// A varint, or an offset to check: sequence 0 goes to the single path.
	ADDQ	$0, SI
	ADDQ	$0, R13
	JMP	single
qshort0:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	qdone0

qesc1:
	// A varint, or an offset to check: sequence 1 goes to the single path.
	ADDQ	$1, SI
	ADDQ	$2, R13
	JMP	single
qshort1:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	qdone1

qesc2:
	// A varint, or an offset to check: sequence 2 goes to the single path.
	ADDQ	$2, SI
	ADDQ	$4, R13
	JMP	single
qshort2:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	qdone2

qesc3:
	// A varint, or an offset to check: sequence 3 goes to the single path.
	ADDQ	$3, SI
	ADDQ	$6, R13
	JMP	single
qshort3:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	qdone3

qmvar0:
	// Sequence 0: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 3 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail0
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	qmvl0
	INCQ	R10
qmvv0:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVWLZX	0(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(3*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail0
qmvok0:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh0
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone0
	MOVQ	$32, R9
qmvm0:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qmvm0
	JMP	qdone0
qmvl0:
	CMPL	AX, $0xC0
	JB	qmv20
	CMPL	AX, $0xE0
	JAE	qvfail0
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qmvv0
qmv20:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qmvv0

qvar0:
	// Sequence 0 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 3 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	qvlo0
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail0
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qva0_1
	CMPL	AX, $0xC0
	JB	qva0_2
	CMPL	AX, $0xE0
	JAE	qvfail0
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qva0_x
qva0_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qva0_x
qva0_1:
	INCQ	R10
qva0_x:
	ADDQ	AX, CX
qvlo0:
	CMPL	DX, $15
	JNE	qvmo0
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail0
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qvb0_1
	CMPL	AX, $0xC0
	JB	qvb0_2
	CMPL	AX, $0xE0
	JAE	qvfail0
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qvb0_x
qvb0_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qvb0_x
qvb0_1:
	INCQ	R10
qvb0_x:
	ADDQ	AX, DX
qvmo0:
	MOVQ	R10, EPOS
	MOVWLZX	0(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(3*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail0
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(3*14), R9
	CMPQ	CX, R9
	JGT	qvfail0
qvok0:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	qvld0
	MOVQ	$32, R9
qvll0:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	qvll0
qvld0:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh0
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone0
	MOVQ	$32, R9
qvml0:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qvml0
	JMP	qdone0
qvsh0:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
qvsl0:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	qvsl0
	JMP	qdone0
qvfail0:
	// Not here: the single path takes sequence 0, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$0, SI
	ADDQ	$0, R13
	JMP	single

qmvar1:
	// Sequence 1: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 2 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail1
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	qmvl1
	INCQ	R10
qmvv1:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVWLZX	2(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(2*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail1
qmvok1:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh1
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone1
	MOVQ	$32, R9
qmvm1:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qmvm1
	JMP	qdone1
qmvl1:
	CMPL	AX, $0xC0
	JB	qmv21
	CMPL	AX, $0xE0
	JAE	qvfail1
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qmvv1
qmv21:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qmvv1

qvar1:
	// Sequence 1 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 2 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	qvlo1
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail1
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qva1_1
	CMPL	AX, $0xC0
	JB	qva1_2
	CMPL	AX, $0xE0
	JAE	qvfail1
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qva1_x
qva1_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qva1_x
qva1_1:
	INCQ	R10
qva1_x:
	ADDQ	AX, CX
qvlo1:
	CMPL	DX, $15
	JNE	qvmo1
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail1
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qvb1_1
	CMPL	AX, $0xC0
	JB	qvb1_2
	CMPL	AX, $0xE0
	JAE	qvfail1
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qvb1_x
qvb1_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qvb1_x
qvb1_1:
	INCQ	R10
qvb1_x:
	ADDQ	AX, DX
qvmo1:
	MOVQ	R10, EPOS
	MOVWLZX	2(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(2*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail1
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(2*14), R9
	CMPQ	CX, R9
	JGT	qvfail1
qvok1:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	qvld1
	MOVQ	$32, R9
qvll1:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	qvll1
qvld1:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh1
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone1
	MOVQ	$32, R9
qvml1:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qvml1
	JMP	qdone1
qvsh1:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
qvsl1:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	qvsl1
	JMP	qdone1
qvfail1:
	// Not here: the single path takes sequence 1, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$1, SI
	ADDQ	$2, R13
	JMP	single

qmvar2:
	// Sequence 2: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 1 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail2
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	qmvl2
	INCQ	R10
qmvv2:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVWLZX	4(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(1*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail2
qmvok2:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh2
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone2
	MOVQ	$32, R9
qmvm2:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qmvm2
	JMP	qdone2
qmvl2:
	CMPL	AX, $0xC0
	JB	qmv22
	CMPL	AX, $0xE0
	JAE	qvfail2
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qmvv2
qmv22:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qmvv2

qvar2:
	// Sequence 2 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 1 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	qvlo2
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail2
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qva2_1
	CMPL	AX, $0xC0
	JB	qva2_2
	CMPL	AX, $0xE0
	JAE	qvfail2
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qva2_x
qva2_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qva2_x
qva2_1:
	INCQ	R10
qva2_x:
	ADDQ	AX, CX
qvlo2:
	CMPL	DX, $15
	JNE	qvmo2
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail2
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qvb2_1
	CMPL	AX, $0xC0
	JB	qvb2_2
	CMPL	AX, $0xE0
	JAE	qvfail2
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qvb2_x
qvb2_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qvb2_x
qvb2_1:
	INCQ	R10
qvb2_x:
	ADDQ	AX, DX
qvmo2:
	MOVQ	R10, EPOS
	MOVWLZX	4(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(1*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail2
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(1*14), R9
	CMPQ	CX, R9
	JGT	qvfail2
qvok2:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	qvld2
	MOVQ	$32, R9
qvll2:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	qvll2
qvld2:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh2
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone2
	MOVQ	$32, R9
qvml2:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qvml2
	JMP	qdone2
qvsh2:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
qvsl2:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	qvsl2
	JMP	qdone2
qvfail2:
	// Not here: the single path takes sequence 2, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$2, SI
	ADDQ	$4, R13
	JMP	single

qmvar3:
	// Sequence 3: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 0 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail3
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	qmvl3
	INCQ	R10
qmvv3:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVWLZX	6(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(0*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail3
qmvok3:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh3
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone3
	MOVQ	$32, R9
qmvm3:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qmvm3
	JMP	qdone3
qmvl3:
	CMPL	AX, $0xC0
	JB	qmv23
	CMPL	AX, $0xE0
	JAE	qvfail3
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qmvv3
qmv23:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qmvv3

qvar3:
	// Sequence 3 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 0 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	qvlo3
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail3
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qva3_1
	CMPL	AX, $0xC0
	JB	qva3_2
	CMPL	AX, $0xE0
	JAE	qvfail3
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qva3_x
qva3_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qva3_x
qva3_1:
	INCQ	R10
qva3_x:
	ADDQ	AX, CX
qvlo3:
	CMPL	DX, $15
	JNE	qvmo3
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	qvfail3
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	qvb3_1
	CMPL	AX, $0xC0
	JB	qvb3_2
	CMPL	AX, $0xE0
	JAE	qvfail3
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	qvb3_x
qvb3_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	qvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	qvb3_x
qvb3_1:
	INCQ	R10
qvb3_x:
	ADDQ	AX, DX
qvmo3:
	MOVQ	R10, EPOS
	MOVWLZX	6(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(0*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	qvfail3
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(0*14), R9
	CMPQ	CX, R9
	JGT	qvfail3
qvok3:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	qvld3
	MOVQ	$32, R9
qvll3:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	qvll3
qvld3:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	qvsh3
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	qdone3
	MOVQ	$32, R9
qvml3:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	qvml3
	JMP	qdone3
qvsh3:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
qvsl3:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	qvsl3
	JMP	qdone3
qvfail3:
	// Not here: the single path takes sequence 3, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$3, SI
	ADDQ	$6, R13
	JMP	single


pbatchseq:
	// Batch below 64 KiB of output: off > d+ll leaves a sequence to
	// the single path.

	// Sequence 0 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	0(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	pvar0
	CMPL	DX, $15
	JEQ	pmvar0
	ADDL	$5, DX
	MOVWLZX	0(R13), R8
	INCL	R8
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pesc0
pok0:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pshort0
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
pdone0:
	ADDQ	DX, DI

	// Sequence 1 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	1(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	pvar1
	CMPL	DX, $15
	JEQ	pmvar1
	ADDL	$5, DX
	MOVWLZX	2(R13), R8
	INCL	R8
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pesc1
pok1:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pshort1
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
pdone1:
	ADDQ	DX, DI

	// Sequence 2 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	2(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	pvar2
	CMPL	DX, $15
	JEQ	pmvar2
	ADDL	$5, DX
	MOVWLZX	4(R13), R8
	INCL	R8
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pesc2
pok2:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pshort2
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
pdone2:
	ADDQ	DX, DI

	// Sequence 3 of the batch, straight-line: ll <= 14, ml <= 19.
	MOVBLZX	3(SI), CX
	MOVL	CX, DX
	SHRL	$4, CX
	ANDL	$15, DX
	CMPL	CX, $15
	JEQ	pvar3
	CMPL	DX, $15
	JEQ	pmvar3
	ADDL	$5, DX
	MOVWLZX	6(R13), R8
	INCL	R8
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pesc3
pok3:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pshort3
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
pdone3:
	ADDQ	DX, DI
	ADDQ	$4, SI
	ADDQ	$8, R13
	CMPQ	SI, R11
	JA	loop
	CMPQ	DI, DMAXP
	JA	loop
	CMPQ	BX, LMAXP
	JA	loop
	CMPQ	DI, OUT64K
	JB	pbatchseq
	JMP	qbatchseq

pesc0:
	// A varint, or an offset to check: sequence 0 goes to the single path.
	ADDQ	$0, SI
	ADDQ	$0, R13
	JMP	single
pshort0:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	pdone0

pesc1:
	// A varint, or an offset to check: sequence 1 goes to the single path.
	ADDQ	$1, SI
	ADDQ	$2, R13
	JMP	single
pshort1:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	pdone1

pesc2:
	// A varint, or an offset to check: sequence 2 goes to the single path.
	ADDQ	$2, SI
	ADDQ	$4, R13
	JMP	single
pshort2:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	pdone2

pesc3:
	// A varint, or an offset to check: sequence 3 goes to the single path.
	ADDQ	$3, SI
	ADDQ	$6, R13
	JMP	single
pshort3:
	// Period below 32: one store of the 32-byte pattern covers ml <= 19.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	MOVOU	X2, (DI)
	MOVOU	X5, 16(DI)
	JMP	pdone3

pmvar0:
	// Sequence 0: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 3 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail0
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	pmvl0
	INCQ	R10
pmvv0:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVWLZX	0(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(3*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail0
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail0
pmvok0:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh0
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone0
	MOVQ	$32, R9
pmvm0:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pmvm0
	JMP	pdone0
pmvl0:
	CMPL	AX, $0xC0
	JB	pmv20
	CMPL	AX, $0xE0
	JAE	pvfail0
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pmvv0
pmv20:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pmvv0

pvar0:
	// Sequence 0 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 3 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	pvlo0
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail0
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pva0_1
	CMPL	AX, $0xC0
	JB	pva0_2
	CMPL	AX, $0xE0
	JAE	pvfail0
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pva0_x
pva0_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pva0_x
pva0_1:
	INCQ	R10
pva0_x:
	ADDQ	AX, CX
pvlo0:
	CMPL	DX, $15
	JNE	pvmo0
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail0
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pvb0_1
	CMPL	AX, $0xC0
	JB	pvb0_2
	CMPL	AX, $0xE0
	JAE	pvfail0
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pvb0_x
pvb0_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail0
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pvb0_x
pvb0_1:
	INCQ	R10
pvb0_x:
	ADDQ	AX, DX
pvmo0:
	MOVQ	R10, EPOS
	MOVWLZX	0(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(3*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail0
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(3*14), R9
	CMPQ	CX, R9
	JGT	pvfail0
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail0
pvok0:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	pvld0
	MOVQ	$32, R9
pvll0:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	pvll0
pvld0:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh0
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone0
	MOVQ	$32, R9
pvml0:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pvml0
	JMP	pdone0
pvsh0:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
pvsl0:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	pvsl0
	JMP	pdone0
pvfail0:
	// Not here: the single path takes sequence 0, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$0, SI
	ADDQ	$0, R13
	JMP	single

pmvar1:
	// Sequence 1: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 2 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail1
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	pmvl1
	INCQ	R10
pmvv1:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVWLZX	2(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(2*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail1
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail1
pmvok1:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh1
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone1
	MOVQ	$32, R9
pmvm1:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pmvm1
	JMP	pdone1
pmvl1:
	CMPL	AX, $0xC0
	JB	pmv21
	CMPL	AX, $0xE0
	JAE	pvfail1
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pmvv1
pmv21:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pmvv1

pvar1:
	// Sequence 1 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 2 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	pvlo1
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail1
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pva1_1
	CMPL	AX, $0xC0
	JB	pva1_2
	CMPL	AX, $0xE0
	JAE	pvfail1
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pva1_x
pva1_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pva1_x
pva1_1:
	INCQ	R10
pva1_x:
	ADDQ	AX, CX
pvlo1:
	CMPL	DX, $15
	JNE	pvmo1
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail1
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pvb1_1
	CMPL	AX, $0xC0
	JB	pvb1_2
	CMPL	AX, $0xE0
	JAE	pvfail1
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pvb1_x
pvb1_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail1
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pvb1_x
pvb1_1:
	INCQ	R10
pvb1_x:
	ADDQ	AX, DX
pvmo1:
	MOVQ	R10, EPOS
	MOVWLZX	2(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(2*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail1
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(2*14), R9
	CMPQ	CX, R9
	JGT	pvfail1
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail1
pvok1:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	pvld1
	MOVQ	$32, R9
pvll1:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	pvll1
pvld1:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh1
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone1
	MOVQ	$32, R9
pvml1:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pvml1
	JMP	pdone1
pvsh1:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
pvsl1:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	pvsl1
	JMP	pdone1
pvfail1:
	// Not here: the single path takes sequence 1, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$1, SI
	ADDQ	$2, R13
	JMP	single

pmvar2:
	// Sequence 2: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 1 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail2
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	pmvl2
	INCQ	R10
pmvv2:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVWLZX	4(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(1*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail2
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail2
pmvok2:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh2
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone2
	MOVQ	$32, R9
pmvm2:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pmvm2
	JMP	pdone2
pmvl2:
	CMPL	AX, $0xC0
	JB	pmv22
	CMPL	AX, $0xE0
	JAE	pvfail2
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pmvv2
pmv22:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pmvv2

pvar2:
	// Sequence 2 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 1 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	pvlo2
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail2
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pva2_1
	CMPL	AX, $0xC0
	JB	pva2_2
	CMPL	AX, $0xE0
	JAE	pvfail2
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pva2_x
pva2_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pva2_x
pva2_1:
	INCQ	R10
pva2_x:
	ADDQ	AX, CX
pvlo2:
	CMPL	DX, $15
	JNE	pvmo2
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail2
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pvb2_1
	CMPL	AX, $0xC0
	JB	pvb2_2
	CMPL	AX, $0xE0
	JAE	pvfail2
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pvb2_x
pvb2_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail2
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pvb2_x
pvb2_1:
	INCQ	R10
pvb2_x:
	ADDQ	AX, DX
pvmo2:
	MOVQ	R10, EPOS
	MOVWLZX	4(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(1*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail2
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(1*14), R9
	CMPQ	CX, R9
	JGT	pvfail2
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail2
pvok2:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	pvld2
	MOVQ	$32, R9
pvll2:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	pvll2
pvld2:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh2
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone2
	MOVQ	$32, R9
pvml2:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pvml2
	JMP	pdone2
pvsh2:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
pvsl2:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	pvsl2
	JMP	pdone2
pvfail2:
	// Not here: the single path takes sequence 2, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$2, SI
	ADDQ	$4, R13
	JMP	single

pmvar3:
	// Sequence 3: a varint on ml only, ll <= 14. The literals keep the
	// 16-byte copy and the batch literal bound; the match must still leave
	// room for the 0 sequences after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail3
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JAE	pmvl3
	INCQ	R10
pmvv3:
	ADDQ	AX, DX
	MOVQ	R10, EPOS
	MOVWLZX	6(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(0*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail3
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail3
pmvok3:
	MOVOU	(BX), X0
	MOVOU	X0, (DI)
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh3
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone3
	MOVQ	$32, R9
pmvm3:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pmvm3
	JMP	pdone3
pmvl3:
	CMPL	AX, $0xC0
	JB	pmv23
	CMPL	AX, $0xE0
	JAE	pvfail3
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pmvv3
pmv23:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pmvv3

pvar3:
	// Sequence 3 announces a varint: decode it here, and keep the batch
	// if the longer sequence still leaves room for the 0 after it.
	MOVQ	EPOS, R10
	MOVQ	R10, ESAVE
	CMPL	CX, $15
	JNE	pvlo3
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail3
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pva3_1
	CMPL	AX, $0xC0
	JB	pva3_2
	CMPL	AX, $0xE0
	JAE	pvfail3
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pva3_x
pva3_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pva3_x
pva3_1:
	INCQ	R10
pva3_x:
	ADDQ	AX, CX
pvlo3:
	CMPL	DX, $15
	JNE	pvmo3
	MOVQ	EXT, R9
	CMPQ	R10, NEXT
	JAE	pvfail3
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	pvb3_1
	CMPL	AX, $0xC0
	JB	pvb3_2
	CMPL	AX, $0xE0
	JAE	pvfail3
	LEAQ	3(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$5, R12
	ANDL	$0x1F, AX
	ORL	R12, AX
	MOVBLZX	2(R9)(R10*1), R12
	SHLL	$13, R12
	ORL	R12, AX
	ADDQ	$3, R10
	JMP	pvb3_x
pvb3_2:
	LEAQ	2(R10), R12
	CMPQ	R12, NEXT
	JA	pvfail3
	MOVBLZX	1(R9)(R10*1), R12
	SHLL	$6, R12
	ANDL	$0x3F, AX
	ORL	R12, AX
	ADDQ	$2, R10
	JMP	pvb3_x
pvb3_1:
	INCQ	R10
pvb3_x:
	ADDQ	AX, DX
pvmo3:
	MOVQ	R10, EPOS
	MOVWLZX	6(R13), R8
	INCL	R8
	ADDQ	$5, DX
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	SUBQ	$(0*33), R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JGT	pvfail3
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	SUBQ	$(0*14), R9
	CMPQ	CX, R9
	JGT	pvfail3
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	pvfail3
pvok3:
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	pvld3
	MOVQ	$32, R9
pvll3:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	pvll3
pvld3:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	pvsh3
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	pdone3
	MOVQ	$32, R9
pvml3:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	pvml3
	JMP	pdone3
pvsh3:
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
pvsl3:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	pvsl3
	JMP	pdone3
pvfail3:
	// Not here: the single path takes sequence 3, extras position restored.
	MOVQ	ESAVE, R10
	MOVQ	R10, EPOS
	ADDQ	$3, SI
	ADDQ	$6, R13
	JMP	single

single:
	MOVQ	EPOS, R12
	FETCH16

	// LL == 15: add a varint from the extras.
	CMPL	CX, $15
	JNE	llok
	MOVQ	EPOS, R10
	CMPQ	R10, NEXT
	JAE	exit
	MOVQ	EXT, R9
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	ll1
	CMPL	AX, $0xC0
	JB	ll2
	CMPL	AX, $0xE0
	JAE	exit
	LEAQ	3(R10), R11
	CMPQ	R11, NEXT
	JA	exit
	MOVBLZX	1(R9)(R10*1), R11
	SHLL	$5, R11
	ANDL	$0x1F, AX
	ORL	R11, AX
	MOVBLZX	2(R9)(R10*1), R11
	SHLL	$13, R11
	ORL	R11, AX
	ADDQ	$3, R10
	JMP	lladd
ll2:
	LEAQ	2(R10), R11
	CMPQ	R11, NEXT
	JA	exit
	MOVBLZX	1(R9)(R10*1), R11
	SHLL	$6, R11
	ANDL	$0x3F, AX
	ORL	R11, AX
	ADDQ	$2, R10
	JMP	lladd
ll1:
	INCQ	R10
lladd:
	ADDQ	AX, CX
	MOVQ	R10, EPOS

llok:
	// ML field == 15: add a varint from the extras.
	CMPL	DX, $15
	JNE	mlok
	MOVQ	EPOS, R10
	CMPQ	R10, NEXT
	JAE	exit
	MOVQ	EXT, R9
	MOVBLZX	(R9)(R10*1), AX
	CMPL	AX, $0x80
	JB	ml1
	CMPL	AX, $0xC0
	JB	ml2
	CMPL	AX, $0xE0
	JAE	exit
	LEAQ	3(R10), R11
	CMPQ	R11, NEXT
	JA	exit
	MOVBLZX	1(R9)(R10*1), R11
	SHLL	$5, R11
	ANDL	$0x1F, AX
	ORL	R11, AX
	MOVBLZX	2(R9)(R10*1), R11
	SHLL	$13, R11
	ORL	R11, AX
	ADDQ	$3, R10
	JMP	mladd
ml2:
	LEAQ	2(R10), R11
	CMPQ	R11, NEXT
	JA	exit
	MOVBLZX	1(R9)(R10*1), R11
	SHLL	$6, R11
	ANDL	$0x3F, AX
	ORL	R11, AX
	ADDQ	$2, R10
	JMP	mladd
ml1:
	INCQ	R10
mladd:
	ADDQ	AX, DX
	MOVQ	R10, EPOS

mlok:
	ADDQ	$5, DX
	// off > d+ll, ll+ml > limit-d or ll > litEnd-l: leave it to decodeSPL.
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	exit
	MOVQ	LIMITP, R9
	SUBQ	DI, R9
	LEAQ	(CX)(DX*1), R10
	CMPQ	R10, R9
	JA	exit
	MOVQ	LITENDP, R9
	SUBQ	BX, R9
	CMPQ	CX, R9
	JA	exit

copy:
	// Literals: out[d:] <- lits[l:], 32 bytes at a time.
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JBE	litdone
	MOVQ	$32, R9
litloop:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	litloop
litdone:
	ADDQ	CX, DI
	ADDQ	CX, BX

	// Match: out[d:] <- out[d-off:].
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	short
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JBE	matchdone
	MOVQ	$32, R9
mloop:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	mloop
	JMP	matchdone

short:
	// Period off < 32: pattern[j] = out[d-off + j%off], j < 32.
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVQ	R8, R9
	SHLQ	$6, R9
	LEAQ	·pakShuf(SB), R10
	ADDQ	R10, R9
	MOVOU	0(R9), X4
	MOVO	X0, X2
	PSHUFB	X4, X2
	MOVOU	32(R9), X4
	MOVO	X1, X3
	PSHUFB	X4, X3
	POR	X3, X2
	MOVOU	16(R9), X4
	MOVO	X0, X5
	PSHUFB	X4, X5
	MOVOU	48(R9), X4
	MOVO	X1, X6
	PSHUFB	X4, X6
	POR	X6, X5
	LEAQ	·pakStrides(SB), R9
	MOVBQZX	(R9)(R8*1), AX
	XORL	R9, R9
sloop:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	sloop

matchdone:
	ADDQ	DX, DI
	INCQ	SI
	ADDQ	$2, R13
	JMP	loop

exit:
	MOVQ	R12, EPOS
done:
	MOVQ	STATE, R10
	SUBQ	SEQS, SI
	MOVQ	SI, 56(R10)
	SUBQ	OUT, DI
	MOVQ	DI, 64(R10)
	SUBQ	LITS, BX
	MOVQ	BX, 72(R10)
	MOVQ	EPOS, R9
	MOVQ	R9, 80(R10)
	RET
