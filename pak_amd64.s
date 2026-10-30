//go:build !purego

#include "textflag.h"

// PAK sequence loop for amd64, called through pakRun (pakrun_asm.go), which
// checks the invariants this code relies on; its comment gives the proof
// of the accesses. Same structure as pak_arm64.s:
//   - batch: while at least 4 sequences remain, d <= limit - 4*513 and
//     l <= litEnd - 4*254, the next 4 sequences cannot pass the block or
//     the literals unless one has a varint, so they are taken with no
//     bounds test; once d >= 64 KiB no 16-bit offset can reach before
//     the window either, so the offset test goes too. A sequence with a
//     varint leaves the batch for the single path.
//   - single: one sequence with every test, varints included; it stops
//     the loop on anything the checked Go path must handle.
//
// A batch is unrolled and laid out like the reference decoder's: the
// common case of each of its 4 sequences (ll and ml up to 32, offset 32
// or more, past 64 KiB of output) runs straight through, with no taken
// branch; the rest jumps out of line and back: the copy loops past 32
// bytes, the short periods, and the exit on a varint. There are two
// copies of the batch: pre, below 64 KiB of output, tests each offset;
// post, past it, has no offset test at all, and once there the loop never
// goes back to pre. The sequence pointer advances once per batch, the fields
// of sequence k being read at 4k(SI) as bytes and a 16-bit word; a
// sequence that leaves the batch sets SI to itself on the way out, the
// sequences before it staying done.
//
// Copies move 32 bytes through two 16-byte SSE registers (MOVOU). Matches
// at distance 1 to 31 load the 32 bytes at out[d-off] into X0 and X1 and
// build the 32-byte pattern out[d-off + j%off] with four PSHUFB (SSSE3):
// pakShuf holds, per offset, the indices of the bytes taken from X0 and
// from X1 (0x80, which PSHUFB turns into 0, for the others). The pattern
// is stored at a stride that keeps the period in phase.
//
// amd64 has fewer registers than arm64: the values used once per batch or
// only on the single path live in the frame.
//
// Registers:
//   SI &seqs[i]   DI &out[d]   BX &lits[l]
//   CX ll         DX ml        R8 off         AX sequence word, then scratch
//   R11 batch: &seqs[nSeq-4]; single: scratch
//   R12 batch: DMAXP; single: e at the sequence start
//   R13 batch: LMAXP (STATE is reloaded on exit)
//   R9 R10 scratch; X0-X6 copies
//
// Frame:
#define OUT 0(SP)       // out
#define LITS 8(SP)      // lits
#define SEQS 16(SP)     // seqs
#define SEQEND 24(SP)   // &seqs[nSeq]
#define LIMITP 32(SP)   // &out[limit]
#define LITENDP 40(SP)  // &lits[litEnd]
#define DMAXP 48(SP)    // &out[limit - 4*513], 0 if negative
#define LMAXP 56(SP)    // &lits[litEnd - 4*254], 0 if negative
#define EXT 64(SP)      // extras
#define NEXT 72(SP)     // nExt
#define OUT64K 80(SP)   // &out[65536]
#define STATE 88(SP)    // *pakState
#define EPOS 96(SP)     // e

// func pakRunAsm(st *pakState)
TEXT ·pakRunAsm(SB), NOSPLIT, $104-8
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
	MOVQ	32(R13), R11
	ADDQ	R10, R11
	MOVQ	R11, SEQEND
	MOVQ	40(R13), R11
	MOVQ	R11, NEXT
	MOVQ	48(R13), SI
	ADDQ	R10, SI
	MOVQ	56(R13), DI
	ADDQ	AX, DI
	MOVQ	64(R13), BX
	ADDQ	R9, BX
	MOVQ	72(R13), R11
	MOVQ	R11, EPOS
	LEAQ	65536(AX), R11
	MOVQ	R11, OUT64K

	MOVQ	80(R13), R10        // limit
	LEAQ	(AX)(R10*1), R11
	MOVQ	R11, LIMITP
	LEAQ	-(4*513)(R10), R10
	LEAQ	(AX)(R10*1), R11
	XORL	R12, R12
	TESTQ	R10, R10
	CMOVQLT	R12, R11
	MOVQ	R11, DMAXP

	MOVQ	88(R13), R10        // litEnd
	LEAQ	(R9)(R10*1), R11
	MOVQ	R11, LITENDP
	LEAQ	-(4*254)(R10), R10
	LEAQ	(R9)(R10*1), R11
	XORL	R12, R12
	TESTQ	R10, R10
	CMOVQLT	R12, R11
	MOVQ	R11, LMAXP

loop:
	CMPQ	SI, SEQEND
	JAE	done

	// Batch of 4, if it fits. In the batch, R11 is the last sequence a
	// batch can start at, &seqs[nSeq-4], R12 DMAXP and R13 LMAXP.
	LEAQ	16(SI), R9
	CMPQ	R9, SEQEND
	JA	single
	CMPQ	DI, DMAXP
	JA	single
	CMPQ	BX, LMAXP
	JA	single
	MOVQ	SEQEND, R11
	SUBQ	$16, R11
	MOVQ	DMAXP, R12
	MOVQ	LMAXP, R13
	CMPQ	DI, OUT64K
	JB	pre

post:
	// Batch past 64 KiB of output: no offset test.

	// Sequence 0 of the batch, straight-line in the common case.
	MOVBLZX	3(SI), CX
	MOVBLZX	2(SI), DX
	CMPL	CX, $255
	JEQ	escq0
	CMPL	DX, $255
	JEQ	escq0
	MOVWLZX	0(SI), R8
	INCL	R8
	ADDL	$5, DX
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JA	litlongq0
litdoneq0:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	shortq0
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JA	mlongq0
doneq0:
	ADDQ	DX, DI

	// Sequence 1 of the batch, straight-line in the common case.
	MOVBLZX	7(SI), CX
	MOVBLZX	6(SI), DX
	CMPL	CX, $255
	JEQ	escq1
	CMPL	DX, $255
	JEQ	escq1
	MOVWLZX	4(SI), R8
	INCL	R8
	ADDL	$5, DX
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JA	litlongq1
litdoneq1:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	shortq1
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JA	mlongq1
doneq1:
	ADDQ	DX, DI

	// Sequence 2 of the batch, straight-line in the common case.
	MOVBLZX	11(SI), CX
	MOVBLZX	10(SI), DX
	CMPL	CX, $255
	JEQ	escq2
	CMPL	DX, $255
	JEQ	escq2
	MOVWLZX	8(SI), R8
	INCL	R8
	ADDL	$5, DX
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JA	litlongq2
litdoneq2:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	shortq2
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JA	mlongq2
doneq2:
	ADDQ	DX, DI

	// Sequence 3 of the batch, straight-line in the common case.
	MOVBLZX	15(SI), CX
	MOVBLZX	14(SI), DX
	CMPL	CX, $255
	JEQ	escq3
	CMPL	DX, $255
	JEQ	escq3
	MOVWLZX	12(SI), R8
	INCL	R8
	ADDL	$5, DX
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JA	litlongq3
litdoneq3:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	shortq3
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JA	mlongq3
doneq3:
	ADDQ	DX, DI

	// Next batch, if it fits.
	ADDQ	$16, SI
	CMPQ	SI, R11
	JA	loop
	CMPQ	DI, R12
	JA	loop
	CMPQ	BX, R13
	JBE	post
	JMP	loop

escq0:
	// A varint, or an offset to check: sequence 0 goes to the single path.
	JMP	single
litlongq0:
	// Literals past 32 bytes.
	MOVQ	$32, R9
blq0:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	blq0
	JMP	litdoneq0
mlongq0:
	// Match past 32 bytes, offset 32 or more.
	MOVQ	$32, R9
bmq0:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	bmq0
	JMP	doneq0
shortq0:
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
slq0:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	slq0
	JMP	doneq0

escq1:
	// A varint, or an offset to check: sequence 1 goes to the single path.
	ADDQ	$4, SI
	JMP	single
litlongq1:
	// Literals past 32 bytes.
	MOVQ	$32, R9
blq1:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	blq1
	JMP	litdoneq1
mlongq1:
	// Match past 32 bytes, offset 32 or more.
	MOVQ	$32, R9
bmq1:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	bmq1
	JMP	doneq1
shortq1:
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
slq1:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	slq1
	JMP	doneq1

escq2:
	// A varint, or an offset to check: sequence 2 goes to the single path.
	ADDQ	$8, SI
	JMP	single
litlongq2:
	// Literals past 32 bytes.
	MOVQ	$32, R9
blq2:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	blq2
	JMP	litdoneq2
mlongq2:
	// Match past 32 bytes, offset 32 or more.
	MOVQ	$32, R9
bmq2:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	bmq2
	JMP	doneq2
shortq2:
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
slq2:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	slq2
	JMP	doneq2

escq3:
	// A varint, or an offset to check: sequence 3 goes to the single path.
	ADDQ	$12, SI
	JMP	single
litlongq3:
	// Literals past 32 bytes.
	MOVQ	$32, R9
blq3:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	blq3
	JMP	litdoneq3
mlongq3:
	// Match past 32 bytes, offset 32 or more.
	MOVQ	$32, R9
bmq3:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	bmq3
	JMP	doneq3
shortq3:
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
slq3:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	slq3
	JMP	doneq3

pre:
	// Batch below 64 KiB of output: off > d+ll leaves a sequence to the
	// single path.

	// Sequence 0 of the batch, straight-line in the common case.
	MOVBLZX	3(SI), CX
	MOVBLZX	2(SI), DX
	CMPL	CX, $255
	JEQ	escp0
	CMPL	DX, $255
	JEQ	escp0
	MOVWLZX	0(SI), R8
	INCL	R8
	ADDL	$5, DX
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	escp0
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JA	litlongp0
litdonep0:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	shortp0
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JA	mlongp0
donep0:
	ADDQ	DX, DI

	// Sequence 1 of the batch, straight-line in the common case.
	MOVBLZX	7(SI), CX
	MOVBLZX	6(SI), DX
	CMPL	CX, $255
	JEQ	escp1
	CMPL	DX, $255
	JEQ	escp1
	MOVWLZX	4(SI), R8
	INCL	R8
	ADDL	$5, DX
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	escp1
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JA	litlongp1
litdonep1:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	shortp1
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JA	mlongp1
donep1:
	ADDQ	DX, DI

	// Sequence 2 of the batch, straight-line in the common case.
	MOVBLZX	11(SI), CX
	MOVBLZX	10(SI), DX
	CMPL	CX, $255
	JEQ	escp2
	CMPL	DX, $255
	JEQ	escp2
	MOVWLZX	8(SI), R8
	INCL	R8
	ADDL	$5, DX
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	escp2
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JA	litlongp2
litdonep2:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	shortp2
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JA	mlongp2
donep2:
	ADDQ	DX, DI

	// Sequence 3 of the batch, straight-line in the common case.
	MOVBLZX	15(SI), CX
	MOVBLZX	14(SI), DX
	CMPL	CX, $255
	JEQ	escp3
	CMPL	DX, $255
	JEQ	escp3
	MOVWLZX	12(SI), R8
	INCL	R8
	ADDL	$5, DX
	MOVQ	DI, R9
	SUBQ	OUT, R9
	ADDQ	CX, R9
	CMPQ	R8, R9
	JA	escp3
	MOVOU	(BX), X0
	MOVOU	16(BX), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	CX, $32
	JA	litlongp3
litdonep3:
	ADDQ	CX, DI
	ADDQ	CX, BX
	MOVQ	DI, R10
	SUBQ	R8, R10
	CMPQ	R8, $32
	JB	shortp3
	MOVOU	(R10), X0
	MOVOU	16(R10), X1
	MOVOU	X0, (DI)
	MOVOU	X1, 16(DI)
	CMPQ	DX, $32
	JA	mlongp3
donep3:
	ADDQ	DX, DI

	// Next batch, if it fits, below or past 64 KiB.
	ADDQ	$16, SI
	CMPQ	SI, R11
	JA	loop
	CMPQ	DI, R12
	JA	loop
	CMPQ	BX, R13
	JA	loop
	CMPQ	DI, OUT64K
	JB	pre
	JMP	post

escp0:
	// A varint, or an offset to check: sequence 0 goes to the single path.
	JMP	single
litlongp0:
	// Literals past 32 bytes.
	MOVQ	$32, R9
blp0:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	blp0
	JMP	litdonep0
mlongp0:
	// Match past 32 bytes, offset 32 or more.
	MOVQ	$32, R9
bmp0:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	bmp0
	JMP	donep0
shortp0:
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
slp0:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	slp0
	JMP	donep0

escp1:
	// A varint, or an offset to check: sequence 1 goes to the single path.
	ADDQ	$4, SI
	JMP	single
litlongp1:
	// Literals past 32 bytes.
	MOVQ	$32, R9
blp1:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	blp1
	JMP	litdonep1
mlongp1:
	// Match past 32 bytes, offset 32 or more.
	MOVQ	$32, R9
bmp1:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	bmp1
	JMP	donep1
shortp1:
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
slp1:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	slp1
	JMP	donep1

escp2:
	// A varint, or an offset to check: sequence 2 goes to the single path.
	ADDQ	$8, SI
	JMP	single
litlongp2:
	// Literals past 32 bytes.
	MOVQ	$32, R9
blp2:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	blp2
	JMP	litdonep2
mlongp2:
	// Match past 32 bytes, offset 32 or more.
	MOVQ	$32, R9
bmp2:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	bmp2
	JMP	donep2
shortp2:
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
slp2:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	slp2
	JMP	donep2

escp3:
	// A varint, or an offset to check: sequence 3 goes to the single path.
	ADDQ	$12, SI
	JMP	single
litlongp3:
	// Literals past 32 bytes.
	MOVQ	$32, R9
blp3:
	MOVOU	(BX)(R9*1), X0
	MOVOU	16(BX)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, CX
	JB	blp3
	JMP	litdonep3
mlongp3:
	// Match past 32 bytes, offset 32 or more.
	MOVQ	$32, R9
bmp3:
	MOVOU	(R10)(R9*1), X0
	MOVOU	16(R10)(R9*1), X1
	MOVOU	X0, (DI)(R9*1)
	MOVOU	X1, 16(DI)(R9*1)
	ADDQ	$32, R9
	CMPQ	R9, DX
	JB	bmp3
	JMP	donep3
shortp3:
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
slp3:
	MOVOU	X2, (DI)(R9*1)
	MOVOU	X5, 16(DI)(R9*1)
	ADDQ	AX, R9
	CMPQ	R9, DX
	JB	slp3
	JMP	donep3

single:
	MOVQ	EPOS, R12
	MOVL	(SI), AX
	MOVL	AX, CX
	SHRL	$24, CX
	MOVL	AX, DX
	SHRL	$16, DX
	ANDL	$0xFF, DX
	MOVL	AX, R8
	ANDL	$0xFFFF, R8
	INCL	R8

	// LL == 255: add a varint from the extras.
	CMPL	CX, $255
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
	// ML field == 255: add a varint from the extras.
	CMPL	DX, $255
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
	// off > d+ll, ll+ml > limit-d or ll > litEnd-l: leave it to decodePAK.
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
	ADDQ	$4, SI
	JMP	loop

exit:
	MOVQ	R12, EPOS
done:
	MOVQ	STATE, R13
	SUBQ	SEQS, SI
	MOVQ	SI, 48(R13)
	SUBQ	OUT, DI
	MOVQ	DI, 56(R13)
	SUBQ	LITS, BX
	MOVQ	BX, 64(R13)
	MOVQ	EPOS, R10
	MOVQ	R10, 72(R13)
	RET

// pakShuf[off]: PSHUFB indices into X0 (bytes 0-31) and into X1 (bytes
// 32-63) for pattern bytes 0-15 and 16-31; pakStrides[off] is the largest
// multiple of off not above 32.
DATA	·pakShuf+0(SB)/8, $0x0000000000000000
DATA	·pakShuf+8(SB)/8, $0x0000000000000000
DATA	·pakShuf+16(SB)/8, $0x0000000000000000
DATA	·pakShuf+24(SB)/8, $0x0000000000000000
DATA	·pakShuf+32(SB)/8, $0x8080808080808080
DATA	·pakShuf+40(SB)/8, $0x8080808080808080
DATA	·pakShuf+48(SB)/8, $0x8080808080808080
DATA	·pakShuf+56(SB)/8, $0x8080808080808080
DATA	·pakShuf+64(SB)/8, $0x0000000000000000
DATA	·pakShuf+72(SB)/8, $0x0000000000000000
DATA	·pakShuf+80(SB)/8, $0x0000000000000000
DATA	·pakShuf+88(SB)/8, $0x0000000000000000
DATA	·pakShuf+96(SB)/8, $0x8080808080808080
DATA	·pakShuf+104(SB)/8, $0x8080808080808080
DATA	·pakShuf+112(SB)/8, $0x8080808080808080
DATA	·pakShuf+120(SB)/8, $0x8080808080808080
DATA	·pakShuf+128(SB)/8, $0x0100010001000100
DATA	·pakShuf+136(SB)/8, $0x0100010001000100
DATA	·pakShuf+144(SB)/8, $0x0100010001000100
DATA	·pakShuf+152(SB)/8, $0x0100010001000100
DATA	·pakShuf+160(SB)/8, $0x8080808080808080
DATA	·pakShuf+168(SB)/8, $0x8080808080808080
DATA	·pakShuf+176(SB)/8, $0x8080808080808080
DATA	·pakShuf+184(SB)/8, $0x8080808080808080
DATA	·pakShuf+192(SB)/8, $0x0100020100020100
DATA	·pakShuf+200(SB)/8, $0x0002010002010002
DATA	·pakShuf+208(SB)/8, $0x0201000201000201
DATA	·pakShuf+216(SB)/8, $0x0100020100020100
DATA	·pakShuf+224(SB)/8, $0x8080808080808080
DATA	·pakShuf+232(SB)/8, $0x8080808080808080
DATA	·pakShuf+240(SB)/8, $0x8080808080808080
DATA	·pakShuf+248(SB)/8, $0x8080808080808080
DATA	·pakShuf+256(SB)/8, $0x0302010003020100
DATA	·pakShuf+264(SB)/8, $0x0302010003020100
DATA	·pakShuf+272(SB)/8, $0x0302010003020100
DATA	·pakShuf+280(SB)/8, $0x0302010003020100
DATA	·pakShuf+288(SB)/8, $0x8080808080808080
DATA	·pakShuf+296(SB)/8, $0x8080808080808080
DATA	·pakShuf+304(SB)/8, $0x8080808080808080
DATA	·pakShuf+312(SB)/8, $0x8080808080808080
DATA	·pakShuf+320(SB)/8, $0x0201000403020100
DATA	·pakShuf+328(SB)/8, $0x0004030201000403
DATA	·pakShuf+336(SB)/8, $0x0302010004030201
DATA	·pakShuf+344(SB)/8, $0x0100040302010004
DATA	·pakShuf+352(SB)/8, $0x8080808080808080
DATA	·pakShuf+360(SB)/8, $0x8080808080808080
DATA	·pakShuf+368(SB)/8, $0x8080808080808080
DATA	·pakShuf+376(SB)/8, $0x8080808080808080
DATA	·pakShuf+384(SB)/8, $0x0100050403020100
DATA	·pakShuf+392(SB)/8, $0x0302010005040302
DATA	·pakShuf+400(SB)/8, $0x0504030201000504
DATA	·pakShuf+408(SB)/8, $0x0100050403020100
DATA	·pakShuf+416(SB)/8, $0x8080808080808080
DATA	·pakShuf+424(SB)/8, $0x8080808080808080
DATA	·pakShuf+432(SB)/8, $0x8080808080808080
DATA	·pakShuf+440(SB)/8, $0x8080808080808080
DATA	·pakShuf+448(SB)/8, $0x0006050403020100
DATA	·pakShuf+456(SB)/8, $0x0100060504030201
DATA	·pakShuf+464(SB)/8, $0x0201000605040302
DATA	·pakShuf+472(SB)/8, $0x0302010006050403
DATA	·pakShuf+480(SB)/8, $0x8080808080808080
DATA	·pakShuf+488(SB)/8, $0x8080808080808080
DATA	·pakShuf+496(SB)/8, $0x8080808080808080
DATA	·pakShuf+504(SB)/8, $0x8080808080808080
DATA	·pakShuf+512(SB)/8, $0x0706050403020100
DATA	·pakShuf+520(SB)/8, $0x0706050403020100
DATA	·pakShuf+528(SB)/8, $0x0706050403020100
DATA	·pakShuf+536(SB)/8, $0x0706050403020100
DATA	·pakShuf+544(SB)/8, $0x8080808080808080
DATA	·pakShuf+552(SB)/8, $0x8080808080808080
DATA	·pakShuf+560(SB)/8, $0x8080808080808080
DATA	·pakShuf+568(SB)/8, $0x8080808080808080
DATA	·pakShuf+576(SB)/8, $0x0706050403020100
DATA	·pakShuf+584(SB)/8, $0x0605040302010008
DATA	·pakShuf+592(SB)/8, $0x0504030201000807
DATA	·pakShuf+600(SB)/8, $0x0403020100080706
DATA	·pakShuf+608(SB)/8, $0x8080808080808080
DATA	·pakShuf+616(SB)/8, $0x8080808080808080
DATA	·pakShuf+624(SB)/8, $0x8080808080808080
DATA	·pakShuf+632(SB)/8, $0x8080808080808080
DATA	·pakShuf+640(SB)/8, $0x0706050403020100
DATA	·pakShuf+648(SB)/8, $0x0504030201000908
DATA	·pakShuf+656(SB)/8, $0x0302010009080706
DATA	·pakShuf+664(SB)/8, $0x0100090807060504
DATA	·pakShuf+672(SB)/8, $0x8080808080808080
DATA	·pakShuf+680(SB)/8, $0x8080808080808080
DATA	·pakShuf+688(SB)/8, $0x8080808080808080
DATA	·pakShuf+696(SB)/8, $0x8080808080808080
DATA	·pakShuf+704(SB)/8, $0x0706050403020100
DATA	·pakShuf+712(SB)/8, $0x04030201000a0908
DATA	·pakShuf+720(SB)/8, $0x01000a0908070605
DATA	·pakShuf+728(SB)/8, $0x0908070605040302
DATA	·pakShuf+736(SB)/8, $0x8080808080808080
DATA	·pakShuf+744(SB)/8, $0x8080808080808080
DATA	·pakShuf+752(SB)/8, $0x8080808080808080
DATA	·pakShuf+760(SB)/8, $0x8080808080808080
DATA	·pakShuf+768(SB)/8, $0x0706050403020100
DATA	·pakShuf+776(SB)/8, $0x030201000b0a0908
DATA	·pakShuf+784(SB)/8, $0x0b0a090807060504
DATA	·pakShuf+792(SB)/8, $0x0706050403020100
DATA	·pakShuf+800(SB)/8, $0x8080808080808080
DATA	·pakShuf+808(SB)/8, $0x8080808080808080
DATA	·pakShuf+816(SB)/8, $0x8080808080808080
DATA	·pakShuf+824(SB)/8, $0x8080808080808080
DATA	·pakShuf+832(SB)/8, $0x0706050403020100
DATA	·pakShuf+840(SB)/8, $0x0201000c0b0a0908
DATA	·pakShuf+848(SB)/8, $0x0a09080706050403
DATA	·pakShuf+856(SB)/8, $0x0504030201000c0b
DATA	·pakShuf+864(SB)/8, $0x8080808080808080
DATA	·pakShuf+872(SB)/8, $0x8080808080808080
DATA	·pakShuf+880(SB)/8, $0x8080808080808080
DATA	·pakShuf+888(SB)/8, $0x8080808080808080
DATA	·pakShuf+896(SB)/8, $0x0706050403020100
DATA	·pakShuf+904(SB)/8, $0x01000d0c0b0a0908
DATA	·pakShuf+912(SB)/8, $0x0908070605040302
DATA	·pakShuf+920(SB)/8, $0x030201000d0c0b0a
DATA	·pakShuf+928(SB)/8, $0x8080808080808080
DATA	·pakShuf+936(SB)/8, $0x8080808080808080
DATA	·pakShuf+944(SB)/8, $0x8080808080808080
DATA	·pakShuf+952(SB)/8, $0x8080808080808080
DATA	·pakShuf+960(SB)/8, $0x0706050403020100
DATA	·pakShuf+968(SB)/8, $0x000e0d0c0b0a0908
DATA	·pakShuf+976(SB)/8, $0x0807060504030201
DATA	·pakShuf+984(SB)/8, $0x01000e0d0c0b0a09
DATA	·pakShuf+992(SB)/8, $0x8080808080808080
DATA	·pakShuf+1000(SB)/8, $0x8080808080808080
DATA	·pakShuf+1008(SB)/8, $0x8080808080808080
DATA	·pakShuf+1016(SB)/8, $0x8080808080808080
DATA	·pakShuf+1024(SB)/8, $0x0706050403020100
DATA	·pakShuf+1032(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1040(SB)/8, $0x0706050403020100
DATA	·pakShuf+1048(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1056(SB)/8, $0x8080808080808080
DATA	·pakShuf+1064(SB)/8, $0x8080808080808080
DATA	·pakShuf+1072(SB)/8, $0x8080808080808080
DATA	·pakShuf+1080(SB)/8, $0x8080808080808080
DATA	·pakShuf+1088(SB)/8, $0x0706050403020100
DATA	·pakShuf+1096(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1104(SB)/8, $0x0605040302010080
DATA	·pakShuf+1112(SB)/8, $0x0e0d0c0b0a090807
DATA	·pakShuf+1120(SB)/8, $0x8080808080808080
DATA	·pakShuf+1128(SB)/8, $0x8080808080808080
DATA	·pakShuf+1136(SB)/8, $0x8080808080808000
DATA	·pakShuf+1144(SB)/8, $0x8080808080808080
DATA	·pakShuf+1152(SB)/8, $0x0706050403020100
DATA	·pakShuf+1160(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1168(SB)/8, $0x0504030201008080
DATA	·pakShuf+1176(SB)/8, $0x0d0c0b0a09080706
DATA	·pakShuf+1184(SB)/8, $0x8080808080808080
DATA	·pakShuf+1192(SB)/8, $0x8080808080808080
DATA	·pakShuf+1200(SB)/8, $0x8080808080800100
DATA	·pakShuf+1208(SB)/8, $0x8080808080808080
DATA	·pakShuf+1216(SB)/8, $0x0706050403020100
DATA	·pakShuf+1224(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1232(SB)/8, $0x0403020100808080
DATA	·pakShuf+1240(SB)/8, $0x0c0b0a0908070605
DATA	·pakShuf+1248(SB)/8, $0x8080808080808080
DATA	·pakShuf+1256(SB)/8, $0x8080808080808080
DATA	·pakShuf+1264(SB)/8, $0x8080808080020100
DATA	·pakShuf+1272(SB)/8, $0x8080808080808080
DATA	·pakShuf+1280(SB)/8, $0x0706050403020100
DATA	·pakShuf+1288(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1296(SB)/8, $0x0302010080808080
DATA	·pakShuf+1304(SB)/8, $0x0b0a090807060504
DATA	·pakShuf+1312(SB)/8, $0x8080808080808080
DATA	·pakShuf+1320(SB)/8, $0x8080808080808080
DATA	·pakShuf+1328(SB)/8, $0x8080808003020100
DATA	·pakShuf+1336(SB)/8, $0x8080808080808080
DATA	·pakShuf+1344(SB)/8, $0x0706050403020100
DATA	·pakShuf+1352(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1360(SB)/8, $0x0201008080808080
DATA	·pakShuf+1368(SB)/8, $0x0a09080706050403
DATA	·pakShuf+1376(SB)/8, $0x8080808080808080
DATA	·pakShuf+1384(SB)/8, $0x8080808080808080
DATA	·pakShuf+1392(SB)/8, $0x8080800403020100
DATA	·pakShuf+1400(SB)/8, $0x8080808080808080
DATA	·pakShuf+1408(SB)/8, $0x0706050403020100
DATA	·pakShuf+1416(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1424(SB)/8, $0x0100808080808080
DATA	·pakShuf+1432(SB)/8, $0x0908070605040302
DATA	·pakShuf+1440(SB)/8, $0x8080808080808080
DATA	·pakShuf+1448(SB)/8, $0x8080808080808080
DATA	·pakShuf+1456(SB)/8, $0x8080050403020100
DATA	·pakShuf+1464(SB)/8, $0x8080808080808080
DATA	·pakShuf+1472(SB)/8, $0x0706050403020100
DATA	·pakShuf+1480(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1488(SB)/8, $0x0080808080808080
DATA	·pakShuf+1496(SB)/8, $0x0807060504030201
DATA	·pakShuf+1504(SB)/8, $0x8080808080808080
DATA	·pakShuf+1512(SB)/8, $0x8080808080808080
DATA	·pakShuf+1520(SB)/8, $0x8006050403020100
DATA	·pakShuf+1528(SB)/8, $0x8080808080808080
DATA	·pakShuf+1536(SB)/8, $0x0706050403020100
DATA	·pakShuf+1544(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1552(SB)/8, $0x8080808080808080
DATA	·pakShuf+1560(SB)/8, $0x0706050403020100
DATA	·pakShuf+1568(SB)/8, $0x8080808080808080
DATA	·pakShuf+1576(SB)/8, $0x8080808080808080
DATA	·pakShuf+1584(SB)/8, $0x0706050403020100
DATA	·pakShuf+1592(SB)/8, $0x8080808080808080
DATA	·pakShuf+1600(SB)/8, $0x0706050403020100
DATA	·pakShuf+1608(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1616(SB)/8, $0x8080808080808080
DATA	·pakShuf+1624(SB)/8, $0x0605040302010080
DATA	·pakShuf+1632(SB)/8, $0x8080808080808080
DATA	·pakShuf+1640(SB)/8, $0x8080808080808080
DATA	·pakShuf+1648(SB)/8, $0x0706050403020100
DATA	·pakShuf+1656(SB)/8, $0x8080808080808008
DATA	·pakShuf+1664(SB)/8, $0x0706050403020100
DATA	·pakShuf+1672(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1680(SB)/8, $0x8080808080808080
DATA	·pakShuf+1688(SB)/8, $0x0504030201008080
DATA	·pakShuf+1696(SB)/8, $0x8080808080808080
DATA	·pakShuf+1704(SB)/8, $0x8080808080808080
DATA	·pakShuf+1712(SB)/8, $0x0706050403020100
DATA	·pakShuf+1720(SB)/8, $0x8080808080800908
DATA	·pakShuf+1728(SB)/8, $0x0706050403020100
DATA	·pakShuf+1736(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1744(SB)/8, $0x8080808080808080
DATA	·pakShuf+1752(SB)/8, $0x0403020100808080
DATA	·pakShuf+1760(SB)/8, $0x8080808080808080
DATA	·pakShuf+1768(SB)/8, $0x8080808080808080
DATA	·pakShuf+1776(SB)/8, $0x0706050403020100
DATA	·pakShuf+1784(SB)/8, $0x80808080800a0908
DATA	·pakShuf+1792(SB)/8, $0x0706050403020100
DATA	·pakShuf+1800(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1808(SB)/8, $0x8080808080808080
DATA	·pakShuf+1816(SB)/8, $0x0302010080808080
DATA	·pakShuf+1824(SB)/8, $0x8080808080808080
DATA	·pakShuf+1832(SB)/8, $0x8080808080808080
DATA	·pakShuf+1840(SB)/8, $0x0706050403020100
DATA	·pakShuf+1848(SB)/8, $0x808080800b0a0908
DATA	·pakShuf+1856(SB)/8, $0x0706050403020100
DATA	·pakShuf+1864(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1872(SB)/8, $0x8080808080808080
DATA	·pakShuf+1880(SB)/8, $0x0201008080808080
DATA	·pakShuf+1888(SB)/8, $0x8080808080808080
DATA	·pakShuf+1896(SB)/8, $0x8080808080808080
DATA	·pakShuf+1904(SB)/8, $0x0706050403020100
DATA	·pakShuf+1912(SB)/8, $0x8080800c0b0a0908
DATA	·pakShuf+1920(SB)/8, $0x0706050403020100
DATA	·pakShuf+1928(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+1936(SB)/8, $0x8080808080808080
DATA	·pakShuf+1944(SB)/8, $0x0100808080808080
DATA	·pakShuf+1952(SB)/8, $0x8080808080808080
DATA	·pakShuf+1960(SB)/8, $0x8080808080808080
DATA	·pakShuf+1968(SB)/8, $0x0706050403020100
DATA	·pakShuf+1976(SB)/8, $0x80800d0c0b0a0908
DATA	·pakShuf+1984(SB)/8, $0x0706050403020100
DATA	·pakShuf+1992(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakShuf+2000(SB)/8, $0x8080808080808080
DATA	·pakShuf+2008(SB)/8, $0x0080808080808080
DATA	·pakShuf+2016(SB)/8, $0x8080808080808080
DATA	·pakShuf+2024(SB)/8, $0x8080808080808080
DATA	·pakShuf+2032(SB)/8, $0x0706050403020100
DATA	·pakShuf+2040(SB)/8, $0x800e0d0c0b0a0908
GLOBL	·pakShuf(SB), RODATA|NOPTR, $2048
DATA	·pakStrides+0(SB)/8, $0x1c1e1e201e202020
DATA	·pakStrides+8(SB)/8, $0x1e1c1a18161e1b20
DATA	·pakStrides+16(SB)/8, $0x1716151413121120
DATA	·pakStrides+24(SB)/8, $0x1f1e1d1c1b1a1918
GLOBL	·pakStrides(SB), RODATA|NOPTR, $32
