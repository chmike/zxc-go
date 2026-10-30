//go:build !purego

#include "textflag.h"

// PAK sequence loop for arm64, called through pakRun (pakrun_arm64.go),
// which checks the invariants this code relies on; its comment gives the
// proof of the accesses.
//
// Two paths:
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
// goes back to pre. The sequence pointer advances once per batch, the 4
// words being read as two pairs at 0(R7) and 8(R7); a sequence that
// leaves the batch sets R7 to itself on the way out, the sequences before
// it staying done.
//
// The loop walks the output, literals and sequences by address; the
// indices of pakState are converted on entry and back on exit. The bounds
// below are the same tests as on indices: p_out - out = d, and so on.
//
// Copies move 32 bytes with one FLDPQ/FSTPQ pair (two 128-bit registers).
// Matches at distance 1 to 31 load the 32 bytes at out[d-off], select the
// first off of them with VTBL into a 32-byte pattern, and store it at a
// stride that keeps the period in phase, as the reference decoder does.
//
// Registers:
//   R0  *pakState           R8  &out[d]          R16 ll
//   R1  out                 R9  &lits[l]         R17 ml field (mb)
//   R2  lits                R10 e                R19 off
//   R3  seqs                R11 &out[limit]      R21 ml
//   R4  extras              R12 &lits[litEnd]    R22 &out[65536]
//   R5  &seqs[nSeq]         R13 &out[limit - 4*513], 0 if negative
//   R7  &seqs[i]            R14 &lits[litEnd - 4*254], 0 if negative
//   R6  single: nExt, reloaded
//   R15 R26 batch: words of the even and odd sequences
//   R26 single: e at the sequence start
//   R20 batch: &seqs[nSeq-4]; single: scratch
//   R15 single: sequence word; R23 R24 R25 scratch; V0-V5 copies.

// func pakRunAsm(st *pakState)
TEXT ·pakRunAsm(SB), NOSPLIT, $0-8
	MOVD	st+0(FP), R0
	MOVD	0(R0), R1
	MOVD	8(R0), R2
	MOVD	16(R0), R3
	MOVD	24(R0), R4
	MOVD	72(R0), R10
	MOVD	32(R0), R5
	ADD	R3, R5
	MOVD	48(R0), R7
	ADD	R3, R7
	MOVD	56(R0), R8
	ADD	R1, R8
	MOVD	64(R0), R9
	ADD	R2, R9
	MOVD	80(R0), R24
	ADD	R1, R24, R11
	SUBS	$(4*513), R24, R24
	ADD	R1, R24, R13
	CSEL	LT, ZR, R13, R13
	MOVD	88(R0), R24
	ADD	R2, R24, R12
	SUBS	$(4*254), R24, R24
	ADD	R2, R24, R14
	CSEL	LT, ZR, R14, R14
	MOVD	$65536, R22
	ADD	R1, R22

loop:
	CMP	R5, R7
	BHS	done

	// Batch of 4, if it fits; R20 is the last sequence a batch can start
	// at, &seqs[nSeq-4].
	ADD	$16, R7, R24
	CMP	R5, R24
	BHI	single
	CMP	R13, R8
	BHI	single
	CMP	R14, R9
	BHI	single
	SUB	$16, R5, R20
	CMP	R22, R8
	BLO	pre

post:
	// Batch past 64 KiB of output: no offset test.

	// Sequence 0 of the batch, straight-line in the common case.
	LDPW	(R7), (R15, R26)
	LSR	$24, R15, R16
	UBFX	$16, R15, $8, R17
	CMP	$255, R16
	BEQ	escq0
	CMP	$255, R17
	BEQ	escq0
	AND	$0xFFFF, R15, R19
	ADD	$1, R19
	ADD	$5, R17, R21
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BHI	litlongq0
litdoneq0:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	shortq0
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BHI	mlongq0
doneq0:
	ADD	R21, R8

	// Sequence 1 of the batch, straight-line in the common case.
	LSR	$24, R26, R16
	UBFX	$16, R26, $8, R17
	CMP	$255, R16
	BEQ	escq1
	CMP	$255, R17
	BEQ	escq1
	AND	$0xFFFF, R26, R19
	ADD	$1, R19
	ADD	$5, R17, R21
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BHI	litlongq1
litdoneq1:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	shortq1
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BHI	mlongq1
doneq1:
	ADD	R21, R8

	// Sequence 2 of the batch, straight-line in the common case.
	LDPW	8(R7), (R15, R26)
	LSR	$24, R15, R16
	UBFX	$16, R15, $8, R17
	CMP	$255, R16
	BEQ	escq2
	CMP	$255, R17
	BEQ	escq2
	AND	$0xFFFF, R15, R19
	ADD	$1, R19
	ADD	$5, R17, R21
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BHI	litlongq2
litdoneq2:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	shortq2
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BHI	mlongq2
doneq2:
	ADD	R21, R8

	// Sequence 3 of the batch, straight-line in the common case.
	LSR	$24, R26, R16
	UBFX	$16, R26, $8, R17
	CMP	$255, R16
	BEQ	escq3
	CMP	$255, R17
	BEQ	escq3
	AND	$0xFFFF, R26, R19
	ADD	$1, R19
	ADD	$5, R17, R21
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BHI	litlongq3
litdoneq3:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	shortq3
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BHI	mlongq3
doneq3:
	ADD	R21, R8

	// Next batch, if it fits.
	ADD	$16, R7
	CMP	R20, R7
	BHI	loop
	CMP	R13, R8
	BHI	loop
	CMP	R14, R9
	BLS	post
	B	loop

escq0:
	// A varint, or an offset to check: sequence 0 goes to the single path.
	B	single
litlongq0:
	// Literals past 32 bytes.
	MOVD	$32, R24
blq0:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	blq0
	B	litdoneq0
mlongq0:
	// Match past 32 bytes, offset 32 or more.
	MOVD	$32, R24
bmq0:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	bmq0
	B	doneq0
shortq0:
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
slq0:
	ADD	R25, R8, R23
	FSTPQ	(F4, F5), (R23)
	ADD	R24, R25
	CMP	R21, R25
	BLO	slq0
	B	doneq0

escq1:
	// A varint, or an offset to check: sequence 1 goes to the single path.
	ADD	$4, R7
	B	single
litlongq1:
	// Literals past 32 bytes.
	MOVD	$32, R24
blq1:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	blq1
	B	litdoneq1
mlongq1:
	// Match past 32 bytes, offset 32 or more.
	MOVD	$32, R24
bmq1:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	bmq1
	B	doneq1
shortq1:
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
slq1:
	ADD	R25, R8, R23
	FSTPQ	(F4, F5), (R23)
	ADD	R24, R25
	CMP	R21, R25
	BLO	slq1
	B	doneq1

escq2:
	// A varint, or an offset to check: sequence 2 goes to the single path.
	ADD	$8, R7
	B	single
litlongq2:
	// Literals past 32 bytes.
	MOVD	$32, R24
blq2:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	blq2
	B	litdoneq2
mlongq2:
	// Match past 32 bytes, offset 32 or more.
	MOVD	$32, R24
bmq2:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	bmq2
	B	doneq2
shortq2:
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
slq2:
	ADD	R25, R8, R23
	FSTPQ	(F4, F5), (R23)
	ADD	R24, R25
	CMP	R21, R25
	BLO	slq2
	B	doneq2

escq3:
	// A varint, or an offset to check: sequence 3 goes to the single path.
	ADD	$12, R7
	B	single
litlongq3:
	// Literals past 32 bytes.
	MOVD	$32, R24
blq3:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	blq3
	B	litdoneq3
mlongq3:
	// Match past 32 bytes, offset 32 or more.
	MOVD	$32, R24
bmq3:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	bmq3
	B	doneq3
shortq3:
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
slq3:
	ADD	R25, R8, R23
	FSTPQ	(F4, F5), (R23)
	ADD	R24, R25
	CMP	R21, R25
	BLO	slq3
	B	doneq3

pre:
	// Batch below 64 KiB of output: off > d+ll leaves a sequence to the
	// single path.

	// Sequence 0 of the batch, straight-line in the common case.
	LDPW	(R7), (R15, R26)
	LSR	$24, R15, R16
	UBFX	$16, R15, $8, R17
	CMP	$255, R16
	BEQ	escp0
	CMP	$255, R17
	BEQ	escp0
	AND	$0xFFFF, R15, R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	escp0
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BHI	litlongp0
litdonep0:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	shortp0
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BHI	mlongp0
donep0:
	ADD	R21, R8

	// Sequence 1 of the batch, straight-line in the common case.
	LSR	$24, R26, R16
	UBFX	$16, R26, $8, R17
	CMP	$255, R16
	BEQ	escp1
	CMP	$255, R17
	BEQ	escp1
	AND	$0xFFFF, R26, R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	escp1
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BHI	litlongp1
litdonep1:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	shortp1
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BHI	mlongp1
donep1:
	ADD	R21, R8

	// Sequence 2 of the batch, straight-line in the common case.
	LDPW	8(R7), (R15, R26)
	LSR	$24, R15, R16
	UBFX	$16, R15, $8, R17
	CMP	$255, R16
	BEQ	escp2
	CMP	$255, R17
	BEQ	escp2
	AND	$0xFFFF, R15, R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	escp2
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BHI	litlongp2
litdonep2:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	shortp2
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BHI	mlongp2
donep2:
	ADD	R21, R8

	// Sequence 3 of the batch, straight-line in the common case.
	LSR	$24, R26, R16
	UBFX	$16, R26, $8, R17
	CMP	$255, R16
	BEQ	escp3
	CMP	$255, R17
	BEQ	escp3
	AND	$0xFFFF, R26, R19
	ADD	$1, R19
	ADD	$5, R17, R21
	SUB	R1, R8, R24
	ADD	R16, R24
	CMP	R24, R19
	BHI	escp3
	FLDPQ	(R9), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R16
	BHI	litlongp3
litdonep3:
	ADD	R16, R8
	ADD	R16, R9
	SUB	R19, R8, R23
	CMP	$32, R19
	BLO	shortp3
	FLDPQ	(R23), (F0, F1)
	FSTPQ	(F0, F1), (R8)
	CMP	$32, R21
	BHI	mlongp3
donep3:
	ADD	R21, R8

	// Next batch, if it fits, below or past 64 KiB.
	ADD	$16, R7
	CMP	R20, R7
	BHI	loop
	CMP	R13, R8
	BHI	loop
	CMP	R14, R9
	BHI	loop
	CMP	R22, R8
	BLO	pre
	B	post

escp0:
	// A varint, or an offset to check: sequence 0 goes to the single path.
	B	single
litlongp0:
	// Literals past 32 bytes.
	MOVD	$32, R24
blp0:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	blp0
	B	litdonep0
mlongp0:
	// Match past 32 bytes, offset 32 or more.
	MOVD	$32, R24
bmp0:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	bmp0
	B	donep0
shortp0:
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
slp0:
	ADD	R25, R8, R23
	FSTPQ	(F4, F5), (R23)
	ADD	R24, R25
	CMP	R21, R25
	BLO	slp0
	B	donep0

escp1:
	// A varint, or an offset to check: sequence 1 goes to the single path.
	ADD	$4, R7
	B	single
litlongp1:
	// Literals past 32 bytes.
	MOVD	$32, R24
blp1:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	blp1
	B	litdonep1
mlongp1:
	// Match past 32 bytes, offset 32 or more.
	MOVD	$32, R24
bmp1:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	bmp1
	B	donep1
shortp1:
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
slp1:
	ADD	R25, R8, R23
	FSTPQ	(F4, F5), (R23)
	ADD	R24, R25
	CMP	R21, R25
	BLO	slp1
	B	donep1

escp2:
	// A varint, or an offset to check: sequence 2 goes to the single path.
	ADD	$8, R7
	B	single
litlongp2:
	// Literals past 32 bytes.
	MOVD	$32, R24
blp2:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	blp2
	B	litdonep2
mlongp2:
	// Match past 32 bytes, offset 32 or more.
	MOVD	$32, R24
bmp2:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	bmp2
	B	donep2
shortp2:
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
slp2:
	ADD	R25, R8, R23
	FSTPQ	(F4, F5), (R23)
	ADD	R24, R25
	CMP	R21, R25
	BLO	slp2
	B	donep2

escp3:
	// A varint, or an offset to check: sequence 3 goes to the single path.
	ADD	$12, R7
	B	single
litlongp3:
	// Literals past 32 bytes.
	MOVD	$32, R24
blp3:
	ADD	R24, R9, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R16, R24
	BLO	blp3
	B	litdonep3
mlongp3:
	// Match past 32 bytes, offset 32 or more.
	MOVD	$32, R24
bmp3:
	ADD	R24, R23, R25
	FLDPQ	(R25), (F0, F1)
	ADD	R24, R8, R25
	FSTPQ	(F0, F1), (R25)
	ADD	$32, R24
	CMP	R21, R24
	BLO	bmp3
	B	donep3
shortp3:
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
slp3:
	ADD	R25, R8, R23
	FSTPQ	(F4, F5), (R23)
	ADD	R24, R25
	CMP	R21, R25
	BLO	slp3
	B	donep3

single:
	MOVWU	(R7), R15
	MOVD	R10, R26
	LSR	$24, R15, R16
	UBFX	$16, R15, $8, R17
	AND	$0xFFFF, R15, R19
	ADD	$1, R19
	ADD	$5, R17, R21

	// LL == 255: add a varint from the extras.
	CMP	$255, R16
	BNE	llok
	MOVD	40(R0), R6
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
	// ML field == 255: add a varint from the extras.
	CMP	$255, R17
	BNE	mlok
	MOVD	40(R0), R6
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
	// off > d+ll, ll+ml > limit-d or ll > litEnd-l: leave it to decodePAK.
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
	ADD	$4, R7
	B	loop

exit:
	MOVD	R26, R10
done:
	SUB	R3, R7
	MOVD	R7, 48(R0)
	SUB	R1, R8
	MOVD	R8, 56(R0)
	SUB	R2, R9
	MOVD	R9, 64(R0)
	MOVD	R10, 72(R0)
	RET

// pakMasks[off] selects j % off for j < 32 (row 0 unused); pakStrides[off]
// is the largest multiple of off not above 32.
DATA	·pakMasks+0(SB)/8, $0x0000000000000000
DATA	·pakMasks+8(SB)/8, $0x0000000000000000
DATA	·pakMasks+16(SB)/8, $0x0000000000000000
DATA	·pakMasks+24(SB)/8, $0x0000000000000000
DATA	·pakMasks+32(SB)/8, $0x0000000000000000
DATA	·pakMasks+40(SB)/8, $0x0000000000000000
DATA	·pakMasks+48(SB)/8, $0x0000000000000000
DATA	·pakMasks+56(SB)/8, $0x0000000000000000
DATA	·pakMasks+64(SB)/8, $0x0100010001000100
DATA	·pakMasks+72(SB)/8, $0x0100010001000100
DATA	·pakMasks+80(SB)/8, $0x0100010001000100
DATA	·pakMasks+88(SB)/8, $0x0100010001000100
DATA	·pakMasks+96(SB)/8, $0x0100020100020100
DATA	·pakMasks+104(SB)/8, $0x0002010002010002
DATA	·pakMasks+112(SB)/8, $0x0201000201000201
DATA	·pakMasks+120(SB)/8, $0x0100020100020100
DATA	·pakMasks+128(SB)/8, $0x0302010003020100
DATA	·pakMasks+136(SB)/8, $0x0302010003020100
DATA	·pakMasks+144(SB)/8, $0x0302010003020100
DATA	·pakMasks+152(SB)/8, $0x0302010003020100
DATA	·pakMasks+160(SB)/8, $0x0201000403020100
DATA	·pakMasks+168(SB)/8, $0x0004030201000403
DATA	·pakMasks+176(SB)/8, $0x0302010004030201
DATA	·pakMasks+184(SB)/8, $0x0100040302010004
DATA	·pakMasks+192(SB)/8, $0x0100050403020100
DATA	·pakMasks+200(SB)/8, $0x0302010005040302
DATA	·pakMasks+208(SB)/8, $0x0504030201000504
DATA	·pakMasks+216(SB)/8, $0x0100050403020100
DATA	·pakMasks+224(SB)/8, $0x0006050403020100
DATA	·pakMasks+232(SB)/8, $0x0100060504030201
DATA	·pakMasks+240(SB)/8, $0x0201000605040302
DATA	·pakMasks+248(SB)/8, $0x0302010006050403
DATA	·pakMasks+256(SB)/8, $0x0706050403020100
DATA	·pakMasks+264(SB)/8, $0x0706050403020100
DATA	·pakMasks+272(SB)/8, $0x0706050403020100
DATA	·pakMasks+280(SB)/8, $0x0706050403020100
DATA	·pakMasks+288(SB)/8, $0x0706050403020100
DATA	·pakMasks+296(SB)/8, $0x0605040302010008
DATA	·pakMasks+304(SB)/8, $0x0504030201000807
DATA	·pakMasks+312(SB)/8, $0x0403020100080706
DATA	·pakMasks+320(SB)/8, $0x0706050403020100
DATA	·pakMasks+328(SB)/8, $0x0504030201000908
DATA	·pakMasks+336(SB)/8, $0x0302010009080706
DATA	·pakMasks+344(SB)/8, $0x0100090807060504
DATA	·pakMasks+352(SB)/8, $0x0706050403020100
DATA	·pakMasks+360(SB)/8, $0x04030201000a0908
DATA	·pakMasks+368(SB)/8, $0x01000a0908070605
DATA	·pakMasks+376(SB)/8, $0x0908070605040302
DATA	·pakMasks+384(SB)/8, $0x0706050403020100
DATA	·pakMasks+392(SB)/8, $0x030201000b0a0908
DATA	·pakMasks+400(SB)/8, $0x0b0a090807060504
DATA	·pakMasks+408(SB)/8, $0x0706050403020100
DATA	·pakMasks+416(SB)/8, $0x0706050403020100
DATA	·pakMasks+424(SB)/8, $0x0201000c0b0a0908
DATA	·pakMasks+432(SB)/8, $0x0a09080706050403
DATA	·pakMasks+440(SB)/8, $0x0504030201000c0b
DATA	·pakMasks+448(SB)/8, $0x0706050403020100
DATA	·pakMasks+456(SB)/8, $0x01000d0c0b0a0908
DATA	·pakMasks+464(SB)/8, $0x0908070605040302
DATA	·pakMasks+472(SB)/8, $0x030201000d0c0b0a
DATA	·pakMasks+480(SB)/8, $0x0706050403020100
DATA	·pakMasks+488(SB)/8, $0x000e0d0c0b0a0908
DATA	·pakMasks+496(SB)/8, $0x0807060504030201
DATA	·pakMasks+504(SB)/8, $0x01000e0d0c0b0a09
DATA	·pakMasks+512(SB)/8, $0x0706050403020100
DATA	·pakMasks+520(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+528(SB)/8, $0x0706050403020100
DATA	·pakMasks+536(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+544(SB)/8, $0x0706050403020100
DATA	·pakMasks+552(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+560(SB)/8, $0x0605040302010010
DATA	·pakMasks+568(SB)/8, $0x0e0d0c0b0a090807
DATA	·pakMasks+576(SB)/8, $0x0706050403020100
DATA	·pakMasks+584(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+592(SB)/8, $0x0504030201001110
DATA	·pakMasks+600(SB)/8, $0x0d0c0b0a09080706
DATA	·pakMasks+608(SB)/8, $0x0706050403020100
DATA	·pakMasks+616(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+624(SB)/8, $0x0403020100121110
DATA	·pakMasks+632(SB)/8, $0x0c0b0a0908070605
DATA	·pakMasks+640(SB)/8, $0x0706050403020100
DATA	·pakMasks+648(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+656(SB)/8, $0x0302010013121110
DATA	·pakMasks+664(SB)/8, $0x0b0a090807060504
DATA	·pakMasks+672(SB)/8, $0x0706050403020100
DATA	·pakMasks+680(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+688(SB)/8, $0x0201001413121110
DATA	·pakMasks+696(SB)/8, $0x0a09080706050403
DATA	·pakMasks+704(SB)/8, $0x0706050403020100
DATA	·pakMasks+712(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+720(SB)/8, $0x0100151413121110
DATA	·pakMasks+728(SB)/8, $0x0908070605040302
DATA	·pakMasks+736(SB)/8, $0x0706050403020100
DATA	·pakMasks+744(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+752(SB)/8, $0x0016151413121110
DATA	·pakMasks+760(SB)/8, $0x0807060504030201
DATA	·pakMasks+768(SB)/8, $0x0706050403020100
DATA	·pakMasks+776(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+784(SB)/8, $0x1716151413121110
DATA	·pakMasks+792(SB)/8, $0x0706050403020100
DATA	·pakMasks+800(SB)/8, $0x0706050403020100
DATA	·pakMasks+808(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+816(SB)/8, $0x1716151413121110
DATA	·pakMasks+824(SB)/8, $0x0605040302010018
DATA	·pakMasks+832(SB)/8, $0x0706050403020100
DATA	·pakMasks+840(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+848(SB)/8, $0x1716151413121110
DATA	·pakMasks+856(SB)/8, $0x0504030201001918
DATA	·pakMasks+864(SB)/8, $0x0706050403020100
DATA	·pakMasks+872(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+880(SB)/8, $0x1716151413121110
DATA	·pakMasks+888(SB)/8, $0x04030201001a1918
DATA	·pakMasks+896(SB)/8, $0x0706050403020100
DATA	·pakMasks+904(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+912(SB)/8, $0x1716151413121110
DATA	·pakMasks+920(SB)/8, $0x030201001b1a1918
DATA	·pakMasks+928(SB)/8, $0x0706050403020100
DATA	·pakMasks+936(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+944(SB)/8, $0x1716151413121110
DATA	·pakMasks+952(SB)/8, $0x0201001c1b1a1918
DATA	·pakMasks+960(SB)/8, $0x0706050403020100
DATA	·pakMasks+968(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+976(SB)/8, $0x1716151413121110
DATA	·pakMasks+984(SB)/8, $0x01001d1c1b1a1918
DATA	·pakMasks+992(SB)/8, $0x0706050403020100
DATA	·pakMasks+1000(SB)/8, $0x0f0e0d0c0b0a0908
DATA	·pakMasks+1008(SB)/8, $0x1716151413121110
DATA	·pakMasks+1016(SB)/8, $0x001e1d1c1b1a1918
GLOBL	·pakMasks(SB), RODATA|NOPTR, $1024
DATA	·pakStrides+0(SB)/8, $0x1c1e1e201e202020
DATA	·pakStrides+8(SB)/8, $0x1e1c1a18161e1b20
DATA	·pakStrides+16(SB)/8, $0x1716151413121120
DATA	·pakStrides+24(SB)/8, $0x1f1e1d1c1b1a1918
GLOBL	·pakStrides(SB), RODATA|NOPTR, $32
