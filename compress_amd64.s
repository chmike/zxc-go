//go:build !purego

#include "textflag.h"

// The encoder's parsers and kernels for amd64, translated from
// compress_arm64.s, whose comments describe them; the proofs of their
// accesses are in compress_asm.go. With fewer registers, the parameters
// and the running output pointers are read from and written to the state
// in memory. The copy of literals, the varints and the match lengths are
// the same blocks wherever they appear.

// PAK parser, levels 1 and 2.
//
// Registers: R14 st   SI src   DI ip   R15 anchor   R9 head   R10 tags
//   R11 chain   per position: R8 v, R12 idx, R13 attempts, BX best length - 3,
//   DX chain link; AX CX scratch
// Frame: 8(SP) best ref (-1 none), 16(SP) the chain link during a match
// length, 24(SP) the next position after a miss, 0(SP) its hash, which a
// miss reuses.
// As the C code, it prefetches the table entries of the next position, the
// source ahead, and the gate of the next candidate of a chain. In st: lits (104), seqs (112), extras (120); anchor (128) on return.

// func pakEncAsm(st *encState)
TEXT ·pakEncAsm(SB), NOSPLIT, $32-8
	MOVQ	st+0(FP), R14
	MOVQ	0(R14), SI
	MOVQ	8(R14), DI
	MOVQ	DI, R15
	MOVQ	32(R14), R9
	MOVQ	40(R14), R10
	MOVQ	48(R14), R11

ploop:
	CMPQ	DI, 24(R14)
	JGE	pdone
	MOVL	(SI)(DI*1), R8
	MOVQ	(SI)(DI*1), AX
	MOVQ	AX, BX
	SHRQ	$15, BX
	XORQ	AX, BX
	IMUL3L	$0x2D35182D, BX, BX
	SHRL	$17, BX
phashed:
	// The step after a miss, 1 when ip + step reaches the limit; the
	// prefetches of the next position (ip + 1 <= limit = iend - 8 keeps its
	// 8-byte load in src) and of the source ahead.
	MOVQ	DI, AX
	SUBQ	R15, AX
	MOVQ	96(R14), CX
	SHRQ	CX, AX
	ADDQ	88(R14), AX
	LEAQ	(DI)(AX*1), CX
	CMPQ	CX, 24(R14)
	JLT	pstepped
	MOVL	$1, AX
	LEAQ	1(DI), CX
pstepped:
	MOVQ	CX, 24(SP)
	LEAQ	(DI)(AX*4), DX
	PREFETCHT0	64(SI)(DX*1)
	MOVQ	(SI)(CX*1), AX
	MOVQ	AX, DX
	SHRQ	$15, DX
	XORQ	AX, DX
	IMUL3L	$0x2D35182D, DX, DX
	SHRL	$17, DX
	PREFETCHT0	(R10)(DX*1)
	PREFETCHT0	(R9)(DX*4)
	MOVL	DX, 0(SP)
	MOVL	R8, CX
	SHRL	$16, CX
	XORL	R8, CX
	MOVBLZX	(R10)(BX*1), DX
	MOVL	(R9)(BX*4), R12
	MOVL	DI, AX
	ORL	56(R14), AX
	MOVL	AX, (R9)(BX*4)
	MOVB	CL, (R10)(BX*1)
	MOVL	DI, BX
	ANDL	$0xFFFF, BX
	CMPB	CL, DL
	JNE	pnocand
	XORL	56(R14), R12
	CMPL	R12, 64(R14)
	JA	pnocand
	TESTL	R12, R12
	JZ	pnocand
	MOVL	DI, AX
	SUBL	R12, AX
	XORL	CX, CX
	CMPL	AX, $65536
	CMOVLCC	CX, AX
	MOVW	AX, (R11)(BX*2)

	MOVQ	$-1, 8(SP)
	MOVL	$1, BX
	MOVL	$3, R13
pcand:
	MOVL	DI, AX
	SUBL	R12, AX
	CMPL	AX, $65535
	JA	pwalked
	TESTQ	R13, R13
	JS	pwalked
	DECQ	R13
	MOVL	R12, CX
	ANDL	$0xFFFF, CX
	MOVWLZX	(R11)(CX*2), DX
	MOVL	R12, CX
	SUBL	DX, CX
	ADDQ	BX, CX
	PREFETCHT0	(SI)(CX*1) // the next candidate's gate
	CMPQ	AX, 72(R14)
	JLT	pnext
	LEAQ	(R12)(BX*1), CX
	MOVL	(SI)(CX*1), CX
	LEAQ	(DI)(BX*1), AX
	CMPL	CX, (SI)(AX*1)
	JEQ	pgate
pnext:
	TESTL	DX, DX
	JZ	pwalked
	SUBL	DX, R12
	JNZ	pcand
pwalked:
	CMPQ	8(SP), $0
	JGE	phit
pmiss:
	MOVQ	24(SP), DI
	CMPQ	DI, 24(R14)
	JGE	pdone
	MOVL	(SI)(DI*1), R8
	MOVL	0(SP), BX
	JMP	phashed
pnocand:
	// No candidate: the miss inline.
	MOVW	$0, (R11)(BX*2)
	MOVQ	24(SP), DI
	CMPQ	DI, 24(R14)
	JGE	pdone
	MOVL	(SI)(DI*1), R8
	MOVL	0(SP), BX
	JMP	phashed

pgate:
	MOVL	(SI)(R12*1), AX
	CMPL	AX, R8
	JNE	pnext
	MOVQ	DX, 16(SP)
	MOVL	$4, CX
pml:
	LEAQ	8(DI)(CX*1), AX
	CMPQ	AX, 16(R14)
	JA	pmtail
	LEAQ	(DI)(CX*1), AX
	MOVQ	(SI)(AX*1), AX
	LEAQ	(R12)(CX*1), DX
	XORQ	(SI)(DX*1), AX
	JNZ	pmdiff
	ADDQ	$8, CX
	JMP	pml
pmdiff:
	BSFQ	AX, AX
	SHRQ	$3, AX
	ADDQ	AX, CX
	JMP	pmdone
pmtail:
	LEAQ	(DI)(CX*1), AX
	CMPQ	AX, 16(R14)
	JAE	pmdone
	MOVBLZX	(SI)(AX*1), AX
	LEAQ	(R12)(CX*1), DX
	CMPB	AX, (SI)(DX*1)
	JNE	pmdone
	INCQ	CX
	JMP	pmtail
pmdone:
	MOVQ	16(SP), DX
	LEAQ	3(BX), AX
	CMPQ	CX, AX
	JLE	pnobetter
	LEAQ	-3(CX), BX
	MOVQ	R12, 8(SP)
pnobetter:
	LEAQ	3(BX), AX
	CMPQ	AX, 80(R14)
	JGE	pwalked
	ADDQ	DI, AX
	CMPQ	AX, 16(R14)
	JGE	pwalked
	JMP	pnext

phit:
	LEAQ	3(BX), R13
	MOVQ	8(SP), R12
	MOVQ	R15, R8
pback:
	CMPQ	DI, R8
	JLE	pemit
	TESTQ	R12, R12
	JZ	pemit
	MOVB	-1(SI)(DI*1), AX
	CMPB	AX, -1(SI)(R12*1)
	JNE	pemit
	DECQ	DI
	DECQ	R12
	INCQ	R13
	JMP	pback
pemit:
	MOVQ	DI, CX
	SUBQ	R8, CX
	LEAQ	(SI)(R8*1), R8
	MOVQ	104(R14), DX
	TESTQ	CX, CX
	JZ	plcdone
	CMPQ	CX, $16
	JB	plcsmall
	XORL	BX, BX
	LEAQ	-16(CX), AX
plc16:
	CMPQ	BX, AX
	JAE	plc16last
	MOVOU	(R8)(BX*1), X0
	MOVOU	X0, (DX)(BX*1)
	ADDQ	$16, BX
	JMP	plc16
plc16last:
	MOVOU	(R8)(AX*1), X0
	MOVOU	X0, (DX)(AX*1)
	JMP	plcdone
plcsmall:
	CMPQ	CX, $8
	JB	plcsmall4
	MOVQ	(R8), AX
	MOVQ	AX, (DX)
	MOVQ	-8(R8)(CX*1), AX
	MOVQ	AX, -8(DX)(CX*1)
	JMP	plcdone
plcsmall4:
	CMPQ	CX, $4
	JB	plcsmall1
	MOVL	(R8), AX
	MOVL	AX, (DX)
	MOVL	-4(R8)(CX*1), AX
	MOVL	AX, -4(DX)(CX*1)
	JMP	plcdone
plcsmall1:
	MOVBLZX	(R8), AX
	MOVB	AX, (DX)
	MOVQ	CX, BX
	SHRQ	$1, BX
	MOVBLZX	(R8)(BX*1), AX
	MOVB	AX, (DX)(BX*1)
	MOVBLZX	-1(R8)(CX*1), AX
	MOVB	AX, -1(DX)(CX*1)
plcdone:
	ADDQ	CX, DX
	MOVQ	DX, 104(R14)
	// The sequence word, then the extras of lengths of 255 or more.
	LEAQ	-5(R13), BX // ml
	MOVQ	DI, AX
	SUBQ	R12, AX
	DECQ	AX
	ANDQ	$0xFFFF, AX
	MOVQ	$255, DX
	MOVQ	CX, R8
	CMPQ	R8, DX
	CMOVQCC	DX, R8
	SHLQ	$24, R8
	ORQ	R8, AX
	MOVQ	BX, R8
	CMPQ	R8, DX
	CMOVQCC	DX, R8
	SHLQ	$16, R8
	ORQ	R8, AX
	MOVQ	112(R14), R8
	MOVL	AX, (R8)
	ADDQ	$4, R8
	MOVQ	R8, 112(R14)
	CMPQ	CX, $255
	JAE	pextras
	CMPQ	BX, $255
	JAE	pextras
padvance:
	ADDQ	R13, DI
	MOVQ	DI, R15
	JMP	ploop
pextras:
	MOVQ	120(R14), DX
	SUBQ	$255, CX
	JB	pexml
	CMPQ	CX, $128
	JAE	pxlv2
	MOVB	CX, (DX)
	INCQ	DX
	JMP	pxlvdone
pxlv2:
	CMPQ	CX, $16384
	JAE	pxlv3
	MOVQ	CX, AX
	ANDQ	$0x3F, AX
	ORQ	$0x80, AX
	MOVB	AX, (DX)
	SHRQ	$6, CX
	MOVB	CX, 1(DX)
	ADDQ	$2, DX
	JMP	pxlvdone
pxlv3:
	MOVQ	CX, AX
	ANDQ	$0x1F, AX
	ORQ	$0xC0, AX
	MOVB	AX, (DX)
	MOVQ	CX, AX
	SHRQ	$5, AX
	MOVB	AX, 1(DX)
	SHRQ	$13, CX
	MOVB	CX, 2(DX)
	ADDQ	$3, DX
pxlvdone:
pexml:
	SUBQ	$255, BX
	JB	pexdone
	CMPQ	BX, $128
	JAE	pxmv2
	MOVB	BX, (DX)
	INCQ	DX
	JMP	pxmvdone
pxmv2:
	CMPQ	BX, $16384
	JAE	pxmv3
	MOVQ	BX, AX
	ANDQ	$0x3F, AX
	ORQ	$0x80, AX
	MOVB	AX, (DX)
	SHRQ	$6, BX
	MOVB	BX, 1(DX)
	ADDQ	$2, DX
	JMP	pxmvdone
pxmv3:
	MOVQ	BX, AX
	ANDQ	$0x1F, AX
	ORQ	$0xC0, AX
	MOVB	AX, (DX)
	MOVQ	BX, AX
	SHRQ	$5, AX
	MOVB	AX, 1(DX)
	SHRQ	$13, BX
	MOVB	BX, 2(DX)
	ADDQ	$3, DX
pxmvdone:
pexdone:
	MOVQ	DX, 120(R14)
	JMP	padvance

pdone:
	MOVQ	R15, 128(R14)
	RET

// SPL parser, levels 3 to 5.
//
// Registers: R14 st   SI src   DI ip   R9 head   R10 tags   R11 chain
//   per position: R8 v, R12 idx, R13 attempts, BX best length - 3,
//   DX chain link; AX CX scratch
// Frame: 0(SP) best length after the backtrack, 8(SP) best ref (-1 none),
// 16(SP) a probe's gate, 24(SP) a probe's attempts, 32(SP) the chain link
// during a match length, 40(SP) the next position after a miss. As the C
// code, it prefetches the table entries of the next position and the gate
// of the next candidate of a chain. In st: anchor (128), lits (104), tokens (112),
// extras (120), offsets (136), largest offset (144), backtracked ip (184).

// func splEncAsm(st *encState)
TEXT ·splEncAsm(SB), NOSPLIT, $48-8
	MOVQ	st+0(FP), R14
	MOVQ	0(R14), SI
	MOVQ	8(R14), DI
	MOVQ	DI, 128(R14)
	MOVQ	32(R14), R9
	MOVQ	40(R14), R10
	MOVQ	48(R14), R11
	MOVQ	$0, 144(R14)

sloop:
	CMPQ	DI, 24(R14)
	JGE	sdone
	// The step after a miss, 1 when ip + step reaches the limit, and the
	// prefetch of the next position's entries (ip + 1 <= limit = iend - 8
	// keeps its 8-byte load in src).
	MOVQ	DI, AX
	SUBQ	128(R14), AX
	MOVQ	96(R14), CX
	SHRQ	CX, AX
	ADDQ	88(R14), AX
	ADDQ	DI, AX
	CMPQ	AX, 24(R14)
	JLT	sstepped
	LEAQ	1(DI), AX
sstepped:
	MOVQ	AX, 40(SP)
	MOVQ	(SI)(AX*1), BX
	MOVQ	$0xFFFFFFFFFF, CX
	ANDQ	CX, BX
	MOVQ	$0x2545F4914F6CDD1D, CX
	IMULQ	CX, BX
	SHRQ	$49, BX
	PREFETCHT0	(R10)(BX*1)
	PREFETCHT0	(R9)(BX*4)
	MOVQ	(SI)(DI*1), AX
	MOVL	AX, R8
	MOVQ	$0xFFFFFFFFFF, BX
	ANDQ	AX, BX
	MOVQ	$0x2545F4914F6CDD1D, CX
	IMULQ	CX, BX
	SHRQ	$49, BX
	MOVL	R8, CX
	SHRL	$16, CX
	XORL	R8, CX
	MOVBLZX	(R10)(BX*1), DX
	MOVL	(R9)(BX*4), R12
	MOVL	DI, AX
	ORL	56(R14), AX
	MOVL	AX, (R9)(BX*4)
	MOVB	CX, (R10)(BX*1)
	XORL	R13, R13
	CMPB	CX, DX
	SETNE	R13 // skip the head: another tag
	MOVL	DI, BX
	ANDL	$0xFFFF, BX
	XORL	56(R14), R12
	CMPL	R12, 64(R14)
	JA	snocand
	TESTL	R12, R12
	JZ	snocand
	MOVL	DI, AX
	SUBL	R12, AX
	XORL	CX, CX
	CMPL	AX, $65536
	CMOVLCC	CX, AX
	MOVW	AX, (R11)(BX*2)

	MOVQ	$-1, 8(SP)
	MOVQ	152(R14), CX
	TESTQ	R13, R13
	JZ	sstart
	MOVL	R12, AX
	ANDL	$0xFFFF, AX
	MOVWLZX	(R11)(AX*2), DX
	DECQ	CX
	TESTL	DX, DX
	JZ	swalked
	SUBL	DX, R12
	JZ	swalked
sstart:
	MOVQ	CX, R13
	MOVL	$1, BX
scand:
	MOVL	DI, AX
	SUBL	R12, AX
	CMPL	AX, $65535
	JA	swalked
	TESTQ	R13, R13
	JS	swalked
	DECQ	R13
	MOVL	R12, CX
	ANDL	$0xFFFF, CX
	MOVWLZX	(R11)(CX*2), DX
	MOVL	R12, CX
	SUBL	DX, CX
	ADDQ	BX, CX
	PREFETCHT0	(SI)(CX*1) // the next candidate's gate
	CMPQ	AX, 72(R14)
	JLT	snext
	LEAQ	(R12)(BX*1), CX
	MOVL	(SI)(CX*1), CX
	LEAQ	(DI)(BX*1), AX
	CMPL	CX, (SI)(AX*1)
	JEQ	sgate
snext:
	TESTL	DX, DX
	JZ	swalked
	SUBL	DX, R12
	JNZ	scand
swalked:
	CMPQ	8(SP), $0
	JGE	shit
smiss:
	MOVQ	40(SP), DI
	JMP	sloop
snocand:
	MOVW	$0, (R11)(BX*2)
	JMP	smiss

sgate:
	MOVL	(SI)(R12*1), AX
	CMPL	AX, R8
	JNE	snext
	MOVQ	DX, 32(SP)
	MOVL	$4, CX
sml:
	LEAQ	8(DI)(CX*1), AX
	CMPQ	AX, 16(R14)
	JA	smtail
	LEAQ	(DI)(CX*1), AX
	MOVQ	(SI)(AX*1), AX
	LEAQ	(R12)(CX*1), DX
	XORQ	(SI)(DX*1), AX
	JNZ	smdiff
	ADDQ	$8, CX
	JMP	sml
smdiff:
	BSFQ	AX, AX
	SHRQ	$3, AX
	ADDQ	AX, CX
	JMP	smdone
smtail:
	LEAQ	(DI)(CX*1), AX
	CMPQ	AX, 16(R14)
	JAE	smdone
	MOVBLZX	(SI)(AX*1), AX
	LEAQ	(R12)(CX*1), DX
	CMPB	AX, (SI)(DX*1)
	JNE	smdone
	INCQ	CX
	JMP	smtail
smdone:
	MOVQ	32(SP), DX
	LEAQ	3(BX), AX
	CMPQ	CX, AX
	JLE	snobetter
	LEAQ	-3(CX), BX
	MOVQ	R12, 8(SP)
snobetter:
	LEAQ	3(BX), AX
	CMPQ	AX, 80(R14)
	JGE	swalked
	ADDQ	DI, AX
	CMPQ	AX, 16(R14)
	JGE	swalked
	JMP	snext

shit:
	// Backtrack into AX (ip stays for the probes), R12, R13.
	LEAQ	3(BX), R13
	MOVQ	8(SP), R12
	MOVQ	DI, AX
	MOVQ	128(R14), R8
sback:
	CMPQ	AX, R8
	JLE	sbacked
	TESTQ	R12, R12
	JZ	sbacked
	MOVB	-1(SI)(AX*1), CX
	CMPB	CX, -1(SI)(R12*1)
	JNE	sbacked
	DECQ	AX
	DECQ	R12
	INCQ	R13
	JMP	sback
sbacked:
	MOVQ	AX, 184(R14)
	MOVQ	R12, 8(SP)
	MOVQ	R13, 0(SP)
	CMPQ	R13, 168(R14)
	JGE	skeep
	LEAQ	1(DI), R12
	CMPQ	R12, 24(R14)
	JGE	skeep
	MOVQ	0(SP), R13
	ADDQ	$2, R13
	MOVQ	16(R14), AX
	SUBQ	R12, AX
	CMPQ	R13, AX
	JG	sp1no
	SUBQ	$4, R13
	MOVQ	(SI)(R12*1), AX
	MOVL	AX, R8
	MOVQ	$0xFFFFFFFFFF, BX
	ANDQ	AX, BX
	MOVQ	$0x2545F4914F6CDD1D, CX
	IMULQ	CX, BX
	SHRQ	$49, BX
	LEAQ	(R12)(R13*1), CX
	MOVL	(SI)(CX*1), CX
	MOVL	CX, 16(SP)
	MOVL	R8, CX
	SHRL	$16, CX
	XORL	R8, CX
	MOVBLZX	(R10)(BX*1), DX
	XORL	AX, AX
	CMPB	CX, DX
	SETNE	AX
	MOVL	(R9)(BX*4), BX
	XORL	56(R14), BX
	CMPL	BX, 64(R14)
	JA	sp1no
	TESTL	BX, BX
	JZ	sp1no
	MOVQ	160(R14), CX
	TESTQ	CX, CX
	JZ	sp1no
	MOVQ	CX, 24(SP)
sp1cand:
	MOVL	R12, CX
	SUBL	BX, CX
	CMPL	CX, $65535
	JA	sp1no
	TESTL	AX, AX
	JNZ	sp1next
	CMPQ	CX, 72(R14)
	JLT	sp1next
	LEAQ	(BX)(R13*1), CX
	MOVL	(SI)(CX*1), CX
	CMPL	CX, 16(SP)
	JEQ	sp1gate
sp1next:
	XORL	AX, AX
	MOVL	BX, CX
	ANDL	$0xFFFF, CX
	MOVWLZX	(R11)(CX*2), CX
	TESTL	CX, CX
	JZ	sp1no
	SUBL	CX, BX
	DECQ	24(SP)
	JZ	sp1no
	TESTL	BX, BX
	JNZ	sp1cand
	JMP	sp1no
sp1gate:
	MOVL	(SI)(BX*1), CX
	CMPL	CX, R8
	JNE	sp1next
	CMPQ	R13, $4
	JLE	smiss
	MOVL	$4, AX
sp1ml:
	LEAQ	4(AX), CX
	CMPQ	CX, R13
	JG	sp1mlast
	LEAQ	(R12)(AX*1), CX
	MOVQ	(SI)(CX*1), CX
	LEAQ	(BX)(AX*1), DX
	CMPQ	CX, (SI)(DX*1)
	JNE	sp1next
	ADDQ	$8, AX
	JMP	sp1ml
sp1mlast:
	LEAQ	4(R13), CX
	CMPQ	AX, CX
	JAE	smiss
	LEAQ	-4(R13), AX
	LEAQ	(R12)(AX*1), CX
	MOVQ	(SI)(CX*1), CX
	LEAQ	(BX)(AX*1), DX
	CMPQ	CX, (SI)(DX*1)
	JEQ	smiss
	JMP	sp1next
sp1no:
	CMPQ	176(R14), $4
	JLT	skeep
	LEAQ	2(DI), R12
	CMPQ	R12, 24(R14)
	JGE	skeep
	MOVQ	0(SP), R13
	ADDQ	$3, R13
	MOVQ	16(R14), AX
	SUBQ	R12, AX
	CMPQ	R13, AX
	JG	skeep
	SUBQ	$4, R13
	MOVQ	(SI)(R12*1), AX
	MOVL	AX, R8
	MOVQ	$0xFFFFFFFFFF, BX
	ANDQ	AX, BX
	MOVQ	$0x2545F4914F6CDD1D, CX
	IMULQ	CX, BX
	SHRQ	$49, BX
	LEAQ	(R12)(R13*1), CX
	MOVL	(SI)(CX*1), CX
	MOVL	CX, 16(SP)
	MOVL	R8, CX
	SHRL	$16, CX
	XORL	R8, CX
	MOVBLZX	(R10)(BX*1), DX
	XORL	AX, AX
	CMPB	CX, DX
	SETNE	AX
	MOVL	(R9)(BX*4), BX
	XORL	56(R14), BX
	CMPL	BX, 64(R14)
	JA	skeep
	TESTL	BX, BX
	JZ	skeep
	MOVQ	160(R14), CX
	TESTQ	CX, CX
	JZ	skeep
	MOVQ	CX, 24(SP)
sp2cand:
	MOVL	R12, CX
	SUBL	BX, CX
	CMPL	CX, $65535
	JA	skeep
	TESTL	AX, AX
	JNZ	sp2next
	CMPQ	CX, 72(R14)
	JLT	sp2next
	LEAQ	(BX)(R13*1), CX
	MOVL	(SI)(CX*1), CX
	CMPL	CX, 16(SP)
	JEQ	sp2gate
sp2next:
	XORL	AX, AX
	MOVL	BX, CX
	ANDL	$0xFFFF, CX
	MOVWLZX	(R11)(CX*2), CX
	TESTL	CX, CX
	JZ	skeep
	SUBL	CX, BX
	DECQ	24(SP)
	JZ	skeep
	TESTL	BX, BX
	JNZ	sp2cand
	JMP	skeep
sp2gate:
	MOVL	(SI)(BX*1), CX
	CMPL	CX, R8
	JNE	sp2next
	CMPQ	R13, $4
	JLE	smiss
	MOVL	$4, AX
sp2ml:
	LEAQ	4(AX), CX
	CMPQ	CX, R13
	JG	sp2mlast
	LEAQ	(R12)(AX*1), CX
	MOVQ	(SI)(CX*1), CX
	LEAQ	(BX)(AX*1), DX
	CMPQ	CX, (SI)(DX*1)
	JNE	sp2next
	ADDQ	$8, AX
	JMP	sp2ml
sp2mlast:
	LEAQ	4(R13), CX
	CMPQ	AX, CX
	JAE	smiss
	LEAQ	-4(R13), AX
	LEAQ	(R12)(AX*1), CX
	MOVQ	(SI)(CX*1), CX
	LEAQ	(BX)(AX*1), DX
	CMPQ	CX, (SI)(DX*1)
	JEQ	smiss
	JMP	sp2next

skeep:
	MOVQ	184(R14), DI
	MOVQ	0(SP), R13
	MOVQ	8(SP), R12
	MOVQ	128(R14), R8
	MOVQ	DI, CX
	SUBQ	R8, CX
	LEAQ	(SI)(R8*1), R8
	MOVQ	104(R14), DX
	TESTQ	CX, CX
	JZ	slcdone
	CMPQ	CX, $16
	JB	slcsmall
	XORL	BX, BX
	LEAQ	-16(CX), AX
slc16:
	CMPQ	BX, AX
	JAE	slc16last
	MOVOU	(R8)(BX*1), X0
	MOVOU	X0, (DX)(BX*1)
	ADDQ	$16, BX
	JMP	slc16
slc16last:
	MOVOU	(R8)(AX*1), X0
	MOVOU	X0, (DX)(AX*1)
	JMP	slcdone
slcsmall:
	CMPQ	CX, $8
	JB	slcsmall4
	MOVQ	(R8), AX
	MOVQ	AX, (DX)
	MOVQ	-8(R8)(CX*1), AX
	MOVQ	AX, -8(DX)(CX*1)
	JMP	slcdone
slcsmall4:
	CMPQ	CX, $4
	JB	slcsmall1
	MOVL	(R8), AX
	MOVL	AX, (DX)
	MOVL	-4(R8)(CX*1), AX
	MOVL	AX, -4(DX)(CX*1)
	JMP	slcdone
slcsmall1:
	MOVBLZX	(R8), AX
	MOVB	AX, (DX)
	MOVQ	CX, BX
	SHRQ	$1, BX
	MOVBLZX	(R8)(BX*1), AX
	MOVB	AX, (DX)(BX*1)
	MOVBLZX	-1(R8)(CX*1), AX
	MOVB	AX, -1(DX)(CX*1)
slcdone:
	ADDQ	CX, DX
	MOVQ	DX, 104(R14)
	// Token, offset, largest offset, extras of lengths of 15 or more.
	LEAQ	-5(R13), BX // ml
	MOVQ	DI, AX
	SUBQ	R12, AX
	DECQ	AX // off - 1
	MOVQ	$15, DX
	MOVQ	CX, R8
	CMPQ	R8, DX
	CMOVQCC	DX, R8
	SHLQ	$4, R8
	MOVQ	BX, R12
	CMPQ	R12, DX
	CMOVQCC	DX, R12
	ORQ	R12, R8
	MOVQ	112(R14), DX
	MOVB	R8, (DX)
	INCQ	DX
	MOVQ	DX, 112(R14)
	MOVQ	136(R14), DX
	MOVW	AX, (DX)
	ADDQ	$2, DX
	MOVQ	DX, 136(R14)
	CMPQ	AX, 144(R14)
	JBE	smaxed
	MOVQ	AX, 144(R14)
smaxed:
	CMPQ	CX, $15
	JAE	sextras
	CMPQ	BX, $15
	JAE	sextras
sinsert:
	CMPQ	176(R14), $5
	JLT	sadvance
	LEAQ	(DI)(R13*1), CX
	MOVQ	16(R14), AX
	SUBQ	$7, AX
	CMPQ	CX, AX
	JGE	sadvance
	SUBQ	$2, CX // the position inserted
	MOVQ	(SI)(CX*1), AX
	MOVL	AX, R8
	MOVQ	$0xFFFFFFFFFF, BX
	ANDQ	AX, BX
	MOVQ	$0x2545F4914F6CDD1D, DX
	IMULQ	DX, BX
	SHRQ	$49, BX
	MOVL	R8, DX
	SHRL	$16, DX
	XORL	R8, DX
	MOVB	DX, (R10)(BX*1)
	MOVL	(R9)(BX*4), R12
	XORL	56(R14), R12
	XORL	DX, DX
	CMPL	R12, 64(R14)
	CMOVLHI	DX, R12 // previous position, 0 when of another epoch
	MOVL	CX, AX
	ORL	56(R14), AX
	MOVL	AX, (R9)(BX*4)
	MOVL	CX, AX
	SUBL	R12, AX
	CMPL	AX, $65536
	CMOVLCC	DX, AX
	TESTL	R12, R12
	CMOVLEQ	DX, AX
	ANDL	$0xFFFF, CX
	MOVW	AX, (R11)(CX*2)
sadvance:
	ADDQ	R13, DI
	MOVQ	DI, 128(R14)
	JMP	sloop
sextras:
	MOVQ	120(R14), DX
	SUBQ	$15, CX
	JB	sexml
	CMPQ	CX, $128
	JAE	sxlv2
	MOVB	CX, (DX)
	INCQ	DX
	JMP	sxlvdone
sxlv2:
	CMPQ	CX, $16384
	JAE	sxlv3
	MOVQ	CX, AX
	ANDQ	$0x3F, AX
	ORQ	$0x80, AX
	MOVB	AX, (DX)
	SHRQ	$6, CX
	MOVB	CX, 1(DX)
	ADDQ	$2, DX
	JMP	sxlvdone
sxlv3:
	MOVQ	CX, AX
	ANDQ	$0x1F, AX
	ORQ	$0xC0, AX
	MOVB	AX, (DX)
	MOVQ	CX, AX
	SHRQ	$5, AX
	MOVB	AX, 1(DX)
	SHRQ	$13, CX
	MOVB	CX, 2(DX)
	ADDQ	$3, DX
sxlvdone:
sexml:
	SUBQ	$15, BX
	JB	sexdone
	CMPQ	BX, $128
	JAE	sxmv2
	MOVB	BX, (DX)
	INCQ	DX
	JMP	sxmvdone
sxmv2:
	CMPQ	BX, $16384
	JAE	sxmv3
	MOVQ	BX, AX
	ANDQ	$0x3F, AX
	ORQ	$0x80, AX
	MOVB	AX, (DX)
	SHRQ	$6, BX
	MOVB	BX, 1(DX)
	ADDQ	$2, DX
	JMP	sxmvdone
sxmv3:
	MOVQ	BX, AX
	ANDQ	$0x1F, AX
	ORQ	$0xC0, AX
	MOVB	AX, (DX)
	MOVQ	BX, AX
	SHRQ	$5, AX
	MOVB	AX, 1(DX)
	SHRQ	$13, BX
	MOVB	BX, 2(DX)
	ADDQ	$3, DX
sxmvdone:
sexdone:
	MOVQ	DX, 120(R14)
	JMP	sinsert

sdone:
	RET

// Match splitting of the SPL encoder: splitAnalyze, then the marking and
// expansion passes of splitMatches (compress_spl.go), called through
// splitFast (compress_asm.go), whose comment gives the proof of the
// accesses. The limit is at most 33, so a split match has 2 pieces.
//
// Registers: R14 st   SI toks   R8 extras   R9 side   R12 n   AX i
//   histogram: BX h   DX hmask   R10 hist   R13 escapes
//   marking: BX r   DX w   R11 bad   R10 bad context   R13 extra
//   expansion: DI offs   CX out
// Frame: 0(SP) escapes, 8(SP) a token kept during a move.

// func splitAsm(st *splitState)
TEXT ·splitAsm(SB), NOSPLIT, $16-8
	MOVQ	st+0(FP), R14
	MOVQ	0(R14), SI
	MOVQ	16(R14), R8
	MOVQ	24(R14), R9
	MOVQ	32(R14), R10
	MOVQ	48(R14), R12
	MOVQ	$0, 72(R14)

	// order: 8, less while n >> order < 16, 2 at least.
	MOVL	$8, CX
xorder:
	CMPQ	CX, $2
	JLE	xordered
	MOVQ	R12, AX
	SHRQ	CX, AX
	CMPQ	AX, $16
	JAE	xordered
	DECQ	CX
	JMP	xorder
xordered:
	MOVL	$1, DX
	SHLL	CX, DX
	DECL	DX // hmask

	// Contexts and histogram (hist is zeroed by the Go caller).
	XORL	AX, AX
	XORL	BX, BX
	XORL	R13, R13
xhist:
	CMPQ	AX, R12
	JAE	xhisted
	MOVBLZX	(SI)(AX*1), CX
	ANDL	$15, CX
	XORL	R11, R11
	CMPL	CX, $15
	SETEQ	R11 // esc
	MOVB	BX, (R9)(AX*1)
	MOVL	R11, DI
	SHLL	$8, DI
	ADDL	BX, DI
	INCL	(R10)(DI*4)
	LEAL	(R11)(BX*2), BX
	ANDL	DX, BX
	ADDQ	R11, R13
	INCQ	AX
	JMP	xhist
xhisted:

	// bad contexts, mispredictions (BX), escapes in bad contexts (DI).
	MOVQ	40(R14), R11
	XORL	AX, AX
	XORL	BX, BX
	XORL	DI, DI
xbad:
	CMPL	AX, DX
	JA	xbaded
	MOVL	(R10)(AX*4), CX // n0
	MOVL	1024(R10)(AX*4), R8 // n1
	CMPL	R8, CX
	JB	xbadctx
	MOVB	$0, (R11)(AX*1)
	ADDQ	CX, BX
	INCL	AX
	JMP	xbad
xbadctx:
	MOVB	$1, (R11)(AX*1)
	ADDQ	R8, BX
	ADDQ	R8, DI
	INCL	AX
	JMP	xbad
xbaded:
	TESTQ	DI, DI
	JZ	xnone
	IMUL3Q	$100, BX, BX
	IMUL3Q	$80, R13, R13
	CMPQ	BX, R13
	JB	xnone

	// Pass 1: mark the matches to split, side[i] = their length code,
	// dropping their varints; the other varints move down.
	MOVQ	16(R14), R8
	XORL	AX, AX
	XORL	BX, BX // r
	XORL	DX, DX // w
	XORL	R13, R13 // extra
xmark:
	CMPQ	AX, R12
	JAE	xmarked
	MOVBLZX	(SI)(AX*1), CX // t
	MOVBLZX	(R9)(AX*1), R10
	MOVBLZX	(R11)(R10*1), R10 // isBad
	MOVB	$0, (R9)(AX*1)
	MOVL	CX, DI
	SHRL	$4, DI
	CMPL	DI, $15
	JNE	xnoll
	// Keep the literal-length varint: its length max(b >> 6, 1).
	MOVBLZX	(R8)(BX*1), DI
	SHRL	$6, DI
	CMPL	DI, $1
	ADCL	$0, DI
	MOVQ	CX, 8(SP)
	CMPQ	BX, DX
	JEQ	xllkept
	MOVB	(R8)(BX*1), CX
	MOVB	CX, (R8)(DX*1)
	CMPQ	DI, $2
	JB	xllkept
	MOVB	1(R8)(BX*1), CX
	MOVB	CX, 1(R8)(DX*1)
	CMPQ	DI, $3
	JB	xllkept
	MOVB	2(R8)(BX*1), CX
	MOVB	CX, 2(R8)(DX*1)
xllkept:
	MOVQ	8(SP), CX
	ADDQ	DI, BX
	ADDQ	DI, DX
xnoll:
	ANDL	$15, CX
	CMPL	CX, $15
	JNE	xnext
	// The match-length varint: its value, code = value + 15, in CX; its
	// length in DI.
	MOVBLZX	(R8)(BX*1), CX
	CMPL	CX, $0x80
	JB	xv1
	MOVBLZX	1(R8)(BX*1), DI
	CMPL	CX, $0xC0
	JAE	xv3
	ANDL	$0x3F, CX
	SHLL	$6, DI
	ORL	DI, CX
	MOVL	$2, DI
	JMP	xvd
xv3:
	ANDL	$0x1F, CX
	SHLL	$5, DI
	ORL	DI, CX
	MOVBLZX	2(R8)(BX*1), DI
	SHLL	$13, DI
	ORL	DI, CX
	MOVL	$3, DI
	JMP	xvd
xv1:
	MOVL	$1, DI
xvd:
	ADDL	$15, CX
	TESTL	R10, R10
	JZ	xkeepml
	CMPQ	CX, 56(R14)
	JA	xkeepml
	MOVB	CX, (R9)(AX*1)
	INCQ	R13
	ADDQ	DI, BX
	JMP	xnext
xkeepml:
	CMPQ	BX, DX
	JEQ	xmlkept
	MOVB	(R8)(BX*1), CX
	MOVB	CX, (R8)(DX*1)
	CMPQ	DI, $2
	JB	xmlkept
	MOVB	1(R8)(BX*1), CX
	MOVB	CX, 1(R8)(DX*1)
	CMPQ	DI, $3
	JB	xmlkept
	MOVB	2(R8)(BX*1), CX
	MOVB	CX, 2(R8)(DX*1)
xmlkept:
	ADDQ	DI, BX
	ADDQ	DI, DX
xnext:
	INCQ	AX
	JMP	xmark
xmarked:
	MOVQ	DX, 64(R14)
	MOVQ	$1, 72(R14)
	TESTQ	R13, R13
	JZ	xdone

	// Pass 2: expand backward; a marked sequence of code c becomes
	// (ll, min(c-5, 14)) and (0, c - piece - 5) at the same offset.
	MOVQ	8(R14), DI
	LEAQ	(R12)(R13*1), CX // out
	MOVQ	CX, 48(R14)
	MOVQ	R12, AX
	MOVL	$14, R12
xexp:
	TESTQ	AX, AX
	JZ	xdone
	DECQ	AX
	MOVBLZX	(SI)(AX*1), BX
	MOVWLZX	(DI)(AX*2), DX
	MOVBLZX	(R9)(AX*1), R10
	TESTL	R10, R10
	JNZ	xpieces
	DECQ	CX
	MOVB	BX, (SI)(CX*1)
	MOVW	DX, (DI)(CX*2)
	JMP	xexp
xpieces:
	SUBQ	$2, CX
	ANDL	$0xF0, BX // literal-length bits
	LEAL	-5(R10), R11
	CMPL	R11, R12
	CMOVLCC	R12, R11 // piece
	ORL	R11, BX
	MOVB	BX, (SI)(CX*1)
	MOVW	DX, (DI)(CX*2)
	SUBL	R11, R10
	SUBL	$5, R10 // the rest's code
	MOVB	R10, 1(SI)(CX*1)
	MOVW	DX, 2(DI)(CX*2)
	JMP	xexp

xnone:
	MOVQ	$0, 72(R14) // no split: n and nx stay
xdone:
	RET

// RLE literal section: rleSize, and appendRLE when out is not nil
// (compress_spl.go), called through rleFast (compress_asm.go), whose
// comment gives the proof of the accesses. A run of rleMinRun equal bytes
// or more becomes (0x80 | c-4, b) pairs of c <= 131 bytes, its last 1 to 3
// bytes a copy; other bytes are copies of up to 128 bytes behind a c-1
// header. The search for the end of a copy tests 16 positions a step with
// SSE2: lanes j where bytes j, j+1, j+2 and j+3 agree.
//
// Registers: SI lits   R12 n   BX i   DI out (0: size only)   R13 size
//   R11 start   R8 b   R9 b in every byte, then the copy's source
//   AX CX DX R10 scratch   X0-X3

// func rleAsm(st *rleState)
TEXT ·rleAsm(SB), NOSPLIT, $0-8
	MOVQ	st+0(FP), AX
	MOVQ	0(AX), SI
	MOVQ	8(AX), R12
	MOVQ	16(AX), DI
	XORL	BX, BX
	XORL	R13, R13

rtop:
	CMPQ	BX, R12
	JAE	rdone
	MOVQ	BX, R11
	MOVBLZX	(SI)(BX*1), R8
	INCQ	BX

	// The run of b: 8 bytes a step, then bytes.
	MOVQ	$0x0101010101010101, R9
	IMULQ	R8, R9
rrun8:
	LEAQ	8(BX), R10
	CMPQ	R10, R12
	JA	rrun1
	MOVQ	(SI)(BX*1), AX
	XORQ	R9, AX
	JNZ	rrunx
	MOVQ	R10, BX
	JMP	rrun8
rrunx:
	BSFQ	AX, AX
	SHRQ	$3, AX
	ADDQ	AX, BX
	JMP	rrunend
rrun1:
	CMPQ	BX, R12
	JAE	rrunend
	MOVBLZX	(SI)(BX*1), AX
	CMPL	AX, R8
	JNE	rrunend
	INCQ	BX
	JMP	rrun1
rrunend:
	MOVQ	BX, AX
	SUBQ	R11, AX // run
	CMPQ	AX, $4
	JB	rcopy

	// A run: q full pairs (AX), then the rest (DX).
	XORL	DX, DX
	MOVL	$131, CX
	DIVL	CX
	LEAQ	(R13)(AX*2), R13
	CMPQ	DX, $4
	JB	rrem
	ADDQ	$2, R13
	JMP	rrunw
rrem:
	ADDQ	DX, R13
	TESTQ	DX, DX
	JZ	rrunw
	INCQ	R13
rrunw:
	TESTQ	DI, DI
	JZ	rtop
rfull:
	TESTQ	AX, AX
	JZ	rlast
	MOVB	$0xFF, (DI) // 0x80 | (131 - 4)
	MOVB	R8, 1(DI)
	ADDQ	$2, DI
	DECQ	AX
	JMP	rfull
rlast:
	TESTQ	DX, DX
	JZ	rtop
	CMPQ	DX, $4
	JB	rlastcopy
	LEAL	-4(DX), CX
	ORL	$0x80, CX
	MOVB	CX, (DI)
	MOVB	R8, 1(DI)
	ADDQ	$2, DI
	JMP	rtop
rlastcopy:
	// 1 to 3 bytes, all equal to b.
	LEAL	-1(DX), CX
	MOVB	CX, (DI)
	INCQ	DI
rlastb:
	MOVB	R8, (DI)
	INCQ	DI
	DECQ	DX
	JNZ	rlastb
	JMP	rtop

rcopy:
	// The copy reaching i ends at the next 4 equal bytes, or at n.
rce16:
	LEAQ	19(BX), R10
	CMPQ	R10, R12
	JA	rce1
	MOVOU	(SI)(BX*1), X0
	MOVOU	1(SI)(BX*1), X1
	MOVOU	2(SI)(BX*1), X2
	MOVOU	3(SI)(BX*1), X3
	PCMPEQB	X1, X0
	PCMPEQB	X2, X1
	PCMPEQB	X3, X2
	PAND	X1, X0
	PAND	X2, X0
	PMOVMSKB	X0, AX
	TESTL	AX, AX
	JNZ	rcex
	ADDQ	$16, BX
	JMP	rce16
rcex:
	BSFL	AX, AX
	ADDQ	AX, BX
	JMP	rcend
rce1:
	CMPQ	BX, R12
	JAE	rcend
	LEAQ	3(BX), R10
	CMPQ	R10, R12
	JAE	rce1next
	MOVBLZX	(SI)(BX*1), AX
	CMPB	AX, 1(SI)(BX*1)
	JNE	rce1next
	CMPB	AX, 2(SI)(BX*1)
	JNE	rce1next
	CMPB	AX, 3(SI)(BX*1)
	JEQ	rcend
rce1next:
	INCQ	BX
	JMP	rce1
rcend:
	MOVQ	BX, R10
	SUBQ	R11, R10 // run
	ADDQ	R10, R13
	ADDQ	$127, R10
	SHRQ	$7, R10
	ADDQ	R10, R13
	TESTQ	DI, DI
	JZ	rtop

	// Write: pieces of up to 128 bytes, each behind its c-1 header.
	LEAQ	(SI)(R11*1), R9 // source
rpiece:
	LEAQ	(SI)(BX*1), AX
	SUBQ	R9, AX // left
	JZ	rtop
	MOVL	$128, CX
	CMPQ	AX, CX
	CMOVQCC	CX, AX // c
	LEAL	-1(AX), CX
	MOVB	CX, (DI)
	INCQ	DI
	LEAQ	(R9)(AX*1), R10 // source end of the piece
	LEAQ	(DI)(AX*1), DX // destination end
	CMPQ	AX, $16
	JB	rpsmall
	LEAQ	-16(R10), CX
rp16:
	CMPQ	R9, CX
	JAE	rp16last
	MOVOU	(R9), X0
	MOVOU	X0, (DI)
	ADDQ	$16, R9
	ADDQ	$16, DI
	JMP	rp16
rp16last:
	MOVOU	(CX), X0
	MOVOU	X0, -16(DX)
	JMP	rpdone
rpsmall:
	CMPQ	AX, $8
	JB	rpsmall4
	MOVQ	(R9), CX
	MOVQ	-8(R10), R11
	MOVQ	CX, (DI)
	MOVQ	R11, -8(DX)
	JMP	rpdone
rpsmall4:
	CMPQ	AX, $4
	JB	rpsmall1
	MOVL	(R9), CX
	MOVL	-4(R10), R11
	MOVL	CX, (DI)
	MOVL	R11, -4(DX)
	JMP	rpdone
rpsmall1:
	MOVB	(R9), CX
	MOVB	CX, (DI)
	SHRQ	$1, AX
	MOVB	(R9)(AX*1), CX
	MOVB	CX, (DI)(AX*1)
	MOVB	-1(R10), CX
	MOVB	CX, -1(DX)
rpdone:
	MOVQ	R10, R9
	MOVQ	DX, DI
	JMP	rpiece

rdone:
	MOVQ	st+0(FP), AX
	MOVQ	R13, 24(AX)
	MOVQ	DI, 16(AX)
	RET

// Optimal parser of levels 6 and 7: the dynamic program of optimalDP with
// findBestMatch inline (compress_opt.go, compress_match.go), called through
// optParseFast (compress_asm.go), whose comment gives the proof of the
// accesses. Positions are window positions ip; dp, parentLen and parentOff
// are addressed through pointers biased by -start, so that entry ip-start
// is at ip. At these levels the offset floor is 1 (no distance test), there
// is no lazy probe and no backtrack (the anchor is ip), and the previous
// match's offset is tried first.
//
// Registers:
//   R14 st   SI src   DI ip
//   search: R9 head   R10 tags   R11 chain   R8 v   R12 idx   R13 attempts
//     BX best length - 3   DX skip flag, then chain link   AX CX scratch
//   relaxation: R9 R10 R11 dp, parentLen, parentOff biased by -ip
//     R8 offset-1   BX lMax   R12 L   R13 lMax+1   DX cost   AX range end
//     CX range bound
// Frame: 8(SP) best ref (-1 none), 16(SP) 24(SP) 32(SP) dp, parentLen,
// parentOff biased by -start, 40(SP) DX during a match length.
// In st: skipUntil, lastOff, prevP, prevLen, depth, sufficient, litCost.

// func optEncAsm(st *optState)
TEXT ·optEncAsm(SB), NOSPLIT, $48-8
	MOVQ	st+0(FP), R14
	MOVQ	0(R14), SI
	MOVQ	8(R14), DI
	MOVQ	DI, CX
	SHLQ	$2, CX
	MOVQ	72(R14), AX
	SUBQ	CX, AX
	MOVQ	AX, 16(SP)
	SHRQ	$1, CX
	MOVQ	80(R14), AX
	SUBQ	CX, AX
	MOVQ	AX, 24(SP)
	MOVQ	88(R14), AX
	SUBQ	CX, AX
	MOVQ	AX, 32(SP)
	MOVQ	32(R14), R9
	MOVQ	40(R14), R10
	MOVQ	48(R14), R11
	MOVQ	$0, 120(R14)
	MOVQ	$0, 128(R14)
	MOVQ	$0, 136(R14)
	MOVQ	$0, 144(R14)

oloop:
	CMPQ	DI, 24(R14)
	JGE	otail
	MOVQ	16(SP), AX
	MOVL	(AX)(DI*4), CX
	CMPL	CX, $-1
	JEQ	onext
	// The literal: dp[ip+1] = dp[ip] + litCost when lower.
	ADDL	96(R14), CX
	CMPL	CX, 4(AX)(DI*4)
	JCC	olit
	MOVL	CX, 4(AX)(DI*4)
	MOVQ	24(SP), AX
	MOVW	$0, 2(AX)(DI*2)
olit:
	CMPQ	DI, 120(R14)
	JLT	onext

	// Hash of 5 bytes, tag, head; the head and its chain link.
	MOVQ	(SI)(DI*1), AX
	MOVL	AX, R8
	MOVQ	$0xFFFFFFFFFF, BX
	ANDQ	AX, BX
	MOVQ	$0x2545F4914F6CDD1D, CX
	IMULQ	CX, BX
	SHRQ	$49, BX
	MOVL	R8, CX
	SHRL	$16, CX
	XORL	R8, CX
	MOVBLZX	(R10)(BX*1), DX
	MOVL	(R9)(BX*4), R12
	MOVL	DI, AX
	ORL	56(R14), AX
	MOVL	AX, (R9)(BX*4)
	MOVB	CX, (R10)(BX*1)
	CMPB	CX, DX
	MOVL	$0, DX
	SETNE	DX // skip the head: another tag
	MOVL	$0, CX
	XORL	56(R14), R12
	CMPL	R12, 64(R14)
	CMOVLHI	CX, R12 // idx, 0 when of another epoch
	MOVL	DI, AX
	SUBL	R12, AX
	CMPL	AX, $65536
	CMOVLCC	CX, AX
	TESTL	R12, R12
	CMOVLEQ	CX, AX
	MOVL	DI, BX
	ANDL	$0xFFFF, BX
	MOVW	AX, (R11)(BX*2)

	MOVL	$1, BX
	MOVQ	$-1, 8(SP)
	MOVQ	104(R14), R13

	// The previous offset, when 0 < lastOff <= 65535 and <= ip.
	MOVQ	128(R14), AX
	TESTQ	AX, AX
	JZ	orepdone
	CMPQ	AX, $65535
	JHI	orepdone
	CMPQ	AX, DI
	JHI	orepdone
	MOVQ	DI, CX
	SUBQ	AX, CX
	MOVL	(SI)(CX*1), AX
	CMPL	AX, R8
	JEQ	orep
orepdone:
	TESTL	R12, R12
	JZ	ofinal
	TESTL	DX, DX
	JZ	ocand
	MOVL	R12, CX
	ANDL	$0xFFFF, CX
	MOVWLZX	(R11)(CX*2), CX
	DECQ	R13
	TESTL	CX, CX
	JZ	ofinal
	SUBL	CX, R12
	JZ	ofinal

	// The chain walk; a candidate failing the gate takes one branch.
ocand:
	MOVL	DI, AX
	SUBL	R12, AX
	CMPL	AX, $65535
	JA	ofinal
	TESTQ	R13, R13
	JS	ofinal
	DECQ	R13
	MOVL	R12, CX
	ANDL	$0xFFFF, CX
	MOVWLZX	(R11)(CX*2), DX
	LEAQ	(R12)(BX*1), CX
	MOVL	(SI)(CX*1), CX
	LEAQ	(DI)(BX*1), AX
	CMPL	CX, (SI)(AX*1)
	JEQ	ogate
onext2:
	TESTL	DX, DX
	JZ	ofinal
	SUBL	DX, R12
	JNZ	ocand

ofinal:
	MOVQ	8(SP), CX
	TESTQ	CX, CX
	JS	onext

	// A match: lastOff, lMax = min(len, iend-ip, 65535), offset - 1.
	MOVQ	DI, R8
	SUBQ	CX, R8
	MOVQ	R8, 128(R14)
	DECQ	R8
	ADDQ	$3, BX
	MOVQ	16(R14), AX
	SUBQ	DI, AX
	CMPQ	BX, AX
	CMOVQHI	AX, BX
	MOVL	$65535, AX
	CMPQ	BX, AX
	CMOVQHI	AX, BX
	MOVQ	16(SP), R9
	LEAQ	(R9)(DI*4), R9
	MOVQ	24(SP), R10
	LEAQ	(R10)(DI*2), R10
	MOVQ	32(SP), R11
	LEAQ	(R11)(DI*2), R11
	MOVL	(R9), CX // dp[ip]

	// Covered: the previous position relaxed longer lengths and dp[ip] >=
	// dp[ip-1]; only lengths 19 and 147 can still win.
	MOVQ	144(R14), AX
	MOVQ	136(R14), DX
	MOVQ	DI, 136(R14)
	MOVQ	BX, 144(R14)
	CMPQ	BX, AX
	JCC	onotcov
	INCQ	DX
	CMPQ	DX, DI
	JNE	onotcov
	CMPL	CX, -4(R9)
	JCS	onotcov
	ADDL	$24, CX
	CMPQ	BX, $19
	JLT	oskip
	CMPL	CX, 76(R9)
	JCC	ocov2
	MOVL	CX, 76(R9)
	MOVW	$19, 38(R10)
	MOVW	R8, 38(R11)
ocov2:
	CMPQ	BX, $147
	JLT	oskip
	ADDL	$8, CX
	CMPL	CX, 588(R9)
	JCC	oskip
	MOVL	CX, 588(R9)
	MOVW	$147, 294(R10)
	MOVW	R8, 294(R11)
	JMP	oskip

onotcov:
	// Lengths 5 to lMax by cost ranges: below 20 no escape (+24 bits),
	// below 148 a 1-byte escape (+32), below 16404 2 bytes (+40), above 3
	// (+48).
	MOVL	$5, R12
	LEAQ	1(BX), R13
	LEAL	24(CX), DX
	MOVL	$20, CX
orange:
	MOVQ	R13, AX
	CMPQ	CX, AX
	CMOVQCS	CX, AX
orloop:
	CMPQ	R12, AX
	JAE	orend
	CMPL	DX, (R9)(R12*4)
	JCC	orskip
	MOVL	DX, (R9)(R12*4)
	MOVW	R12, (R10)(R12*2)
	MOVW	R8, (R11)(R12*2)
orskip:
	INCQ	R12
	JMP	orloop
orend:
	CMPQ	R12, R13
	JAE	oskip
	ADDL	$8, DX
	CMPQ	CX, $20
	JEQ	ob148
	CMPQ	CX, $148
	JEQ	ob16404
	MOVL	$65536, CX
	JMP	orange
ob148:
	MOVL	$148, CX
	JMP	orange
ob16404:
	MOVL	$16404, CX
	JMP	orange

oskip:
	// No search inside a match of 256 bytes or more.
	MOVQ	32(R14), R9
	MOVQ	40(R14), R10
	MOVQ	48(R14), R11
	CMPQ	BX, $256
	JLT	onext
	LEAQ	-1(DI)(BX*1), AX
	MOVQ	AX, 120(R14)
onext:
	INCQ	DI
	JMP	oloop

orep:
	// The previous offset matches 4 bytes: its length is the best so far,
	// and ends the search when sufficient or at the end.
	MOVQ	CX, 8(SP)
	MOVQ	DX, 40(SP)
	MOVL	$4, BX
orml:
	LEAQ	8(DI)(BX*1), AX
	CMPQ	AX, 16(R14)
	JA	ormtail
	LEAQ	(DI)(BX*1), AX
	MOVQ	(SI)(AX*1), AX
	LEAQ	(CX)(BX*1), DX
	XORQ	(SI)(DX*1), AX
	JNZ	ormdiff
	ADDQ	$8, BX
	JMP	orml
ormdiff:
	BSFQ	AX, AX
	SHRQ	$3, AX
	ADDQ	AX, BX
	JMP	ormdone
ormtail:
	LEAQ	(DI)(BX*1), AX
	CMPQ	AX, 16(R14)
	JAE	ormdone
	MOVBLZX	(SI)(AX*1), AX
	LEAQ	(CX)(BX*1), DX
	CMPB	AX, (SI)(DX*1)
	JNE	ormdone
	INCQ	BX
	JMP	ormtail
ormdone:
	MOVQ	40(SP), DX
	CMPQ	BX, 112(R14)
	JGE	orfinal
	LEAQ	(DI)(BX*1), AX
	CMPQ	AX, 16(R14)
	JGE	orfinal
	SUBQ	$3, BX
	JMP	orepdone
orfinal:
	SUBQ	$3, BX
	JMP	ofinal

ogate:
	// A candidate past the gate: the first 4 bytes, then its length.
	MOVL	(SI)(R12*1), AX
	CMPL	AX, R8
	JNE	onext2
	MOVQ	DX, 40(SP)
	MOVL	$4, CX
ogml:
	LEAQ	8(DI)(CX*1), AX
	CMPQ	AX, 16(R14)
	JA	ogmtail
	LEAQ	(DI)(CX*1), AX
	MOVQ	(SI)(AX*1), AX
	LEAQ	(R12)(CX*1), DX
	XORQ	(SI)(DX*1), AX
	JNZ	ogmdiff
	ADDQ	$8, CX
	JMP	ogml
ogmdiff:
	BSFQ	AX, AX
	SHRQ	$3, AX
	ADDQ	AX, CX
	JMP	omdone
ogmtail:
	LEAQ	(DI)(CX*1), AX
	CMPQ	AX, 16(R14)
	JAE	omdone
	MOVBLZX	(SI)(AX*1), AX
	LEAQ	(R12)(CX*1), DX
	CMPB	AX, (SI)(DX*1)
	JNE	omdone
	INCQ	CX
	JMP	ogmtail
omdone:
	MOVQ	40(SP), DX
	LEAQ	3(BX), AX
	CMPQ	CX, AX
	JLE	onobetter
	LEAQ	-3(CX), BX
	MOVQ	R12, 8(SP)
onobetter:
	LEAQ	3(BX), AX
	CMPQ	AX, 112(R14)
	JGE	ofinal
	ADDQ	DI, AX
	CMPQ	AX, 16(R14)
	JGE	ofinal
	JMP	onext2

otail:
	// The last positions: literals only.
	MOVQ	16(SP), AX
	MOVQ	24(SP), DX
otloop:
	CMPQ	DI, 16(R14)
	JGE	odone
	MOVL	(AX)(DI*4), CX
	CMPL	CX, $-1
	JEQ	otnext
	ADDL	96(R14), CX
	CMPL	CX, 4(AX)(DI*4)
	JCC	otnext
	MOVL	CX, 4(AX)(DI*4)
	MOVW	$0, 2(DX)(DI*2)
otnext:
	INCQ	DI
	JMP	otloop
odone:
	RET
