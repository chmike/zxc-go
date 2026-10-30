//go:build !purego

#include "textflag.h"

// Huffman merge kernel for amd64 (SSSE3), called through mergeFast
// (huffman_asm.go), which checks the invariants this code relies on; its
// comment gives the proof of the accesses.
//
// One step makes 16 outputs: X0 holds the next 16 left symbols, X1 the
// next 16 right ones, and the 16 indices hufIdxA[b0] (outputs 0-7) and
// hufIdxB[p][b1] (outputs 8-15), p the number of 1 bits of b0, pick them
// from the 32-byte table {X0, X1}: index i < 16 is left byte i, i >= 16
// right byte i-16. PSHUFB takes a 16-byte table and zeroes the lanes whose
// index has its top bit set, so the step shuffles X0 with i+0x70 (top bit
// set exactly for i >= 16) and X1 with i-16 (top bit set exactly for
// i < 16), and ORs the two. The left position then moves by 16 minus the
// number of 1 bits of b0 and b1, the right one by that number. mergeOnes
// (huffman.go) holds the bit counts.
//
// The loop makes four steps a round while k+64 <= n and l, r <= max-48:
// each step reads at most 16 bytes further on each side than the one
// before, so the one test covers the four. Rounds of two steps (k+32 <= n,
// l, r <= max-16), then single steps (k+16 <= n, l, r <= max) finish.
//
// Registers:
//   DI dst   SI ch   R8 l   R9 r   R11 run   R12 hufIdxA   R13 hufIdxB
//   BX mergeOnes   AX k   CX DX R10 scratch   X0-X4, X6 = 0x70s, X7 = 0x10s
// Frame: n-16 at 0(SP), max at 8(SP), n-32 at 16(SP), max-16 at 24(SP),
// n-64 at 32(SP), max-48 at 40(SP).

// MSTEP makes one step: 16 outputs at dst[k:], k += 16.
#define MSTEP \
	MOVQ	AX, DX; \
	SHRQ	$3, DX; \
	MOVBLZX	(R11)(DX*1), CX; \
	MOVBLZX	1(R11)(DX*1), R10; \
	MOVOU	(SI)(R8*1), X0; \
	MOVOU	(SI)(R9*1), X1; \
	MOVQ	(R12)(CX*8), X2; \
	MOVBLZX	(BX)(CX*1), DX; \
	MOVQ	DX, CX; \
	SHLQ	$8, CX; \
	ADDQ	R10, CX; \
	MOVQ	(R13)(CX*8), X3; \
	PUNPCKLQDQ	X3, X2; \
	MOVO	X2, X4; \
	PADDB	X6, X4; \
	PSHUFB	X4, X0; \
	PSUBB	X7, X2; \
	PSHUFB	X2, X1; \
	POR	X1, X0; \
	MOVOU	X0, (DI)(AX*1); \
	MOVBLZX	(BX)(R10*1), R10; \
	ADDQ	R10, DX; \
	ADDQ	DX, R9; \
	ADDQ	$16, R8; \
	SUBQ	DX, R8; \
	ADDQ	$16, AX

// func hufMergeAsm(dst *byte, n int, ch *byte, l, r, max int, run *byte) (k, lo, ro int)
TEXT ·hufMergeAsm(SB), NOSPLIT, $48-80
	MOVQ	dst+0(FP), DI
	MOVQ	n+8(FP), CX
	SUBQ	$16, CX
	MOVQ	CX, 0(SP)
	SUBQ	$16, CX
	MOVQ	CX, 16(SP)
	SUBQ	$32, CX
	MOVQ	CX, 32(SP)
	MOVQ	ch+16(FP), SI
	MOVQ	l+24(FP), R8
	MOVQ	r+32(FP), R9
	MOVQ	max+40(FP), CX
	MOVQ	CX, 8(SP)
	SUBQ	$16, CX
	MOVQ	CX, 24(SP)
	SUBQ	$32, CX
	MOVQ	CX, 40(SP)
	MOVQ	run+48(FP), R11
	LEAQ	·hufIdxA(SB), R12
	LEAQ	·hufIdxB(SB), R13
	LEAQ	·mergeOnes(SB), BX
	MOVQ	$0x7070707070707070, CX
	MOVQ	CX, X6
	PUNPCKLQDQ	X6, X6
	MOVQ	$0x1010101010101010, CX
	MOVQ	CX, X7
	PUNPCKLQDQ	X7, X7
	XORL	AX, AX

	CMPQ	24(SP), $0
	JLT	loop // fewer than 32 bytes in ch: single steps only
	CMPQ	40(SP), $0
	JLT	loop2 // fewer than 64 bytes in ch: no rounds of four

loop4:
	// k+64 <= n, l <= max-48, r <= max-48 (unsigned: l and r are >= 0).
	CMPQ	AX, 32(SP)
	JGT	loop2
	CMPQ	R8, 40(SP)
	JA	loop2
	CMPQ	R9, 40(SP)
	JA	loop2
	MSTEP
	MSTEP
	MSTEP
	MSTEP
	JMP	loop4

loop2:
	// k+32 <= n, l <= max-16, r <= max-16 (unsigned: l and r are >= 0).
	CMPQ	AX, 16(SP)
	JGT	loop
	CMPQ	R8, 24(SP)
	JA	loop
	CMPQ	R9, 24(SP)
	JA	loop
	MSTEP
	MSTEP
	JMP	loop2

loop:
	// k+16 <= n, l <= max, r <= max.
	CMPQ	AX, 0(SP)
	JGT	done
	CMPQ	R8, 8(SP)
	JA	done
	CMPQ	R9, 8(SP)
	JA	done
	MSTEP
	JMP	loop

done:
	MOVQ	AX, k+56(FP)
	MOVQ	R8, lo+64(FP)
	MOVQ	R9, ro+72(FP)
	RET

// Flat-root kernel (SSSE3), called through flatFast (huffman_asm.go), which
// checks the invariants this code relies on; its comment gives the proof
// of the accesses. D is 2 to 6.
//
// One step decodes 16 codes from the 2D bytes at run[o:], o = 2D*k/16,
// loaded as 16 bytes. Two PSHUFB gather each code's 16-bit window (idxA,
// idxB of hufFlatConst); PMULLW by 2^(16-D-sh) moves the code to the top
// of its lane, dropping the bits above it, and PSRLW by 16-D brings it
// down alone; PACKUSWB packs the 16 codes into bytes. The table lookup
// takes one PSHUFB per 16 entries: for entries 16c to 16c+15, the code
// minus 16c plus 0x70 with unsigned saturation has its top bit clear
// exactly when the code is in range, and PSHUFB zeroes the other lanes, so
// the chunks OR together. D <= 4 needs 1 chunk, D = 5 2 and D = 6 4.
//
// Registers:
//   DI dst   SI run   CX n-16   DX runLen-16   R10 2D   AX k   BX o
//   X4 idxA  X5 idxB  X6 mul  X7 cnt  X8 0x70s  X9 0x10s
//   X10-X13 table   X0-X3, X14 scratch

// EXTRACT leaves in X1 the 16 codes of the step at run[o:].
#define EXTRACT \
	MOVOU	(SI)(BX*1), X0; \
	MOVO	X0, X1; \
	PSHUFB	X4, X1; \
	PSHUFB	X5, X0; \
	PMULLW	X6, X1; \
	PMULLW	X6, X0; \
	PSRLW	X7, X1; \
	PSRLW	X7, X0; \
	PACKUSWB	X0, X1

// CHUNK ORs into X2 the symbols of the codes of X1 in table chunk T, then
// moves X1 to the next chunk.
#define CHUNK(T) \
	MOVO	X1, X3; \
	PADDUSB	X8, X3; \
	MOVO	T, X14; \
	PSHUFB	X3, X14; \
	POR	X14, X2; \
	PSUBB	X9, X1

// func hufFlatAsm(dst *byte, n int, run *byte, runLen int, c *hufFlatConst, tbl *[64]byte, D int) (k int)
TEXT ·hufFlatAsm(SB), NOSPLIT, $0-64
	MOVQ	dst+0(FP), DI
	MOVQ	n+8(FP), CX
	SUBQ	$16, CX
	MOVQ	run+16(FP), SI
	MOVQ	runLen+24(FP), DX
	SUBQ	$16, DX
	MOVQ	c+32(FP), R8
	MOVQ	tbl+40(FP), R9
	MOVQ	D+48(FP), R10
	MOVOU	0(R8), X4
	MOVOU	16(R8), X5
	MOVOU	64(R8), X6
	MOVOU	80(R8), X7
	MOVOU	0(R9), X10
	MOVOU	16(R9), X11
	MOVOU	32(R9), X12
	MOVOU	48(R9), X13
	MOVQ	$0x7070707070707070, R11
	MOVQ	R11, X8
	PUNPCKLQDQ	X8, X8
	MOVQ	$0x1010101010101010, R11
	MOVQ	R11, X9
	PUNPCKLQDQ	X9, X9
	XORL	AX, AX
	XORL	BX, BX
	CMPQ	R10, $5
	JEQ	f2
	JA	f4
	SHLQ	$1, R10

f1:
	// D <= 4: codes below 16, one PSHUFB.
	CMPQ	AX, CX
	JGT	fdone
	CMPQ	BX, DX
	JGT	fdone
	EXTRACT
	MOVO	X10, X2
	PSHUFB	X1, X2
	MOVOU	X2, (DI)(AX*1)
	ADDQ	$16, AX
	ADDQ	R10, BX
	JMP	f1

f2:
	// D = 5: two chunks.
	SHLQ	$1, R10
f2loop:
	CMPQ	AX, CX
	JGT	fdone
	CMPQ	BX, DX
	JGT	fdone
	EXTRACT
	PXOR	X2, X2
	CHUNK(X10)
	CHUNK(X11)
	MOVOU	X2, (DI)(AX*1)
	ADDQ	$16, AX
	ADDQ	R10, BX
	JMP	f2loop

f4:
	// D = 6: four chunks.
	SHLQ	$1, R10
f4loop:
	CMPQ	AX, CX
	JGT	fdone
	CMPQ	BX, DX
	JGT	fdone
	EXTRACT
	PXOR	X2, X2
	CHUNK(X10)
	CHUNK(X11)
	CHUNK(X12)
	CHUNK(X13)
	MOVOU	X2, (DI)(AX*1)
	ADDQ	$16, AX
	ADDQ	R10, BX
	JMP	f4loop

fdone:
	MOVQ	AX, k+56(FP)
	RET

// Whole-section decoder (SSSE3 and POPCNT), called through decodeFast
// (huffman_asm.go), which checks the invariants this code relies on; its
// comment gives the proof of the accesses. The same as hufDecodeAsm in
// huffman_arm64.s: the two passes of hufDecoder.decode with the kernels
// inline; it returns 1, handing the section back to the Go decoder, on
// anything off its path. With fewer registers, what a depth or a node
// needs lives in the frame, and a merge spills the pass's registers.
//
// Registers, pass 1:
//   R8 count   R9 flat   R10 p   R11 i   R12 k   R13 e = base[d+1]
//   AX c   BX D, then bits left   DX ones   DI run bytes   SI run   CX
// Registers, pass 2:
//   R8 count   R9 flat   R10 off   R11 i   R12 k (first child of node i)
//   R13 e   AX c, then symbols left; BX CX DX SI DI per node
// Frame: 0 st, 8 body, 16 bodyLen, 24 body+bodyCap, 32 d, 40 leaves of
// depth d+1, 48 n, 56 base[d], 64 &syms of depth d+1's leaves, 72 buf,
// 80 child, 88 coff, 96 rp, 104-128 R10-R13 around a merge.

// MSTEP3 makes one merge step: 16 outputs at DI, from the 16 symbols at
// SI (left) and R8 (right), control bits at R9; R10 is hufMergeTab, X6
// holds 0x70s and X7 0x10s.
#define MSTEP3 \
	MOVBLZX	(R9), CX; \
	MOVBLZX	1(R9), DX; \
	MOVOU	(SI), X0; \
	MOVOU	(R8), X1; \
	MOVQ	(R10)(CX*8), X2; \
	MOVBLZX	20480(R10)(CX*1), BX; \
	MOVQ	BX, R12; \
	SHLQ	$8, R12; \
	ADDQ	DX, R12; \
	MOVQ	2048(R10)(R12*8), X3; \
	PUNPCKLQDQ	X3, X2; \
	MOVO	X2, X4; \
	PADDB	X6, X4; \
	PSHUFB	X4, X0; \
	PSUBB	X7, X2; \
	PSHUFB	X2, X1; \
	POR	X1, X0; \
	MOVOU	X0, (DI); \
	MOVBLZX	20480(R10)(DX*1), DX; \
	ADDQ	BX, DX; \
	ADDQ	DX, R8; \
	ADDQ	$16, SI; \
	SUBQ	DX, SI; \
	ADDQ	$16, DI; \
	ADDQ	$2, R9

// EXTRACT2 leaves in X1 the 16 codes of a flat-root step at SI.
#define EXTRACT2 \
	MOVOU	(SI), X0; \
	MOVO	X0, X1; \
	PSHUFB	X4, X1; \
	PSHUFB	X5, X0; \
	PMULLW	X6, X1; \
	PMULLW	X6, X0; \
	PSRLW	X7, X1; \
	PSRLW	X7, X0; \
	PACKUSWB	X0, X1

// func hufDecodeAsm(st *hufState) int
TEXT ·hufDecodeAsm(SB), NOSPLIT, $144-16
	MOVQ	st+0(FP), AX
	MOVQ	AX, 0(SP)
	MOVQ	0(AX), BX
	MOVQ	BX, 8(SP)
	MOVQ	8(AX), CX
	MOVQ	CX, 16(SP)
	MOVQ	16(AX), DX
	ADDQ	BX, DX
	MOVQ	DX, 24(SP)
	MOVQ	24(AX), CX
	MOVQ	CX, 48(SP)
	MOVQ	48(AX), R8
	MOVQ	88(AX), R9

	// Pass 1.
	MOVQ	CX, (R8)                // count[0] = n
	MOVQ	104(AX), CX
	MOVQ	64(AX), BX
	MOVQ	8(BX)(CX*8), DX
	MOVQ	$0, (R8)(DX*8)          // the slot after the last node
	XORL	R10, R10
	MOVQ	$0, 32(SP)
p1level:
	MOVQ	0(SP), AX
	MOVQ	32(SP), CX
	CMPQ	CX, 104(AX)
	JGE	p1done
	MOVQ	56(AX), BX
	MOVQ	R10, (BX)(CX*8)         // runs[d] = p
	MOVQ	64(AX), BX
	MOVQ	(BX)(CX*8), R11
	MOVQ	8(BX)(CX*8), R13
	MOVQ	72(AX), BX
	MOVQ	8(BX)(CX*8), DX
	MOVQ	16(BX)(CX*8), SI
	SUBQ	DX, SI
	MOVQ	SI, 40(SP)              // leaves of depth d+1
	SUBQ	(BX)(CX*8), DX          // leaves of depth d
	ADDQ	DX, R11                 // first internal node
	MOVQ	R13, R12                // its first child
p1node:
	CMPQ	R11, R13
	JGE	p1next
	MOVQ	(R8)(R11*8), AX
	TESTQ	AX, AX
	JS	fail                    // never: counts are c-ones, ones <= c
	MOVBQZX	(R9)(R11*1), BX
	TESTQ	BX, BX
	JNZ	p1flat
	LEAQ	7(AX), DI
	SHRQ	$3, DI
	MOVQ	16(SP), CX
	SUBQ	R10, CX
	CMPQ	DI, CX
	JA	fail                    // the run past the section
	MOVQ	8(SP), SI
	ADDQ	R10, SI
	MOVQ	AX, BX
	XORL	DX, DX
p1pc:
	CMPQ	BX, $64
	JB	p1pct
	POPCNTQ	(SI), CX
	ADDQ	CX, DX
	ADDQ	$8, SI
	SUBQ	$64, BX
	JMP	p1pc
p1pct:
	TESTQ	BX, BX
	JZ	p1pcd
	LEAQ	8(SI), CX
	CMPQ	CX, 24(SP)
	JA	fail                    // the last word past bodyCap
	MOVQ	(SI), SI
	MOVQ	BX, CX
	MOVQ	$1, BX
	SHLQ	CX, BX
	DECQ	BX
	ANDQ	BX, SI
	POPCNTQ	SI, CX
	ADDQ	CX, DX
p1pcd:
	CMPQ	DX, AX
	JA	fail                    // never: ones of c bits is at most c
	ADDQ	DI, R10
	MOVQ	R12, CX
	SUBQ	R13, CX
	INCQ	CX
	CMPQ	CX, 40(SP)
	JLT	p1zero                  // a leaf pair
	MOVQ	AX, CX
	SUBQ	DX, CX
	MOVQ	CX, (R8)(R12*8)
	MOVQ	DX, 8(R8)(R12*8)
	JMP	p1adv
p1flat:
	// A flat root, or a covered node (c = 0).
	IMULQ	AX, BX
	LEAQ	7(BX), DI
	SHRQ	$3, DI
	MOVQ	16(SP), CX
	SUBQ	R10, CX
	CMPQ	DI, CX
	JA	fail
	ADDQ	DI, R10
p1zero:
	MOVQ	$0, (R8)(R12*8)
	MOVQ	$0, 8(R8)(R12*8)
p1adv:
	INCQ	R11
	ADDQ	$2, R12
	JMP	p1node
p1next:
	INCQ	32(SP)
	JMP	p1level
p1done:
	MOVQ	0(SP), AX
	MOVQ	104(AX), CX
	MOVQ	64(AX), BX
	MOVQ	8(BX)(CX*8), DX
	CMPQ	(R8)(DX*8), $0
	JNE	fail                    // symbols routed to an absent node

	// Pass 2.
	MOVQ	CX, 32(SP)
p2level:
	MOVQ	0(SP), AX
	MOVQ	32(SP), CX
	MOVQ	32(AX), DX
	MOVQ	40(AX), SI
	TESTQ	$1, CX
	JZ	p2even
	MOVQ	SI, 72(SP)              // odd depths in tmp
	MOVQ	DX, 80(SP)
	JMP	p2bufs
p2even:
	MOVQ	DX, 72(SP)              // even ones in out
	MOVQ	SI, 80(SP)
p2bufs:
	MOVQ	64(AX), BX
	MOVQ	(BX)(CX*8), R11
	MOVQ	R11, 56(SP)
	MOVQ	8(BX)(CX*8), R13
	MOVQ	72(AX), BX
	MOVQ	(BX)(CX*8), SI
	MOVQ	8(BX)(CX*8), DX
	SUBQ	SI, DX                  // leaves of depth d
	ADDQ	96(AX), SI              // their symbols
	MOVQ	R11, R12
	ADDQ	DX, R12
	XORL	R10, R10
p2leaf:
	CMPQ	R11, R12
	JGE	p2leafd
	MOVQ	(R8)(R11*8), AX
	TESTQ	AX, AX
	JZ	p2leafn
	LEAQ	(R10)(AX*1), DX
	CMPQ	DX, 48(SP)
	JA	fail                    // off+c > n
	MOVBLZX	(SI), CX
	MOVQ	CX, X0
	PXOR	X1, X1
	PSHUFB	X1, X0
	MOVQ	72(SP), DI
	MOVQ	DI, BX
	ADDQ	R10, DI
	ADDQ	DX, BX
p2fill:
	MOVOU	X0, (DI)
	MOVOU	X0, 16(DI)
	ADDQ	$32, DI
	CMPQ	DI, BX
	JB	p2fill
	MOVQ	DX, R10
p2leafn:
	INCQ	R11
	INCQ	SI
	JMP	p2leaf
p2leafd:
	MOVQ	0(SP), AX
	MOVQ	32(SP), CX
	CMPQ	CX, 104(AX)
	JEQ	p2nextlevel             // the deepest depth: leaves only
	MOVQ	56(AX), BX
	MOVQ	(BX)(CX*8), DX
	MOVQ	DX, 96(SP)              // rp = runs[d]
	MOVQ	72(AX), BX
	MOVQ	8(BX)(CX*8), DX
	MOVQ	16(BX)(CX*8), SI
	SUBQ	DX, SI
	MOVQ	SI, 40(SP)              // leaves of depth d+1
	ADDQ	96(AX), DX
	MOVQ	DX, 64(SP)              // their symbols
	MOVQ	R13, R12
	MOVQ	$0, 88(SP)
p2node:
	CMPQ	R11, R13
	JGE	p2nextlevel
	MOVQ	(R8)(R11*8), AX
	TESTQ	AX, AX
	JZ	p2adv                   // no symbol: none in its children either
	LEAQ	(R10)(AX*1), DX
	CMPQ	DX, 48(SP)
	JA	fail                    // off+c > n
	MOVBQZX	(R9)(R11*1), BX
	TESTQ	BX, BX
	JNZ	p2flat
	MOVQ	R12, CX
	SUBQ	R13, CX
	INCQ	CX
	CMPQ	CX, 40(SP)
	JLT	p2pair

	// A bitmap node: merge its children's sequences.
	MOVQ	R10, 104(SP)
	MOVQ	R11, 112(SP)
	MOVQ	R12, 120(SP)
	MOVQ	R13, 128(SP)
	MOVQ	(R8)(R12*8), DX
	MOVQ	80(SP), SI
	ADDQ	88(SP), SI              // left sequence
	LEAQ	(SI)(DX*1), BX          // right sequence
	MOVQ	80(SP), R11
	ADDQ	48(SP), R11
	ADDQ	$16, R11                // last 16-byte read start in the child level
	MOVQ	8(SP), R9
	ADDQ	96(SP), R9
	LEAQ	15(AX), CX
	SHRQ	$4, CX
	LEAQ	(R9)(CX*2), CX
	CMPQ	CX, 24(SP)
	JA	fail                    // control bytes past bodyCap
	MOVQ	72(SP), DI
	ADDQ	R10, DI
	LEAQ	·hufMergeTab(SB), R10
	MOVQ	$0x7070707070707070, CX
	MOVQ	CX, X6
	PUNPCKLQDQ	X6, X6
	MOVQ	$0x1010101010101010, CX
	MOVQ	CX, X7
	PUNPCKLQDQ	X7, X7
	MOVQ	BX, R8
mloop:
	CMPQ	SI, R11
	JA	fail
	CMPQ	R8, R11
	JA	fail
	MSTEP3
	SUBQ	$16, AX
	JG	mloop
	MOVQ	0(SP), BX
	MOVQ	48(BX), R8
	MOVQ	88(BX), R9
	MOVQ	104(SP), R10
	MOVQ	112(SP), R11
	MOVQ	120(SP), R12
	MOVQ	128(SP), R13
	MOVQ	(R8)(R11*8), AX
	LEAQ	7(AX), CX
	SHRQ	$3, CX
	ADDQ	CX, 96(SP)
	JMP	p2nodeend

p2pair:
	// A leaf pair: s1 where the bit is set, s0 elsewhere.
	MOVQ	64(SP), SI
	MOVQ	R12, CX
	SUBQ	R13, CX
	ADDQ	CX, SI
	MOVBLZX	(SI), CX
	MOVBLZX	1(SI), DX
	PXOR	X12, X12
	MOVQ	CX, X8
	PSHUFB	X12, X8
	XORL	CX, DX
	MOVQ	DX, X9
	PSHUFB	X12, X9
	MOVOU	·hufPairConst(SB), X10
	MOVOU	·hufPairConst+16(SB), X11
	MOVQ	8(SP), SI
	ADDQ	96(SP), SI
	LEAQ	15(AX), CX
	SHRQ	$4, CX
	LEAQ	(SI)(CX*2), CX
	CMPQ	CX, 24(SP)
	JA	fail                    // control bytes past bodyCap
	MOVQ	72(SP), DI
	ADDQ	R10, DI
ploop:
	MOVWLZX	(SI), CX
	MOVQ	CX, X0
	PSHUFB	X10, X0
	PAND	X11, X0
	PCMPEQB	X11, X0
	PAND	X9, X0
	PXOR	X8, X0
	MOVOU	X0, (DI)
	ADDQ	$16, DI
	ADDQ	$2, SI
	SUBQ	$16, AX
	JG	ploop
	MOVQ	(R8)(R11*8), AX
	LEAQ	7(AX), CX
	SHRQ	$3, CX
	ADDQ	CX, 96(SP)
	JMP	p2nodeend

p2flat:
	// A flat root of depth D (covered nodes have no symbol).
	CMPQ	BX, $6
	JA	fail                    // D = 7 or 8: the Go decoder
	MOVQ	0(SP), DI
	MOVQ	32(SP), CX
	MOVQ	72(DI), SI
	MOVQ	80(DI), DX
	LEAQ	(CX)(BX*1), AX
	MOVQ	(SI)(AX*8), SI
	SUBQ	(DX)(AX*8), SI
	MOVQ	(DX)(CX*8), AX
	ADDQ	R11, AX
	SUBQ	56(SP), AX
	MOVQ	BX, CX
	SHLQ	CX, AX
	ADDQ	AX, SI
	ADDQ	96(DI), SI              // its code -> symbol table (flatSyms)
	MOVOU	0(SI), X10
	MOVOU	16(SI), X11
	MOVOU	32(SI), X12
	MOVOU	48(SI), X13
	LEAQ	·hufFlat(SB), DX
	IMUL3Q	$96, BX, AX
	ADDQ	AX, DX
	MOVOU	0(DX), X4
	MOVOU	16(DX), X5
	MOVOU	64(DX), X6
	MOVOU	80(DX), X7
	MOVQ	$0x7070707070707070, CX
	MOVQ	CX, X8
	PUNPCKLQDQ	X8, X8
	MOVQ	$0x1010101010101010, CX
	MOVQ	CX, X9
	PUNPCKLQDQ	X9, X9
	LEAQ	(BX)(BX*1), CX          // 2D bytes a step
	MOVQ	8(SP), SI
	ADDQ	96(SP), SI
	MOVQ	(R8)(R11*8), AX
	LEAQ	15(AX), DX
	SHRQ	$4, DX
	DECQ	DX
	IMULQ	CX, DX
	ADDQ	SI, DX
	ADDQ	$16, DX
	CMPQ	DX, 24(SP)
	JA	fail                    // the last 16-byte read past bodyCap
	MOVQ	72(SP), DI
	ADDQ	R10, DI
	CMPQ	BX, $5
	JEQ	fl2
	JA	fl4
fl1:
	EXTRACT2
	MOVO	X10, X2
	PSHUFB	X1, X2
	MOVOU	X2, (DI)
	ADDQ	$16, DI
	ADDQ	CX, SI
	SUBQ	$16, AX
	JG	fl1
	JMP	fldone
fl2:
	EXTRACT2
	PXOR	X2, X2
	CHUNK(X10)
	CHUNK(X11)
	MOVOU	X2, (DI)
	ADDQ	$16, DI
	ADDQ	CX, SI
	SUBQ	$16, AX
	JG	fl2
	JMP	fldone
fl4:
	EXTRACT2
	PXOR	X2, X2
	CHUNK(X10)
	CHUNK(X11)
	CHUNK(X12)
	CHUNK(X13)
	MOVOU	X2, (DI)
	ADDQ	$16, DI
	ADDQ	CX, SI
	SUBQ	$16, AX
	JG	fl4
fldone:
	MOVQ	(R8)(R11*8), AX
	MOVBQZX	(R9)(R11*1), BX
	IMULQ	AX, BX
	ADDQ	$7, BX
	SHRQ	$3, BX
	ADDQ	BX, 96(SP)

p2nodeend:
	ADDQ	AX, R10                 // off += c
	MOVQ	(R8)(R12*8), CX
	ADDQ	8(R8)(R12*8), CX
	ADDQ	CX, 88(SP)              // coff += both children's counts
p2adv:
	INCQ	R11
	ADDQ	$2, R12
	JMP	p2node
p2nextlevel:
	DECQ	32(SP)
	JGE	p2level
	MOVQ	$0, ret+8(FP)
	RET
fail:
	MOVQ	$1, ret+8(FP)
	RET

// hufPairConst: the byte of control bits each output of a leaf-pair step
// takes (0 for outputs 0-7, 1 for 8-15), then the bit it tests.
DATA	·hufPairConst+0(SB)/8, $0x0000000000000000
DATA	·hufPairConst+8(SB)/8, $0x0101010101010101
DATA	·hufPairConst+16(SB)/8, $0x8040201008040201
DATA	·hufPairConst+24(SB)/8, $0x8040201008040201
GLOBL	·hufPairConst(SB), RODATA|NOPTR, $32
