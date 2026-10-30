//go:build !purego

#include "textflag.h"

// Huffman merge kernel for arm64, called through mergeFast
// (huffman_asm.go), which checks the invariants this code relies on; its
// comment gives the proof of the accesses.
//
// One step makes 16 outputs: V0 holds the next 16 left symbols, V1 the
// next 16 right ones, and one TBL over the 32-byte table {V0, V1} picks
// the outputs with the indices hufIdxA[b0] (outputs 0-7) and
// hufIdxB[p][b1] (outputs 8-15), p the number of 1 bits of b0. The left
// position then moves by 16 minus the number of 1 bits of b0 and b1, the
// right one by that number. mergeOnes (huffman.go) holds the bit counts.
//
// The loop makes four steps a round while k+64 <= n and l, r <= max-48:
// each step reads at most 16 bytes further on each side than the one
// before, so the one test covers the four. Rounds of two steps (k+32 <= n,
// l, r <= max-16), then single steps (k+16 <= n, l, r <= max) finish.
//
// Registers:
//   R0 dst   R1 n-16     R2 ch      R3 l       R4 r      R5 max
//   R6 run   R7 hufIdxA  R8 hufIdxB R16 mergeOnes        R9 k
//   R19 n-32  R20 max-16  R21 n-64  R22 max-48
//   R10-R15 R17 scratch; V0-V4

// MSTEP makes one step: 16 outputs at dst[k:], k += 16.
#define MSTEP \
	LSR	$3, R9, R10; \
	ADD	R6, R10; \
	MOVBU	(R10), R11; \
	MOVBU	1(R10), R12; \
	ADD	R2, R3, R13; \
	VLD1	(R13), [V0.B16]; \
	ADD	R2, R4, R13; \
	VLD1	(R13), [V1.B16]; \
	ADD	R11<<3, R7, R13; \
	FMOVD	(R13), F2; \
	MOVBU	(R16)(R11), R14; \
	ADD	R14<<11, R8, R13; \
	ADD	R12<<3, R13; \
	FMOVD	(R13), F3; \
	VMOV	V3.D[0], V2.D[1]; \
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16; \
	ADD	R0, R9, R13; \
	VST1	[V4.B16], (R13); \
	MOVBU	(R16)(R12), R15; \
	ADD	R14, R15; \
	ADD	R15, R4; \
	ADD	$16, R3; \
	SUB	R15, R3; \
	ADD	$16, R9

// func hufMergeAsm(dst *byte, n int, ch *byte, l, r, max int, run *byte) (k, lo, ro int)
TEXT ·hufMergeAsm(SB), NOSPLIT, $0-80
	MOVD	dst+0(FP), R0
	MOVD	n+8(FP), R1
	MOVD	ch+16(FP), R2
	MOVD	l+24(FP), R3
	MOVD	r+32(FP), R4
	MOVD	max+40(FP), R5
	MOVD	run+48(FP), R6
	MOVD	$·hufIdxA(SB), R7
	MOVD	$·hufIdxB(SB), R8
	MOVD	$·mergeOnes(SB), R16
	SUB	$16, R1
	SUB	$16, R1, R19
	SUB	$16, R5, R20
	SUB	$32, R1, R21
	SUB	$48, R5, R22
	MOVD	$0, R9
	CMP	$0, R20
	BLT	loop // fewer than 32 bytes in ch: single steps only
	CMP	$0, R22
	BLT	loop2 // fewer than 64 bytes in ch: no rounds of four

loop4:
	// k+64 <= n, l <= max-48, r <= max-48 (unsigned: l and r are >= 0).
	CMP	R21, R9
	BGT	loop2
	CMP	R22, R3
	BHI	loop2
	CMP	R22, R4
	BHI	loop2
	MSTEP
	MSTEP
	MSTEP
	MSTEP
	B	loop4

loop2:
	// k+32 <= n, l <= max-16, r <= max-16 (unsigned: l and r are >= 0).
	CMP	R19, R9
	BGT	loop
	CMP	R20, R3
	BHI	loop
	CMP	R20, R4
	BHI	loop
	MSTEP
	MSTEP
	B	loop2

loop:
	// k+16 <= n, l <= max, r <= max.
	CMP	R1, R9
	BGT	done
	CMP	R5, R3
	BHI	done
	CMP	R5, R4
	BHI	done
	MSTEP
	B	loop

done:
	MOVD	R9, k+56(FP)
	MOVD	R3, lo+64(FP)
	MOVD	R4, ro+72(FP)
	RET

// Flat-root kernel, called through flatFast (huffman_asm.go), which checks
// the invariants this code relies on; its comment gives the proof of the
// accesses. D is 2 to 6.
//
// One step decodes 16 codes from the 2D bytes at run[o:], o = 2D*k/16,
// loaded as 16 bytes in V0. Two TBL gather each code's 16-bit window
// (idxA, idxB of hufFlatConst), USHL shifts each window right by its own
// amount (shr, negative counts), UZP1 keeps the low byte of each lane, the
// mask keeps D bits, and a TBL over the 64-byte table maps codes to
// symbols. The Go assembler has no USHL: it is written as its encoding,
// ushl v1.8h, v1.8h, v22.8h = 0x6e764421, ushl v2.8h, v2.8h, v22.8h =
// 0x6e764442.
//
// Registers:
//   R0 dst   R1 n-16   R2 run   R3 runLen-16   R6 2D   R9 k   R10 o
//   V20-V23 idxA idxB shr mask   V24-V27 table   V0-V4 scratch

// func hufFlatAsm(dst *byte, n int, run *byte, runLen int, c *hufFlatConst, tbl *[64]byte, D int) (k int)
TEXT ·hufFlatAsm(SB), NOSPLIT, $0-64
	MOVD	dst+0(FP), R0
	MOVD	n+8(FP), R1
	MOVD	run+16(FP), R2
	MOVD	runLen+24(FP), R3
	MOVD	c+32(FP), R4
	MOVD	tbl+40(FP), R5
	MOVD	D+48(FP), R6
	VLD1	(R4), [V20.B16, V21.B16, V22.B16, V23.B16]
	VLD1	(R5), [V24.B16, V25.B16, V26.B16, V27.B16]
	SUB	$16, R1
	SUB	$16, R3
	LSL	$1, R6
	MOVD	$0, R9
	MOVD	$0, R10

floop:
	// k+16 <= n, o+16 <= runLen.
	CMP	R1, R9
	BGT	fdone
	CMP	R3, R10
	BGT	fdone

	ADD	R2, R10, R11
	VLD1	(R11), [V0.B16]
	VTBL	V20.B16, [V0.B16], V1.B16
	VTBL	V21.B16, [V0.B16], V2.B16
	WORD	$0x6e764421 // ushl v1.8h, v1.8h, v22.8h
	WORD	$0x6e764442 // ushl v2.8h, v2.8h, v22.8h
	VUZP1	V2.B16, V1.B16, V3.B16
	VAND	V23.B16, V3.B16, V3.B16
	VTBL	V3.B16, [V24.B16, V25.B16, V26.B16, V27.B16], V4.B16
	ADD	R0, R9, R11
	VST1	[V4.B16], (R11)
	ADD	$16, R9
	ADD	R6, R10
	B	floop

fdone:
	MOVD	R9, k+56(FP)
	RET

// Whole-section decoder, called through decodeFast (huffman_asm.go), which
// checks the invariants this code relies on; its comment gives the proof
// of the accesses. The two passes of hufDecoder.decode (huffman.go), with
// the kernels inline and no call per node; it returns 1, handing the
// section back to the Go decoder, on anything off its path: a malformed
// section, a flat root of depth 7 or 8, a test of the proof failing.
//
// Pass 1, in wire order: the symbol counts of the nodes, from their
// parents' popcounts (CNT over 64-bit words, the last one masked to the
// node's bits), and where the runs of each depth start. A count is never
// negative, nor ones above it; both are still tested, so that no slip in
// the counting can let a negative count through to the loops.
//
// Pass 2, bottom-up: per depth, the leaves, a run of their symbol stored
// 32 bytes at a time; then the internal nodes: a flat root with the
// flat-root step of hufFlatAsm, a leaf pair 16 symbols a step (each
// control bit spread to a byte, CMTST, a select of the two symbols), a
// bitmap node with the merge step of hufMergeAsm. A node's last step,
// which may be partial, writes a whole step, overwritten by the nodes
// after it or falling in the slack.
//
// Registers, pass 1:
//   R0 st   R1 body   R2 bodyLen   R3 body+bodyCap   R4 count   R5 runs
//   R6 base   R7 leafBase   R8 flat   R9 maxDepth   R12 p   R13 d
//   R14 b   R15 e = base[d+1]   R19 leaves of depth d+1   R20 i   R21 k
//   R22 c   R23 D   R24 run bytes   R25 run   R26 bits left   R10 ones
// Registers, pass 2:
//   R0 st   R1 body   R2 syms   R3 body+bodyCap   R4 count   R8 flat
//   R11 n   R12 buf   R13 child   R14 i   R15 e   R16 off   R17 rp
//   R20 k (first child of node i)   R21 coff   R22 leaves of depth d+1
//   R23 c, then symbols left; R24 R25 R26 R5-R7 R9 R10 R19 per node
// st.scratch: 112 d, 120 base[d], 128 &syms of depth d+1's leaves,
// 136-160 R17 R20 R21 R22 around a merge.

// MSTEP2 makes one merge step: 16 outputs at R24, from the 16 symbols at
// R26 (left) and R5 (right), control bits at R25; R7 is hufMergeTab.
#define MSTEP2 \
	MOVBU	(R25), R9; \
	MOVBU	1(R25), R10; \
	VLD1	(R26), [V0.B16]; \
	VLD1	(R5), [V1.B16]; \
	ADD	R9<<3, R7, R17; \
	FMOVD	(R17), F2; \
	ADD	$20480, R7, R19; \
	MOVBU	(R19)(R9), R20; \
	MOVBU	(R19)(R10), R21; \
	ADD	R20<<11, R7, R17; \
	ADD	R10<<3, R17; \
	FMOVD	2048(R17), F3; \
	VMOV	V3.D[0], V2.D[1]; \
	VTBL	V2.B16, [V0.B16, V1.B16], V4.B16; \
	VST1.P	[V4.B16], 16(R24); \
	ADD	R20, R21; \
	ADD	R21, R5; \
	ADD	$16, R26; \
	SUB	R21, R26; \
	ADD	$2, R25

// func hufDecodeAsm(st *hufState) int
TEXT ·hufDecodeAsm(SB), NOSPLIT, $0-16
	MOVD	st+0(FP), R0
	MOVD	0(R0), R1
	MOVD	8(R0), R2
	MOVD	16(R0), R3
	ADD	R1, R3
	MOVD	48(R0), R4
	MOVD	56(R0), R5
	MOVD	64(R0), R6
	MOVD	72(R0), R7
	MOVD	88(R0), R8
	MOVD	104(R0), R9

	// Pass 1.
	MOVD	24(R0), R10
	MOVD	R10, (R4)               // count[0] = n
	ADD	$1, R9, R11
	MOVD	(R6)(R11<<3), R11
	MOVD	ZR, (R4)(R11<<3)        // the slot after the last node
	MOVD	$0, R12
	MOVD	$0, R13
p1level:
	CMP	R9, R13
	BGE	p1done
	MOVD	R12, (R5)(R13<<3)       // runs[d] = p
	MOVD	(R6)(R13<<3), R14
	ADD	$1, R13, R11
	MOVD	(R6)(R11<<3), R15
	MOVD	(R7)(R13<<3), R17
	MOVD	(R7)(R11<<3), R16
	SUB	R17, R16, R17           // leaves of depth d
	ADD	$2, R13, R10
	MOVD	(R7)(R10<<3), R19
	SUB	R16, R19, R19           // leaves of depth d+1
	ADD	R17, R14, R20           // first internal node
	MOVD	R15, R21                // its first child
p1node:
	CMP	R15, R20
	BGE	p1next
	MOVD	(R4)(R20<<3), R22
	TBNZ	$63, R22, fail          // never: counts are c-ones, ones <= c
	MOVBU	(R8)(R20), R23
	CBNZ	R23, p1flat
	ADD	$7, R22, R24
	LSR	$3, R24
	SUB	R12, R2, R11
	CMP	R11, R24
	BHI	fail                    // the run past the section
	ADD	R1, R12, R25
	MOVD	R22, R26
	MOVD	$0, R10
p1pc:
	CMP	$64, R26
	BLO	p1pct
	MOVD.P	8(R25), R11
	FMOVD	R11, F0
	VCNT	V0.B8, V0.B8
	VUADDLV	V0.B8, V0
	FMOVD	F0, R11
	ADD	R11, R10
	SUB	$64, R26
	B	p1pc
p1pct:
	CBZ	R26, p1pcd
	ADD	$8, R25, R11
	CMP	R3, R11
	BHI	fail                    // the last word past bodyCap
	MOVD	(R25), R11
	MOVD	$1, R17
	LSL	R26, R17, R17
	SUB	$1, R17
	AND	R17, R11
	FMOVD	R11, F0
	VCNT	V0.B8, V0.B8
	VUADDLV	V0.B8, V0
	FMOVD	F0, R11
	ADD	R11, R10
p1pcd:
	CMP	R22, R10
	BHI	fail                    // never: ones of c bits is at most c
	ADD	R24, R12
	SUB	R15, R21, R11
	ADD	$1, R11
	ADD	$1, R21, R17
	CMP	R19, R11
	BLT	p1zero                  // a leaf pair
	SUB	R10, R22, R11
	MOVD	R11, (R4)(R21<<3)
	MOVD	R10, (R4)(R17<<3)
	B	p1adv
p1flat:
	// A flat root, or a covered node (c = 0).
	MUL	R23, R22, R24
	ADD	$7, R24
	LSR	$3, R24
	SUB	R12, R2, R11
	CMP	R11, R24
	BHI	fail
	ADD	R24, R12
	ADD	$1, R21, R17
p1zero:
	MOVD	ZR, (R4)(R21<<3)
	MOVD	ZR, (R4)(R17<<3)
p1adv:
	ADD	$1, R20
	ADD	$2, R21
	B	p1node
p1next:
	ADD	$1, R13
	B	p1level
p1done:
	ADD	$1, R9, R11
	MOVD	(R6)(R11<<3), R11
	MOVD	(R4)(R11<<3), R11
	CBNZ	R11, fail               // symbols routed to an absent node

	// Pass 2.
	MOVD	96(R0), R2
	MOVD	24(R0), R11
p2level:
	MOVD	R9, 112(R0)
	MOVD	32(R0), R12
	MOVD	40(R0), R13
	TST	$1, R9
	CSEL	NE, R13, R12, R10       // odd depths in tmp, even ones in out
	CSEL	NE, R12, R13, R13
	MOVD	R10, R12
	MOVD	64(R0), R6
	MOVD	(R6)(R9<<3), R14
	MOVD	R14, 120(R0)
	ADD	$1, R9, R10
	MOVD	(R6)(R10<<3), R15
	MOVD	72(R0), R7
	MOVD	(R7)(R9<<3), R19
	MOVD	(R7)(R10<<3), R23
	SUB	R19, R23, R5            // leaves of depth d
	ADD	R2, R19, R19            // their symbols
	MOVD	$0, R16
	ADD	R14, R5, R6
p2leaf:
	CMP	R6, R14
	BGE	p2leafd
	MOVD	(R4)(R14<<3), R23
	CBZ	R23, p2leafn
	ADD	R23, R16, R24
	CMP	R11, R24
	BHI	fail                    // off+c > n
	MOVBU	(R19), R10
	VDUP	R10, V0.B16
	ADD	R16, R12, R25
	ADD	R24, R12, R26
p2fill:
	FSTPQ	(F0, F0), (R25)
	ADD	$32, R25
	CMP	R26, R25
	BLO	p2fill
	MOVD	R24, R16
p2leafn:
	ADD	$1, R14
	ADD	$1, R19
	B	p2leaf
p2leafd:
	MOVD	104(R0), R10
	CMP	R10, R9
	BEQ	p2nextlevel             // the deepest depth: leaves only
	MOVD	56(R0), R10
	MOVD	(R10)(R9<<3), R17
	ADD	$1, R9, R10
	MOVD	(R7)(R10<<3), R24
	ADD	$2, R9, R10
	MOVD	(R7)(R10<<3), R22
	SUB	R24, R22, R22           // leaves of depth d+1
	ADD	R2, R24, R24
	MOVD	R24, 128(R0)            // their symbols
	MOVD	R15, R20
	MOVD	$0, R21
p2node:
	CMP	R15, R14
	BGE	p2nextlevel
	MOVD	(R4)(R14<<3), R23
	CBZ	R23, p2adv              // no symbol: none in its children either
	ADD	R23, R16, R24
	CMP	R11, R24
	BHI	fail                    // off+c > n
	MOVBU	(R8)(R14), R24
	CBNZ	R24, p2flat
	SUB	R15, R20, R10
	ADD	$1, R10
	CMP	R22, R10
	BLT	p2pair

	// A bitmap node: merge its children's sequences.
	MOVD	R17, 136(R0)
	MOVD	R20, 144(R0)
	MOVD	R21, 152(R0)
	MOVD	R22, 160(R0)
	MOVD	(R4)(R20<<3), R10
	ADD	R21, R13, R26           // left sequence
	ADD	R10, R26, R5            // right sequence
	ADD	R11, R13, R6
	ADD	$16, R6                 // last 16-byte read start in the child level
	ADD	R17, R1, R25
	ADD	$15, R23, R9
	LSR	$4, R9
	ADD	R9<<1, R25, R9
	CMP	R3, R9
	BHI	fail                    // control bytes past bodyCap
	ADD	R16, R12, R24
	MOVD	$·hufMergeTab(SB), R7
mloop:
	CMP	R6, R26
	BHI	fail
	CMP	R6, R5
	BHI	fail
	MSTEP2
	SUBS	$16, R23
	BGT	mloop
	MOVD	136(R0), R17
	MOVD	144(R0), R20
	MOVD	152(R0), R21
	MOVD	160(R0), R22
	MOVD	(R4)(R14<<3), R23
	ADD	$7, R23, R10
	LSR	$3, R10
	ADD	R10, R17
	B	p2nodeend

p2pair:
	// A leaf pair: s1 where the bit is set, s0 elsewhere.
	MOVD	128(R0), R10
	SUB	R15, R20, R9
	ADD	R9, R10
	MOVBU	(R10), R9
	MOVBU	1(R10), R10
	VDUP	R9, V18.B16
	EOR	R9, R10
	VDUP	R10, V19.B16
	MOVD	$·hufPairConst(SB), R9
	VLD1	(R9), [V16.B16, V17.B16]
	ADD	R17, R1, R25
	ADD	$15, R23, R9
	LSR	$4, R9
	ADD	R9<<1, R25, R9
	CMP	R3, R9
	BHI	fail                    // control bytes past bodyCap
	ADD	R16, R12, R24
ploop:
	MOVHU.P	2(R25), R9
	VMOV	R9, V5.H[0]
	VTBL	V16.B16, [V5.B16], V6.B16
	VCMTST	V17.B16, V6.B16, V6.B16
	VAND	V19.B16, V6.B16, V6.B16
	VEOR	V18.B16, V6.B16, V6.B16
	VST1.P	[V6.B16], 16(R24)
	SUBS	$16, R23
	BGT	ploop
	MOVD	(R4)(R14<<3), R23
	ADD	$7, R23, R10
	LSR	$3, R10
	ADD	R10, R17
	B	p2nodeend

p2flat:
	// A flat root of depth D (covered nodes have no symbol).
	CMP	$6, R24
	BHI	fail                    // D = 7 or 8: the Go decoder
	MOVD	112(R0), R9
	MOVD	72(R0), R7
	MOVD	80(R0), R6
	ADD	R24, R9, R10
	MOVD	(R7)(R10<<3), R5
	MOVD	(R6)(R10<<3), R26
	SUB	R26, R5, R5
	MOVD	(R6)(R9<<3), R26
	MOVD	120(R0), R10
	SUB	R10, R14, R10
	ADD	R10, R26
	LSL	R24, R26, R26
	ADD	R26, R5
	ADD	R2, R5                  // its code -> symbol table (flatSyms)
	VLD1	(R5), [V24.B16, V25.B16, V26.B16, V27.B16]
	MOVD	$·hufFlat(SB), R5
	MOVD	$96, R10
	MUL	R24, R10, R10
	ADD	R10, R5
	VLD1	(R5), [V20.B16, V21.B16, V22.B16, V23.B16]
	LSL	$1, R24, R26            // 2D bytes a step
	ADD	R17, R1, R25
	ADD	$15, R23, R9
	LSR	$4, R9
	SUB	$1, R9
	MUL	R26, R9, R9
	ADD	R25, R9
	ADD	$16, R9
	CMP	R3, R9
	BHI	fail                    // the last 16-byte read past bodyCap
	ADD	R16, R12, R10
floop2:
	VLD1	(R25), [V0.B16]
	ADD	R26, R25
	VTBL	V20.B16, [V0.B16], V1.B16
	VTBL	V21.B16, [V0.B16], V2.B16
	WORD	$0x6e764421 // ushl v1.8h, v1.8h, v22.8h
	WORD	$0x6e764442 // ushl v2.8h, v2.8h, v22.8h
	VUZP1	V2.B16, V1.B16, V3.B16
	VAND	V23.B16, V3.B16, V3.B16
	VTBL	V3.B16, [V24.B16, V25.B16, V26.B16, V27.B16], V4.B16
	VST1.P	[V4.B16], 16(R10)
	SUBS	$16, R23
	BGT	floop2
	MOVD	(R4)(R14<<3), R23
	MOVBU	(R8)(R14), R24
	MUL	R24, R23, R10
	ADD	$7, R10
	LSR	$3, R10
	ADD	R10, R17

p2nodeend:
	ADD	R23, R16                // off += c
	MOVD	(R4)(R20<<3), R10
	ADD	R10, R21
	ADD	$1, R20, R10
	MOVD	(R4)(R10<<3), R10
	ADD	R10, R21                // coff += both children's counts
p2adv:
	ADD	$1, R14
	ADD	$2, R20
	B	p2node
p2nextlevel:
	MOVD	112(R0), R9
	SUBS	$1, R9
	BGE	p2level
	MOVD	$0, R10
	MOVD	R10, ret+8(FP)
	RET
fail:
	MOVD	$1, R10
	MOVD	R10, ret+8(FP)
	RET

// hufPairConst: the byte of control bits each output of a leaf-pair step
// takes (0 for outputs 0-7, 1 for 8-15), then the bit it tests.
DATA	·hufPairConst+0(SB)/8, $0x0000000000000000
DATA	·hufPairConst+8(SB)/8, $0x0101010101010101
DATA	·hufPairConst+16(SB)/8, $0x8040201008040201
DATA	·hufPairConst+24(SB)/8, $0x8040201008040201
GLOBL	·hufPairConst(SB), RODATA|NOPTR, $32
