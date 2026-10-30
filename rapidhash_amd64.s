//go:build !purego

#include "textflag.h"

// Main loop of rapidhash for amd64 with BMI2, the same computation as
// rapidLoopGo in rapidhash.go. MULXQ takes its first factor in DX and
// writes both halves of the product to any two registers, so the seven
// lanes stay in registers: the compiler, with MULQ only, has to move
// operands through AX and DX and spills lanes to the stack.
//
// Registers: SI read pointer, CX bytes left, AX BX DI R8 R9 R10 R11 the
// lanes seed and see1..see6, DX and R12 scratch.

// MIX sets acc = mix(read64(off)^sec, read64(off+8)^acc), where mix(a, b)
// is the xor of the two halves of the 128-bit product a*b. The secret is an
// immediate: loading it from memory would add seven loads per step, enough
// to slow the loop down.
#define MIX(off, sec, acc) \
	MOVQ	$sec, DX; \
	XORQ	off(SI), DX; \
	MOVQ	off+8(SI), R12; \
	XORQ	acc, R12; \
	MULXQ	R12, acc, R12; \
	XORQ	R12, acc

// func rapidLoopAsm(p []byte, seed uint64) (h uint64, n int)
// Requires len(p) > 112 and BMI2 (haveRapidLoopAsm).
TEXT ·rapidLoopAsm(SB), NOSPLIT, $0-48
	MOVQ	p_base+0(FP), SI
	MOVQ	p_len+8(FP), CX
	MOVQ	seed+24(FP), AX
	MOVQ	AX, BX
	MOVQ	AX, DI
	MOVQ	AX, R8
	MOVQ	AX, R9
	MOVQ	AX, R10
	MOVQ	AX, R11

loop:
	// The secrets are rapidSecret[0..6] of rapidhash.go.
	MIX(0, 0x2d358dccaa6c78a5, AX)
	MIX(16, 0x8bb84b93962eacc9, BX)
	MIX(32, 0x4b33a62ed433d4a3, DI)
	MIX(48, 0x4d5a2da51de1aa47, R8)
	MIX(64, 0xa0761d6478bd642f, R9)
	MIX(80, 0xe7037ed1a0b428db, R10)
	MIX(96, 0x90ed1765281c388c, R11)
	ADDQ	$112, SI
	SUBQ	$112, CX
	CMPQ	CX, $112
	JHI	loop

	// Fold the lanes, in the order of the C code.
	XORQ	BX, AX
	XORQ	R8, DI
	XORQ	R10, R9
	XORQ	R11, AX
	XORQ	R9, DI
	XORQ	DI, AX

	MOVQ	AX, h+32(FP)
	MOVQ	p_len+8(FP), DX
	SUBQ	CX, DX
	MOVQ	DX, n+40(FP)
	RET

// func cpuid(leaf, sub uint32) (a, b, c, d uint32)
TEXT ·cpuid(SB), NOSPLIT, $0-24
	MOVL	leaf+0(FP), AX
	MOVL	sub+4(FP), CX
	CPUID
	MOVL	AX, a+8(FP)
	MOVL	BX, b+12(FP)
	MOVL	CX, c+16(FP)
	MOVL	DX, d+20(FP)
	RET
