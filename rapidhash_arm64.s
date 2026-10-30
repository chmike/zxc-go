//go:build !purego

#include "textflag.h"

// Main loop of rapidhash for arm64, the same computation as rapidLoopGo in
// rapidhash.go. MUL and UMULH give the two halves of the 128-bit product
// with any registers, LDP loads two words at once, and the seven lanes and
// seven secrets all stay in registers.
//
// Registers: R0 read pointer, R1 bytes left, R2..R8 the lanes seed and
// see1..see6, R9..R15 the secrets, R19..R22 scratch.

// MIX sets acc = mix(read64(off)^sec, read64(off+8)^acc), where mix(a, b)
// is the xor of the two halves of the 128-bit product a*b.
#define MIX(off, sec, acc) \
	LDP	off(R0), (R19, R20); \
	EOR	sec, R19, R19; \
	EOR	acc, R20, R20; \
	MUL	R20, R19, R21; \
	UMULH	R20, R19, R22; \
	EOR	R22, R21, acc

// func rapidLoopAsm(p []byte, seed uint64) (h uint64, n int)
// Requires len(p) > 112.
TEXT ·rapidLoopAsm(SB), NOSPLIT, $0-48
	MOVD	p_base+0(FP), R0
	MOVD	p_len+8(FP), R1
	MOVD	seed+24(FP), R2
	MOVD	R2, R3
	MOVD	R2, R4
	MOVD	R2, R5
	MOVD	R2, R6
	MOVD	R2, R7
	MOVD	R2, R8

	// rapidSecret[0..6] of rapidhash.go.
	MOVD	$0x2d358dccaa6c78a5, R9
	MOVD	$0x8bb84b93962eacc9, R10
	MOVD	$0x4b33a62ed433d4a3, R11
	MOVD	$0x4d5a2da51de1aa47, R12
	MOVD	$0xa0761d6478bd642f, R13
	MOVD	$0xe7037ed1a0b428db, R14
	MOVD	$0x90ed1765281c388c, R15

loop:
	MIX(0, R9, R2)
	MIX(16, R10, R3)
	MIX(32, R11, R4)
	MIX(48, R12, R5)
	MIX(64, R13, R6)
	MIX(80, R14, R7)
	MIX(96, R15, R8)
	ADD	$112, R0
	SUB	$112, R1
	CMP	$112, R1
	BHI	loop

	// Fold the lanes, in the order of the C code.
	EOR	R3, R2, R2
	EOR	R5, R4, R4
	EOR	R7, R6, R6
	EOR	R8, R2, R2
	EOR	R6, R4, R4
	EOR	R4, R2, R2

	MOVD	R2, h+32(FP)
	MOVD	p_len+8(FP), R19
	SUB	R1, R19, R19
	MOVD	R19, n+40(FP)
	RET
