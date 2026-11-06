//go:build !purego

#include "textflag.h"

// PAK parser of the encoder, levels 1 and 2: the loop of appendPAK with
// findBestMatch inline (compress_pak.go, compress_match.go), called through
// pakParseFast (compress_asm.go), whose comment gives the proof of the
// accesses. At these levels the hash covers 4 bytes, a head with another
// tag counts as no candidate, and there is neither lazy probe nor previous
// offset; the walk sees 4 candidates at most (searchDepth 3, tested before
// its decrement as in the C code). As the C code, it prefetches the table
// entries of the next position, the source ahead, and the gate of the next
// candidate of a chain; the next position's hash serves again after a miss.
//
// Registers:
//   R0 st   R1 src   R2 ip   R3 anchor   R4 iend   R5 limit
//   R6 head   R7 tags   R8 chain   R9 epochMark   R10 offsetMask
//   R11 next position after a miss   R12 its hash   R15 lits out
//   R16 seqs out
//   per position: R20 v (first 4 bytes at ip), R21 idx, R22 chain link,
//   R23 best length, R24 best ref (-1 none), R25 attempts left
//   scratch: R13 R14 R17 R19 R26

// func pakEncAsm(st *pakEncState)
TEXT ·pakEncAsm(SB), NOSPLIT, $0-8
	MOVD	st+0(FP), R0
	MOVD	0(R0), R1
	MOVD	8(R0), R2
	MOVD	R2, R3
	MOVD	16(R0), R4
	MOVD	24(R0), R5
	MOVD	32(R0), R6
	MOVD	40(R0), R7
	MOVD	48(R0), R8
	MOVD	56(R0), R9
	MOVD	64(R0), R10
	MOVD	104(R0), R15
	MOVD	112(R0), R16

loop:
	CMP	R5, R2
	BGE	done

	// Hash, tag, and the head of the bucket, replaced by ip.
	MOVD	(R1)(R2), R19
	MOVWU	R19, R20
	EOR	R19>>15, R19, R21
	MOVW	$0x2D35182D, R22
	MULW	R22, R21, R21
	LSRW	$17, R21, R21
hashed:
	// The step after a miss, 1 when ip + step reaches the limit: the next
	// position R11 (ip + 1 <= limit = iend - 8 keeps its 8-byte load in
	// src), its hash R12, and the prefetches.
	MOVD	88(R0), R19
	MOVD	96(R0), R26
	SUB	R3, R2, R13
	LSR	R26, R13, R13
	ADD	R13, R19, R19
	ADD	R2, R19, R11
	CMP	R5, R11
	BLT	stepped
	MOVD	$1, R19
	ADD	$1, R2, R11
stepped:
	ADD	R19<<2, R2, R13
	ADD	R1, R13
	PRFM	64(R13), PLDL1KEEP
	MOVD	(R1)(R11), R19
	EOR	R19>>15, R19, R12
	MOVW	$0x2D35182D, R22
	MULW	R22, R12, R12
	LSRW	$17, R12, R12
	ADD	R7, R12, R13
	PRFM	(R13), PLDL1KEEP
	ADD	R12<<2, R6, R13
	PRFM	(R13), PLDL1KEEP
	EORW	R20>>16, R20, R22
	ANDW	$0xFF, R22, R22
	MOVBU	(R7)(R21), R23
	MOVWU	(R6)(R21<<2), R24
	ORR	R9, R2, R25
	MOVW	R25, (R6)(R21<<2)
	MOVB	R22, (R7)(R21)
	ANDW	$0xFFFF, R2, R13
	CMPW	R22, R23
	BNE	nocand
	EORW	R9, R24, R21 // the position, if of this epoch
	CMPW	R10, R21
	BHI	nocand
	CBZW	R21, nocand
	SUBW	R21, R2, R26
	CMPW	$65536, R26
	CSELW	LO, R26, ZR, R26
	MOVH	R26, (R8)(R13<<1)

	// The chain walk.
	MOVD	$4, R23
	MOVD	$-1, R24
	MOVD	$3, R25
	ADD	R1, R2, R14 // &src[ip]

cand:
	SUBW	R21, R2, R26 // ip - idx, 32 bits
	CMPW	$65535, R26
	BHI	walked
	TBNZ	$63, R25, walked
	SUB	$1, R25
	ANDW	$0xFFFF, R21, R13
	MOVHU	(R8)(R13<<1), R22
	SUBW	R22, R21, R13
	ADD	R1, R13
	ADD	R23, R13
	SUB	$3, R13
	PRFM	(R13), PLDL1KEEP // the next candidate's gate
	MOVD	72(R0), R17 // minOffset
	CMP	R17, R26
	BLT	next
	ADD	R1, R21, R13 // &src[ref]
	SUB	$3, R23, R17
	MOVWU	(R13)(R17), R19
	MOVWU	(R14)(R17), R26
	CMPW	R19, R26
	BNE	next
	MOVWU	(R13), R19
	CMPW	R19, R20
	BNE	next

	// Match length from 4: 8 bytes a step while ip+n+8 <= iend, then
	// bytes.
	MOVD	$4, R17
mloop:
	ADD	R2, R17, R19
	ADD	$8, R19
	CMP	R4, R19
	BHI	mtail
	MOVD	(R14)(R17), R19
	MOVD	(R13)(R17), R26
	EOR	R19, R26, R19
	CBNZ	R19, mdiff
	ADD	$8, R17
	B	mloop
mdiff:
	RBIT	R19, R19
	CLZ	R19, R19
	ADD	R19>>3, R17, R17
	B	mdone
mtail:
	ADD	R2, R17, R19
	CMP	R4, R19
	BHS	mdone
	MOVBU	(R14)(R17), R19
	MOVBU	(R13)(R17), R26
	CMPW	R19, R26
	BNE	mdone
	ADD	$1, R17
	B	mtail
mdone:
	CMP	R23, R17
	BLE	nobetter
	MOVD	R17, R23
	MOVD	R21, R24
nobetter:
	MOVD	80(R0), R19 // sufficient
	CMP	R19, R23
	BGE	walked
	ADD	R2, R23, R19
	CMP	R4, R19
	BGE	walked

next:
	CBZW	R22, walked
	SUBW	R22, R21, R21
	CBNZW	R21, cand

walked:
	TBZ	$63, R24, hit

miss:
	// No match: the next position, its hash already computed.
	MOVD	R11, R2
	CMP	R5, R2
	BGE	done
	MOVWU	(R1)(R2), R20
	MOVW	R12, R21
	B	hashed

nocand:
	MOVH	ZR, (R8)(R13<<1)
	B	miss

hit:
	// Backtrack while ip > anchor, ref > 0 and the bytes before agree.
	CMP	R3, R2
	BLE	emit
	CBZ	R24, emit
	ADD	R1, R2, R13
	MOVBU	-1(R13), R19
	ADD	R1, R24, R14
	MOVBU	-1(R14), R26
	CMPW	R19, R26
	BNE	emit
	SUB	$1, R2
	SUB	$1, R24
	ADD	$1, R23
	B	hit

emit:
	// Literals src[anchor:ip] to the literal buffer, exactly: 16 bytes a
	// step, then the last 16, overlapping; below 16, two overlapping
	// halves, or for 1 to 3 bytes the first, middle and last.
	SUB	R3, R2, R13 // ll
	ADD	R1, R3, R17 // &src[anchor]
	ADD	R17, R13, R20 // &src[ip]
	ADD	R15, R13, R21 // literal buffer end
	CBZ	R13, copied
	CMP	$16, R13
	BLO	small
	SUB	$16, R20, R22
	MOVD	R15, R14
c16:
	CMP	R22, R17
	BHS	c16last
	LDP.P	16(R17), (R19, R26)
	STP.P	(R19, R26), 16(R14)
	B	c16
c16last:
	LDP	(R22), (R19, R26)
	STP	(R19, R26), -16(R21)
	B	copied
small:
	CMP	$8, R13
	BLO	small4
	MOVD	(R17), R19
	MOVD	-8(R20), R26
	MOVD	R19, (R15)
	MOVD	R26, -8(R21)
	B	copied
small4:
	CMP	$4, R13
	BLO	small1
	MOVWU	(R17), R19
	MOVWU	-4(R20), R26
	MOVW	R19, (R15)
	MOVW	R26, -4(R21)
	B	copied
small1:
	MOVBU	(R17), R19
	MOVB	R19, (R15)
	LSR	$1, R13, R22
	MOVBU	(R17)(R22), R19
	MOVB	R19, (R15)(R22)
	MOVBU	-1(R20), R19
	MOVB	R19, -1(R21)
copied:
	MOVD	R21, R15

	// The sequence word, and the extras of lengths of 255 or more.
	SUB	$5, R23, R14 // ml
	SUB	R24, R2, R17 // off
	SUB	$1, R17
	ANDW	$0xFFFF, R17, R17
	MOVD	$255, R19
	CMP	R19, R13
	CSEL	LO, R13, R19, R26
	ORRW	R26<<24, R17, R17
	CMP	R19, R14
	CSEL	LO, R14, R19, R26
	ORRW	R26<<16, R17, R17
	MOVW	R17, (R16)
	ADD	$4, R16
	CMP	R19, R13
	BHS	extras
	CMP	R19, R14
	BHS	extras
advance:
	ADD	R23, R2
	MOVD	R2, R3
	B	loop

extras:
	// Varints of ll-255 and ml-255 when not negative: 1 byte below 2^7, 2
	// below 2^14, else 3; the values stay below 2^21, the block size
	// limit.
	MOVD	120(R0), R17
	SUBS	$255, R13, R13
	BLT	extraML
	CMP	$128, R13
	BHS	ll2
	MOVB	R13, (R17)
	ADD	$1, R17
	B	extraML
ll2:
	CMP	$16384, R13
	BHS	ll3
	AND	$0x3F, R13, R19
	ORR	$0x80, R19
	MOVB	R19, (R17)
	LSR	$6, R13, R19
	MOVB	R19, 1(R17)
	ADD	$2, R17
	B	extraML
ll3:
	AND	$0x1F, R13, R19
	ORR	$0xC0, R19
	MOVB	R19, (R17)
	LSR	$5, R13, R19
	MOVB	R19, 1(R17)
	LSR	$13, R13, R19
	MOVB	R19, 2(R17)
	ADD	$3, R17
extraML:
	SUBS	$255, R14, R13
	BLT	extrasDone
	CMP	$128, R13
	BHS	ml2
	MOVB	R13, (R17)
	ADD	$1, R17
	B	extrasDone
ml2:
	CMP	$16384, R13
	BHS	ml3
	AND	$0x3F, R13, R19
	ORR	$0x80, R19
	MOVB	R19, (R17)
	LSR	$6, R13, R19
	MOVB	R19, 1(R17)
	ADD	$2, R17
	B	extrasDone
ml3:
	AND	$0x1F, R13, R19
	ORR	$0xC0, R19
	MOVB	R19, (R17)
	LSR	$5, R13, R19
	MOVB	R19, 1(R17)
	LSR	$13, R13, R19
	MOVB	R19, 2(R17)
	ADD	$3, R17
extrasDone:
	MOVD	R17, 120(R0)
	B	advance

done:
	MOVD	R15, 104(R0)
	MOVD	R16, 112(R0)
	MOVD	R3, 128(R0)
	RET

// SPL parser of the encoder, levels 3 to 5: the loop of lazyParse with
// findBestMatch and lazyProbe inline (compress_spl.go, compress_match.go),
// called through splParseFast (compress_asm.go), whose comment gives the
// proof of the accesses. The hash covers 5 bytes; a head with another tag
// is not tested but its chain is walked, one attempt less; a match shorter
// than lazyLen is dropped when the position after it (and from level 4 the
// one after that) has one 2 (3) bytes longer; from level 5 the position two
// bytes before a match end is inserted. As the C code, it prefetches the
// table entries of the next position and the gate of the next candidate of
// a chain.
//
// Registers: as pakEncAsm, R16 being the token output and R12 the hash
// multiplier (sufficient is read from st); the offsets, the largest offset
// and the backtracked ip during the probes live in st.
//   per position: R20 v, R21 idx, R22 chain link, R23 best length,
//   R24 best ref (-1 none), R25 attempts left, R17 skip-head flag
//   probes: R14 lp, R17 need, R20 val, R21 idx, R22 gate, R25 attempts,
//   R13 skip flag then compare offset
//   scratch: R13 R14 R17 R19 R26

// PROBE(lp_add, need_add, P) branches to P##yes when the position ip +
// lp_add has a match of best length + need_add bytes, else to P##no. It
// cannot paste label names, so the probe is written out twice below.

// func splEncAsm(st *encState)
TEXT ·splEncAsm(SB), NOSPLIT, $0-8
	MOVD	st+0(FP), R0
	MOVD	0(R0), R1
	MOVD	8(R0), R2
	MOVD	R2, R3
	MOVD	16(R0), R4
	MOVD	24(R0), R5
	MOVD	32(R0), R6
	MOVD	40(R0), R7
	MOVD	48(R0), R8
	MOVD	56(R0), R9
	MOVD	64(R0), R10
	MOVD	72(R0), R11
	MOVD	$0x2545F4914F6CDD1D, R12 // the hash multiplier
	MOVD	104(R0), R15
	MOVD	112(R0), R16
	MOVD	ZR, 144(R0)

sloop:
	CMP	R5, R2
	BGE	sdone

	// The prefetch of the next position's entries, ip + step or ip + 1
	// (<= limit = iend - 8, so its 8-byte load stays in src).
	MOVD	88(R0), R19
	MOVD	96(R0), R26
	SUB	R3, R2, R13
	LSR	R26, R13, R13
	ADD	R13, R19, R19
	ADD	R2, R19, R26
	CMP	R5, R26
	BLT	spf
	ADD	$1, R2, R26
spf:
	MOVD	(R1)(R26), R19
	AND	$0xFFFFFFFFFF, R19, R19
	MUL	R12, R19, R19
	LSR	$49, R19, R19
	ADD	R7, R19, R13
	PRFM	(R13), PLDL1KEEP
	ADD	R19<<2, R6, R13
	PRFM	(R13), PLDL1KEEP

	// Hash of 5 bytes, tag, and the head of the bucket, replaced by ip.
	MOVD	(R1)(R2), R19
	MOVWU	R19, R20
	AND	$0xFFFFFFFFFF, R19, R21
	MUL	R12, R21, R21
	LSR	$49, R21, R21
	EORW	R20>>16, R20, R22
	ANDW	$0xFF, R22, R22
	MOVBU	(R7)(R21), R23
	MOVWU	(R6)(R21<<2), R24
	ORR	R9, R2, R25
	MOVW	R25, (R6)(R21<<2)
	MOVB	R22, (R7)(R21)
	CMPW	R22, R23
	CSETW	NE, R17 // skip the head: another tag
	ANDW	$0xFFFF, R2, R13
	EORW	R9, R24, R21
	CMPW	R10, R21
	BHI	snocand
	CBZW	R21, snocand
	SUBW	R21, R2, R26
	CMPW	$65536, R26
	CSELW	LO, R26, ZR, R26
	MOVH	R26, (R8)(R13<<1)

	MOVD	$4, R23
	MOVD	$-1, R24
	MOVD	152(R0), R25
	ADD	R1, R2, R14
	CBZW	R17, sstart
	ANDW	$0xFFFF, R21, R13
	MOVHU	(R8)(R13<<1), R22
	SUB	$1, R25
	CBZW	R22, swalked
	SUBW	R22, R21, R21
	CBZW	R21, swalked
sstart:
	MOVD	$1, R17 // best length - 3, kept through the walk

	// A candidate that fails the gate, the common case, takes the one
	// branch back to scand; the rest of the test is out of line (sgate).
scand:
	SUBW	R21, R2, R26
	CMPW	$65535, R26
	BHI	swalked
	TBNZ	$63, R25, swalked
	SUB	$1, R25
	ANDW	$0xFFFF, R21, R13
	MOVHU	(R8)(R13<<1), R22
	SUBW	R22, R21, R13
	ADD	R1, R13
	ADD	R17, R13
	PRFM	(R13), PLDL1KEEP // the next candidate's gate
	CMP	R11, R26
	BLT	snext
	ADD	R1, R21, R13
	MOVWU	(R13)(R17), R19
	MOVWU	(R14)(R17), R26
	CMPW	R19, R26
	BEQ	sgate
snext:
	CBZW	R22, swalked
	SUBW	R22, R21, R21
	CBNZW	R21, scand

swalked:
	TBZ	$63, R24, shit

smiss:
	MOVD	88(R0), R19
	MOVD	96(R0), R26
	SUB	R3, R2, R13
	LSR	R26, R13, R13
	ADD	R13, R19, R19
	ADD	R2, R19, R26
	CMP	R5, R26
	BLT	sstepped
	MOVD	$1, R19
sstepped:
	ADD	R19, R2
	B	sloop

sgate:
	MOVWU	(R13), R19
	CMPW	R19, R20
	BNE	snext
	MOVD	$4, R17
smloop:
	ADD	R2, R17, R19
	ADD	$8, R19
	CMP	R4, R19
	BHI	smtail
	MOVD	(R14)(R17), R19
	MOVD	(R13)(R17), R26
	EOR	R19, R26, R19
	CBNZ	R19, smdiff
	ADD	$8, R17
	B	smloop
smdiff:
	RBIT	R19, R19
	CLZ	R19, R19
	ADD	R19>>3, R17, R17
	B	smdone
smtail:
	ADD	R2, R17, R19
	CMP	R4, R19
	BHS	smdone
	MOVBU	(R14)(R17), R19
	MOVBU	(R13)(R17), R26
	CMPW	R19, R26
	BNE	smdone
	ADD	$1, R17
	B	smtail
smdone:
	CMP	R23, R17
	BLE	snobetter
	MOVD	R17, R23
	MOVD	R21, R24
snobetter:
	SUB	$3, R23, R17
	MOVD	80(R0), R19 // sufficient
	CMP	R19, R23
	BGE	swalked
	ADD	R2, R23, R19
	CMP	R4, R19
	BGE	swalked
	B	snext

snocand:
	// No candidate: the chain link is 0, and the miss path follows here
	// rather than through a second branch.
	MOVH	ZR, (R8)(R13<<1)
	MOVD	88(R0), R19
	MOVD	96(R0), R26
	SUB	R3, R2, R13
	LSR	R26, R13, R13
	ADD	R13, R19, R19
	ADD	R2, R19, R26
	CMP	R5, R26
	BLT	snstepped
	MOVD	$1, R19
snstepped:
	ADD	R19, R2
	B	sloop

shit:
	// Backtrack into R13 (ip stays for the probes), R24 and R23.
	MOVD	R2, R13
sback:
	CMP	R3, R13
	BLE	sbacked
	CBZ	R24, sbacked
	ADD	R1, R13, R19
	MOVBU	-1(R19), R19
	ADD	R1, R24, R26
	MOVBU	-1(R26), R26
	CMPW	R19, R26
	BNE	sbacked
	SUB	$1, R13
	SUB	$1, R24
	ADD	$1, R23
	B	sback
sbacked:
	MOVD	R13, 184(R0)

	// Lazy: no probe for a match of lazyLen bytes or more, or at the end.
	MOVD	168(R0), R19
	CMP	R19, R23
	BGE	skeep
	ADD	$1, R2, R14
	CMP	R5, R14
	BGE	skeep

	// Probe 1: at ip+1, best length + 2 bytes. A candidate failing the
	// gate takes the one branch back to p1cand; the rest is out of line.
	ADD	$2, R23, R17
	SUB	R14, R4, R19
	CMP	R19, R17
	BGT	p1no
	SUB	$4, R17 // need - 4, kept through the probe
	MOVD	(R1)(R14), R19
	MOVWU	R19, R20
	AND	$0xFFFFFFFFFF, R19, R21
	MUL	R12, R21, R21
	LSR	$49, R21, R21
	ADD	R14, R17, R19
	MOVWU	(R1)(R19), R22
	MOVBU	(R7)(R21), R26
	EORW	R20>>16, R20, R19
	ANDW	$0xFF, R19, R19
	CMPW	R19, R26
	CSETW	NE, R13
	MOVWU	(R6)(R21<<2), R21
	EORW	R9, R21, R21
	CMPW	R10, R21
	BHI	p1no
	CBZW	R21, p1no
	MOVD	160(R0), R25
	CBZ	R25, p1no
p1cand:
	SUBW	R21, R14, R19
	CMPW	$65535, R19
	BHI	p1no
	CBNZW	R13, p1next
	CMP	R11, R19
	BLT	p1next
	ADD	R21, R17, R19
	MOVWU	(R1)(R19), R19
	CMPW	R19, R22
	BEQ	p1gate
p1next:
	MOVD	$0, R13
	ANDW	$0xFFFF, R21, R19
	MOVHU	(R8)(R19<<1), R19
	CBZW	R19, p1no
	SUBW	R19, R21, R21
	SUB	$1, R25
	CBZ	R25, p1no
	CBNZW	R21, p1cand
	B	p1no
p1gate:
	// First 4 bytes, then [4, need-4) by 8-byte words, the last one
	// ending at need; with need <= 8 the two 4-byte ends cover it all.
	MOVWU	(R1)(R21), R19
	CMPW	R19, R20
	BNE	p1next
	CMP	$4, R17
	BLE	smiss
	MOVD	$4, R13
p1ml:
	ADD	$4, R13, R19
	CMP	R17, R19
	BGT	p1mlast
	ADD	R14, R13, R19
	MOVD	(R1)(R19), R19
	ADD	R21, R13, R26
	MOVD	(R1)(R26), R26
	CMP	R19, R26
	BNE	p1next
	ADD	$8, R13
	B	p1ml
p1mlast:
	ADD	$4, R17, R19
	CMP	R19, R13
	BHS	smiss
	SUB	$4, R17, R13
	ADD	R14, R13, R19
	MOVD	(R1)(R19), R19
	ADD	R21, R13, R26
	MOVD	(R1)(R26), R26
	CMP	R19, R26
	BEQ	smiss
	B	p1next

p1no:
	// Probe 2, from level 4: at ip+2, best length + 3 bytes.
	MOVD	176(R0), R19
	CMP	$4, R19
	BLT	skeep
	ADD	$2, R2, R14
	CMP	R5, R14
	BGE	skeep
	ADD	$3, R23, R17
	SUB	R14, R4, R19
	CMP	R19, R17
	BGT	skeep
	SUB	$4, R17 // need - 4, kept through the probe
	MOVD	(R1)(R14), R19
	MOVWU	R19, R20
	AND	$0xFFFFFFFFFF, R19, R21
	MUL	R12, R21, R21
	LSR	$49, R21, R21
	ADD	R14, R17, R19
	MOVWU	(R1)(R19), R22
	MOVBU	(R7)(R21), R26
	EORW	R20>>16, R20, R19
	ANDW	$0xFF, R19, R19
	CMPW	R19, R26
	CSETW	NE, R13
	MOVWU	(R6)(R21<<2), R21
	EORW	R9, R21, R21
	CMPW	R10, R21
	BHI	skeep
	CBZW	R21, skeep
	MOVD	160(R0), R25
	CBZ	R25, skeep
p2cand:
	SUBW	R21, R14, R19
	CMPW	$65535, R19
	BHI	skeep
	CBNZW	R13, p2next
	CMP	R11, R19
	BLT	p2next
	ADD	R21, R17, R19
	MOVWU	(R1)(R19), R19
	CMPW	R19, R22
	BEQ	p2gate
p2next:
	MOVD	$0, R13
	ANDW	$0xFFFF, R21, R19
	MOVHU	(R8)(R19<<1), R19
	CBZW	R19, skeep
	SUBW	R19, R21, R21
	SUB	$1, R25
	CBZ	R25, skeep
	CBNZW	R21, p2cand
	B	skeep
p2gate:
	// First 4 bytes, then [4, need-4) by 8-byte words, the last one
	// ending at need; with need <= 8 the two 4-byte ends cover it all.
	MOVWU	(R1)(R21), R19
	CMPW	R19, R20
	BNE	p2next
	CMP	$4, R17
	BLE	smiss
	MOVD	$4, R13
p2ml:
	ADD	$4, R13, R19
	CMP	R17, R19
	BGT	p2mlast
	ADD	R14, R13, R19
	MOVD	(R1)(R19), R19
	ADD	R21, R13, R26
	MOVD	(R1)(R26), R26
	CMP	R19, R26
	BNE	p2next
	ADD	$8, R13
	B	p2ml
p2mlast:
	ADD	$4, R17, R19
	CMP	R19, R13
	BHS	smiss
	SUB	$4, R17, R13
	ADD	R14, R13, R19
	MOVD	(R1)(R19), R19
	ADD	R21, R13, R26
	MOVD	(R1)(R26), R26
	CMP	R19, R26
	BEQ	smiss
	B	p2next

skeep:
	// The match stands: ip becomes its backtracked start.
	MOVD	184(R0), R2

	// Literals, exactly as in pakEncAsm.
	SUB	R3, R2, R13
	ADD	R1, R3, R17
	ADD	R17, R13, R20
	ADD	R15, R13, R21
	CBZ	R13, scopied
	CMP	$16, R13
	BLO	ssmall
	SUB	$16, R20, R22
	MOVD	R15, R14
sc16:
	CMP	R22, R17
	BHS	sc16last
	LDP.P	16(R17), (R19, R26)
	STP.P	(R19, R26), 16(R14)
	B	sc16
sc16last:
	LDP	(R22), (R19, R26)
	STP	(R19, R26), -16(R21)
	B	scopied
ssmall:
	CMP	$8, R13
	BLO	ssmall4
	MOVD	(R17), R19
	MOVD	-8(R20), R26
	MOVD	R19, (R15)
	MOVD	R26, -8(R21)
	B	scopied
ssmall4:
	CMP	$4, R13
	BLO	ssmall1
	MOVWU	(R17), R19
	MOVWU	-4(R20), R26
	MOVW	R19, (R15)
	MOVW	R26, -4(R21)
	B	scopied
ssmall1:
	MOVBU	(R17), R19
	MOVB	R19, (R15)
	LSR	$1, R13, R22
	MOVBU	(R17)(R22), R19
	MOVB	R19, (R15)(R22)
	MOVBU	-1(R20), R19
	MOVB	R19, -1(R21)
scopied:
	MOVD	R21, R15

	// Token, offset, largest offset, extras of lengths of 15 or more.
	SUB	$5, R23, R14 // ml
	SUB	R24, R2, R17
	SUB	$1, R17 // off - 1
	MOVD	$15, R19
	CMP	R19, R13
	CSEL	LO, R13, R19, R26
	CMP	R19, R14
	CSEL	LO, R14, R19, R22
	ORR	R26<<4, R22, R22
	MOVB	R22, (R16)
	ADD	$1, R16
	MOVD	136(R0), R26
	MOVH	R17, (R26)
	ADD	$2, R26
	MOVD	R26, 136(R0)
	MOVD	144(R0), R26
	CMP	R26, R17
	BLS	smaxed
	MOVD	R17, 144(R0)
smaxed:
	CMP	R19, R13
	BHS	sextras
	CMP	R19, R14
	BHS	sextras
sinsert:
	// From level 5: position end - 2 into the tables, end = ip + len,
	// when end < iend - 7.
	MOVD	176(R0), R19
	CMP	$5, R19
	BLT	sadvance
	ADD	R2, R23, R19
	SUB	$7, R4, R26
	CMP	R26, R19
	BGE	sadvance
	SUB	$2, R19
	MOVD	(R1)(R19), R26
	MOVWU	R26, R20
	EORW	R20>>16, R20, R22
	ANDW	$0xFF, R22, R22
	AND	$0xFFFFFFFFFF, R26, R21
	MUL	R12, R21, R21
	LSR	$49, R21, R21
	MOVWU	(R6)(R21<<2), R14
	EORW	R9, R14, R14
	CMPW	R10, R14
	CSELW	HI, ZR, R14, R14
	ORR	R9, R19, R26
	MOVW	R26, (R6)(R21<<2)
	MOVB	R22, (R7)(R21)
	SUBW	R14, R19, R26
	CMPW	$65536, R26
	CSELW	LO, R26, ZR, R26
	CMPW	$0, R14
	CSELW	EQ, ZR, R26, R26
	ANDW	$0xFFFF, R19, R14
	MOVH	R26, (R8)(R14<<1)
sadvance:
	ADD	R23, R2
	MOVD	R2, R3
	B	sloop

sextras:
	MOVD	120(R0), R17
	SUBS	$15, R13, R13
	BLT	sxml
	CMP	$128, R13
	BHS	sxll2
	MOVB	R13, (R17)
	ADD	$1, R17
	B	sxml
sxll2:
	CMP	$16384, R13
	BHS	sxll3
	AND	$0x3F, R13, R19
	ORR	$0x80, R19
	MOVB	R19, (R17)
	LSR	$6, R13, R19
	MOVB	R19, 1(R17)
	ADD	$2, R17
	B	sxml
sxll3:
	AND	$0x1F, R13, R19
	ORR	$0xC0, R19
	MOVB	R19, (R17)
	LSR	$5, R13, R19
	MOVB	R19, 1(R17)
	LSR	$13, R13, R19
	MOVB	R19, 2(R17)
	ADD	$3, R17
sxml:
	SUBS	$15, R14, R13
	BLT	sxdone
	CMP	$128, R13
	BHS	sxml2
	MOVB	R13, (R17)
	ADD	$1, R17
	B	sxdone
sxml2:
	CMP	$16384, R13
	BHS	sxml3
	AND	$0x3F, R13, R19
	ORR	$0x80, R19
	MOVB	R19, (R17)
	LSR	$6, R13, R19
	MOVB	R19, 1(R17)
	ADD	$2, R17
	B	sxdone
sxml3:
	AND	$0x1F, R13, R19
	ORR	$0xC0, R19
	MOVB	R19, (R17)
	LSR	$5, R13, R19
	MOVB	R19, 1(R17)
	LSR	$13, R13, R19
	MOVB	R19, 2(R17)
	ADD	$3, R17
sxdone:
	MOVD	R17, 120(R0)
	B	sinsert

sdone:
	MOVD	R15, 104(R0)
	MOVD	R16, 112(R0)
	MOVD	R3, 128(R0)
	RET

// Match splitting of the SPL encoder: splitAnalyze, then the marking and
// expansion passes of splitMatches (compress_spl.go), called through
// splitFast (compress_asm.go), whose comment gives the proof of the
// accesses. The limit is at most 33, so a split match has 2 pieces.
//
// Registers: R0 st   R1 toks   R2 offs   R3 extras   R4 side   R5 hist
//   R6 bad   R7 n   R8 limit   R9 i   R10 h, then r   R11 hmask, then w
//   R12 escapes, then extra   R13-R17 R19-R23 scratch

// func splitAsm(st *splitState)
TEXT ·splitAsm(SB), NOSPLIT, $0-8
	MOVD	st+0(FP), R0
	MOVD	0(R0), R1
	MOVD	8(R0), R2
	MOVD	16(R0), R3
	MOVD	24(R0), R4
	MOVD	32(R0), R5
	MOVD	40(R0), R6
	MOVD	48(R0), R7
	MOVD	56(R0), R8
	MOVD	ZR, 72(R0)

	// order: 8, less while n >> order < 16, 2 at least.
	MOVD	$8, R13
xorder:
	CMP	$2, R13
	BLE	xordered
	LSR	R13, R7, R14
	CMP	$16, R14
	BHS	xordered
	SUB	$1, R13
	B	xorder
xordered:
	MOVD	$1, R11
	LSL	R13, R11, R11
	SUB	$1, R11 // hmask

	// Contexts and histogram (hist is zeroed by the Go caller).
	MOVD	$0, R9
	MOVD	$0, R10
	MOVD	$0, R12
xhist:
	CMP	R7, R9
	BHS	xhisted
	MOVBU	(R1)(R9), R14
	AND	$15, R14
	CMP	$15, R14
	CSET	EQ, R15 // esc
	MOVB	R10, (R4)(R9)
	ADD	R15<<8, R10, R16
	MOVWU	(R5)(R16<<2), R17
	ADD	$1, R17
	MOVW	R17, (R5)(R16<<2)
	ORR	R10<<1, R15, R10
	AND	R11, R10
	ADD	R15, R12
	ADD	$1, R9
	B	xhist
xhisted:

	// bad contexts, mispredictions, escapes in bad contexts.
	MOVD	$0, R9
	MOVD	$0, R13 // errors
	MOVD	$0, R14 // bad escapes
xbad:
	CMP	R11, R9
	BHI	xbaded
	MOVWU	(R5)(R9<<2), R15 // n0
	ADD	$256, R9, R16
	MOVWU	(R5)(R16<<2), R16 // n1
	CMP	R15, R16
	CSET	LO, R17
	MOVB	R17, (R6)(R9)
	CSEL	LO, R16, ZR, R19
	ADD	R19, R14
	CSEL	LO, R16, R15, R19 // min(n0, n1)
	ADD	R19, R13
	ADD	$1, R9
	B	xbad
xbaded:
	CBZ	R14, xnone
	MOVD	$100, R15
	MUL	R15, R13, R13
	MOVD	$80, R15
	MUL	R15, R12, R12
	CMP	R12, R13
	BLO	xnone

	// Pass 1: mark the matches to split, side[i] = their length code,
	// dropping their varints; the other varints move down.
	MOVD	$0, R9
	MOVD	$0, R10 // r
	MOVD	$0, R11 // w
	MOVD	$0, R12 // extra
xmark:
	CMP	R7, R9
	BHS	xmarked
	MOVBU	(R1)(R9), R14 // t
	MOVBU	(R4)(R9), R15
	MOVBU	(R6)(R15), R15 // isBad
	MOVB	ZR, (R4)(R9)
	LSR	$4, R14, R16
	CMP	$15, R16
	BNE	xnoll
	// Keep the literal-length varint.
	MOVBU	(R3)(R10), R16
	MOVD	$1, R17
	CMP	$0x80, R16
	CINC	HS, R17, R17
	CMP	$0xC0, R16
	CINC	HS, R17, R17
	CMP	R10, R11
	BEQ	xllkept
	MOVD	$0, R19
xllmove:
	ADD	R10, R19, R20
	MOVBU	(R3)(R20), R21
	ADD	R11, R19, R20
	MOVB	R21, (R3)(R20)
	ADD	$1, R19
	CMP	R17, R19
	BLO	xllmove
xllkept:
	ADD	R17, R10
	ADD	R17, R11
xnoll:
	AND	$15, R14, R16
	CMP	$15, R16
	BNE	xnext
	// The match-length varint: its value v, code = v + 15.
	MOVBU	(R3)(R10), R16
	MOVD	$1, R17
	CMP	$0x80, R16
	BLO	xv1
	ADD	$1, R10, R20
	MOVBU	(R3)(R20), R21
	CMP	$0xC0, R16
	BHS	xv3
	AND	$0x3F, R16, R19
	ORR	R21<<6, R19, R19
	MOVD	$2, R17
	B	xvd
xv3:
	AND	$0x1F, R16, R19
	ORR	R21<<5, R19, R19
	ADD	$2, R10, R20
	MOVBU	(R3)(R20), R21
	ORR	R21<<13, R19, R19
	MOVD	$3, R17
	B	xvd
xv1:
	MOVD	R16, R19
xvd:
	ADD	$15, R19 // code
	CBZ	R15, xkeepml
	CMP	R8, R19
	BHI	xkeepml
	MOVB	R19, (R4)(R9)
	ADD	$1, R12
	ADD	R17, R10
	B	xnext
xkeepml:
	CMP	R10, R11
	BEQ	xmlkept
	MOVD	$0, R19
xmlmove:
	ADD	R10, R19, R20
	MOVBU	(R3)(R20), R21
	ADD	R11, R19, R20
	MOVB	R21, (R3)(R20)
	ADD	$1, R19
	CMP	R17, R19
	BLO	xmlmove
xmlkept:
	ADD	R17, R10
	ADD	R17, R11
xnext:
	ADD	$1, R9
	B	xmark
xmarked:
	MOVD	R11, 64(R0)
	MOVD	$1, R13
	MOVD	R13, 72(R0)
	CBZ	R12, xdone

	// Pass 2: expand backward; a marked sequence of code c becomes
	// (ll, min(c-5, 14)) and (0, c - piece - 5) at the same offset.
	ADD	R7, R12, R13 // out
	MOVD	R13, 48(R0)
	MOVD	R7, R9
xexp:
	CBZ	R9, xdone
	SUB	$1, R9
	MOVBU	(R1)(R9), R14
	MOVHU	(R2)(R9<<1), R15
	MOVBU	(R4)(R9), R16
	CBNZ	R16, xpieces
	SUB	$1, R13
	MOVB	R14, (R1)(R13)
	MOVH	R15, (R2)(R13<<1)
	B	xexp
xpieces:
	SUB	$2, R13
	AND	$0xF0, R14, R17 // literal-length bits
	SUB	$5, R16, R19
	MOVD	$14, R20
	CMP	R20, R19
	CSEL	LO, R19, R20, R19 // piece
	ORR	R19, R17, R17
	MOVB	R17, (R1)(R13)
	MOVH	R15, (R2)(R13<<1)
	SUB	R19, R16, R16
	SUB	$5, R16 // the rest's code
	ADD	$1, R13, R20
	MOVB	R16, (R1)(R20)
	MOVH	R15, (R2)(R20<<1)
	B	xexp

xnone:
	MOVD	ZR, 72(R0) // no split: n and nx stay
xdone:
	RET

// RLE literal section: rleSize, and appendRLE when out is not nil
// (compress_spl.go), called through rleFast (compress_asm.go), whose
// comment gives the proof of the accesses. A run of rleMinRun equal bytes
// or more becomes (0x80 | c-4, b) pairs of c <= 131 bytes, its last 1 to 3
// bytes a copy; other bytes are copies of up to 128 bytes behind a c-1
// header. The search for the end of a copy tests 16 positions a step with
// NEON: lanes j where bytes j, j+1, j+2 and j+3 agree.
//
// Registers: R0 st   R1 lits   R2 n   R3 i   R4 out (0: size only)
//   R6 size   R7 start   R8 b   R9-R17 R19-R26 scratch   V0-V5

// func rleAsm(st *rleState)
TEXT ·rleAsm(SB), NOSPLIT, $0-8
	MOVD	st+0(FP), R0
	MOVD	0(R0), R1
	MOVD	8(R0), R2
	MOVD	16(R0), R4
	MOVD	$0, R3
	MOVD	$0, R6
	MOVD	$0x0101010101010101, R22
	MOVD	$131, R23

rtop:
	CMP	R2, R3
	BHS	rdone
	MOVD	R3, R7
	MOVBU	(R1)(R3), R8
	ADD	$1, R3

	// The run of b: 8 bytes a step, then bytes.
	MUL	R22, R8, R9
rrun8:
	ADD	$8, R3, R10
	CMP	R2, R10
	BHI	rrun1
	MOVD	(R1)(R3), R11
	EOR	R9, R11, R11
	CBNZ	R11, rrunx
	MOVD	R10, R3
	B	rrun8
rrunx:
	RBIT	R11, R11
	CLZ	R11, R11
	ADD	R11>>3, R3, R3
	B	rrunend
rrun1:
	CMP	R2, R3
	BHS	rrunend
	MOVBU	(R1)(R3), R11
	CMP	R8, R11
	BNE	rrunend
	ADD	$1, R3
	B	rrun1
rrunend:
	SUB	R7, R3, R10 // run
	CMP	$4, R10
	BLO	rcopy

	// A run: q full pairs, then the rest.
	UDIV	R23, R10, R11 // q
	MSUB	R23, R10, R11, R12 // rem = run - 131 q
	ADD	R11<<1, R6, R6
	CMP	$4, R12
	BLO	rrem
	ADD	$2, R6
	B	rrunw
rrem:
	ADD	R12, R6
	CBZ	R12, rrunw
	ADD	$1, R6
rrunw:
	CBZ	R4, rtop
	MOVD	$0xFF, R13 // 0x80 | (131 - 4)
rfull:
	CBZ	R11, rlast
	MOVB	R13, (R4)
	MOVB	R8, 1(R4)
	ADD	$2, R4
	SUB	$1, R11
	B	rfull
rlast:
	CBZ	R12, rtop
	CMP	$4, R12
	BLO	rlastcopy
	SUB	$4, R12, R13
	ORR	$0x80, R13
	MOVB	R13, (R4)
	MOVB	R8, 1(R4)
	ADD	$2, R4
	B	rtop
rlastcopy:
	// 1 to 3 bytes, all equal to b.
	SUB	$1, R12, R13
	MOVB	R13, (R4)
	ADD	$1, R4
rlastb:
	MOVB	R8, (R4)
	ADD	$1, R4
	SUB	$1, R12
	CBNZ	R12, rlastb
	B	rtop

rcopy:
	// The copy reaching i ends at the next 4 equal bytes, or at n.
rce16:
	ADD	$19, R3, R10
	CMP	R2, R10
	BHI	rce1
	ADD	R1, R3, R10
	VLD1	(R10), [V0.B16]
	ADD	$1, R10, R11
	VLD1	(R11), [V1.B16]
	ADD	$1, R11
	VLD1	(R11), [V2.B16]
	ADD	$1, R11
	VLD1	(R11), [V3.B16]
	VCMEQ	V0.B16, V1.B16, V4.B16
	VCMEQ	V1.B16, V2.B16, V5.B16
	VAND	V5.B16, V4.B16, V4.B16
	VCMEQ	V2.B16, V3.B16, V5.B16
	VAND	V5.B16, V4.B16, V4.B16
	VMOV	V4.D[0], R11
	VMOV	V4.D[1], R12
	CBNZ	R11, rcelo
	CBNZ	R12, rcehi
	ADD	$16, R3
	B	rce16
rcelo:
	RBIT	R11, R11
	CLZ	R11, R11
	ADD	R11>>3, R3, R3
	B	rcend
rcehi:
	RBIT	R12, R12
	CLZ	R12, R12
	ADD	R12>>3, R3, R3
	ADD	$8, R3
	B	rcend
rce1:
	CMP	R2, R3
	BHS	rcend
	ADD	$3, R3, R10
	CMP	R2, R10
	BHS	rce1next
	ADD	R1, R3, R10
	MOVBU	(R10), R11
	MOVBU	1(R10), R12
	CMP	R11, R12
	BNE	rce1next
	MOVBU	2(R10), R12
	CMP	R11, R12
	BNE	rce1next
	MOVBU	3(R10), R12
	CMP	R11, R12
	BEQ	rcend
rce1next:
	ADD	$1, R3
	B	rce1
rcend:
	SUB	R7, R3, R10 // run
	ADD	R10, R6
	ADD	$127, R10, R11
	ADD	R11>>7, R6, R6
	CBZ	R4, rtop

	// Write: pieces of up to 128 bytes, each behind its c-1 header.
	ADD	R1, R7, R14 // source
rpiece:
	ADD	R1, R3, R15
	SUB	R14, R15, R10 // left
	CBZ	R10, rtop
	MOVD	$128, R11
	CMP	R11, R10
	CSEL	LO, R10, R11, R10 // c
	SUB	$1, R10, R11
	MOVB	R11, (R4)
	ADD	$1, R4
	ADD	R14, R10, R16 // source end of the piece
	ADD	R4, R10, R17 // destination end
	CMP	$16, R10
	BLO	rpsmall
	SUB	$16, R16, R19
	MOVD	R4, R20
	MOVD	R14, R21
rp16:
	CMP	R19, R21
	BHS	rp16last
	LDP.P	16(R21), (R24, R25)
	STP.P	(R24, R25), 16(R20)
	B	rp16
rp16last:
	LDP	(R19), (R24, R25)
	STP	(R24, R25), -16(R17)
	B	rpdone
rpsmall:
	CMP	$8, R10
	BLO	rpsmall4
	MOVD	(R14), R24
	MOVD	-8(R16), R25
	MOVD	R24, (R4)
	MOVD	R25, -8(R17)
	B	rpdone
rpsmall4:
	CMP	$4, R10
	BLO	rpsmall1
	MOVWU	(R14), R24
	MOVWU	-4(R16), R25
	MOVW	R24, (R4)
	MOVW	R25, -4(R17)
	B	rpdone
rpsmall1:
	MOVBU	(R14), R24
	MOVB	R24, (R4)
	LSR	$1, R10, R25
	MOVBU	(R14)(R25), R24
	MOVB	R24, (R4)(R25)
	MOVBU	-1(R16), R24
	MOVB	R24, -1(R17)
rpdone:
	MOVD	R16, R14
	MOVD	R17, R4
	B	rpiece

rdone:
	MOVD	R6, 24(R0)
	MOVD	R4, 16(R0)
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
//   R0 st   R1 src   R2 ip   R3 litCost   R4 iend   R5 limit
//   R6 head   R7 tags   R8 chain   R9 epochMark   R10 offsetMask
//   R11 parentLen   R12 hash multiplier   R15 dp   R16 parentOff
//   search: R20 v, R21 idx, R22 skip flag then chain link, R23 best
//   length, R24 best ref (-1 none), R25 attempts, R13 &src[ref],
//   R14 &src[ip], R17 best length - 3, or the length being measured
//   relaxation: R13 L, R17 lMax+1, R19 offset-1, R20 dp[ip], R21 range
//   end, R14 range bound, R26 cost
//   scratch: R19 R22 R25 R26
//   in st: skipUntil, lastOff, prevP, prevLen, depth, sufficient

// func optEncAsm(st *optState)
TEXT ·optEncAsm(SB), NOSPLIT, $0-8
	MOVD	st+0(FP), R0
	MOVD	0(R0), R1
	MOVD	8(R0), R2
	MOVD	16(R0), R4
	MOVD	24(R0), R5
	MOVD	32(R0), R6
	MOVD	40(R0), R7
	MOVD	48(R0), R8
	MOVD	56(R0), R9
	MOVD	64(R0), R10
	MOVD	72(R0), R15
	SUB	R2<<2, R15
	MOVD	80(R0), R11
	SUB	R2<<1, R11
	MOVD	88(R0), R16
	SUB	R2<<1, R16
	MOVD	96(R0), R3
	MOVD	$0x2545F4914F6CDD1D, R12
	MOVD	ZR, 120(R0)
	MOVD	ZR, 128(R0)
	MOVD	ZR, 136(R0)
	MOVD	ZR, 144(R0)

oloop:
	CMP	R5, R2
	BGE	otail
	MOVWU	(R15)(R2<<2), R19
	CMNW	$1, R19
	BEQ	onext
	// The literal: dp[ip+1] = dp[ip] + litCost when lower.
	ADD	$1, R2, R13
	ADDW	R3, R19, R26
	MOVWU	(R15)(R13<<2), R14
	CMPW	R14, R26
	BHS	olit
	MOVW	R26, (R15)(R13<<2)
	MOVH	ZR, (R11)(R13<<1)
olit:
	MOVD	120(R0), R13
	CMP	R13, R2
	BLT	onext

	// Hash of 5 bytes, tag, head; the head and its chain link.
	MOVD	(R1)(R2), R19
	MOVWU	R19, R20
	AND	$0xFFFFFFFFFF, R19, R21
	MUL	R12, R21, R21
	LSR	$49, R21, R21
	EORW	R20>>16, R20, R22
	ANDW	$0xFF, R22, R22
	MOVBU	(R7)(R21), R23
	MOVWU	(R6)(R21<<2), R24
	ORR	R9, R2, R25
	MOVW	R25, (R6)(R21<<2)
	MOVB	R22, (R7)(R21)
	CMPW	R22, R23
	CSETW	NE, R22 // skip the head: another tag
	ANDW	$0xFFFF, R2, R13
	EORW	R9, R24, R21
	CMPW	R10, R21
	CSELW	HI, ZR, R21, R21 // idx, 0 when of another epoch
	SUBW	R21, R2, R26
	CMPW	$65536, R26
	CSELW	LO, R26, ZR, R26
	CMPW	$0, R21
	CSELW	EQ, ZR, R26, R26
	MOVH	R26, (R8)(R13<<1)

	MOVD	$4, R23
	MOVD	$-1, R24
	MOVD	104(R0), R25
	ADD	R1, R2, R14

	// The previous offset, when 0 < lastOff <= 65535 and <= ip.
	MOVD	128(R0), R19
	CBZ	R19, orepdone
	CMP	$65535, R19
	BHI	orepdone
	CMP	R2, R19
	BHI	orepdone
	SUB	R19, R2, R19
	MOVWU	(R1)(R19), R26
	CMPW	R26, R20
	BEQ	orep
orepdone:
	CBZW	R21, ofinal
	CBZW	R22, ostart
	ANDW	$0xFFFF, R21, R13
	MOVHU	(R8)(R13<<1), R19
	SUB	$1, R25
	CBZW	R19, ofinal
	SUBW	R19, R21, R21
	CBZW	R21, ofinal
ostart:
	SUB	$3, R23, R17

	// The chain walk; a candidate failing the gate takes one branch.
ocand:
	SUBW	R21, R2, R26
	CMPW	$65535, R26
	BHI	ofinal
	TBNZ	$63, R25, ofinal
	SUB	$1, R25
	ANDW	$0xFFFF, R21, R13
	MOVHU	(R8)(R13<<1), R22
	ADD	R1, R21, R13
	MOVWU	(R13)(R17), R19
	MOVWU	(R14)(R17), R26
	CMPW	R19, R26
	BEQ	ogate
onext2:
	CBZW	R22, ofinal
	SUBW	R22, R21, R21
	CBNZW	R21, ocand

ofinal:
	TBNZ	$63, R24, onext

	// A match: lastOff, lMax = min(len, iend-ip, 65535), offset - 1.
	SUB	R24, R2, R19
	MOVD	R19, 128(R0)
	SUB	$1, R19
	SUB	R2, R4, R26
	CMP	R26, R23
	CSEL	LO, R23, R26, R23
	MOVD	$65535, R26
	CMP	R26, R23
	CSEL	LO, R23, R26, R23
	MOVWU	(R15)(R2<<2), R20

	// Covered: the previous position relaxed longer lengths and dp[ip] >=
	// dp[ip-1]; only lengths 19 and 147 can still win.
	MOVD	144(R0), R21
	MOVD	136(R0), R22
	MOVD	R2, 136(R0)
	MOVD	R23, 144(R0)
	CMP	R23, R21
	BLS	onotcov
	ADD	$1, R22
	CMP	R2, R22
	BNE	onotcov
	SUB	$1, R2, R13
	MOVWU	(R15)(R13<<2), R13
	CMPW	R13, R20
	BLO	onotcov
	ADDW	$24, R20, R26
	CMP	$19, R23
	BLT	oskip
	ADD	$19, R2, R22
	MOVWU	(R15)(R22<<2), R25
	CMPW	R25, R26
	BHS	ocov2
	MOVD	$19, R13
	MOVW	R26, (R15)(R22<<2)
	MOVH	R13, (R11)(R22<<1)
	MOVH	R19, (R16)(R22<<1)
ocov2:
	CMP	$147, R23
	BLT	oskip
	ADDW	$8, R26
	ADD	$147, R2, R22
	MOVWU	(R15)(R22<<2), R25
	CMPW	R25, R26
	BHS	oskip
	MOVD	$147, R13
	MOVW	R26, (R15)(R22<<2)
	MOVH	R13, (R11)(R22<<1)
	MOVH	R19, (R16)(R22<<1)
	B	oskip

onotcov:
	// Lengths 5 to lMax by cost ranges: below 20 no escape (+24 bits),
	// below 148 a 1-byte escape (+32), below 16404 2 bytes (+40), above 3
	// (+48).
	MOVD	$5, R13
	ADD	$1, R23, R17
	ADDW	$24, R20, R26
	MOVD	$20, R14
orange:
	CMP	R17, R14
	CSEL	LO, R14, R17, R21
orloop:
	CMP	R21, R13
	BHS	orend
	ADD	R2, R13, R22
	MOVWU	(R15)(R22<<2), R25
	CMPW	R25, R26
	BHS	orskip
	MOVW	R26, (R15)(R22<<2)
	MOVH	R13, (R11)(R22<<1)
	MOVH	R19, (R16)(R22<<1)
orskip:
	ADD	$1, R13
	B	orloop
orend:
	CMP	R17, R13
	BHS	oskip
	ADDW	$8, R26
	CMP	$20, R14
	BEQ	ob148
	CMP	$148, R14
	BEQ	ob16404
	MOVD	$65536, R14
	B	orange
ob148:
	MOVD	$148, R14
	B	orange
ob16404:
	MOVD	$16404, R14
	B	orange

oskip:
	// No search inside a match of 256 bytes or more.
	CMP	$256, R23
	BLT	onext
	ADD	R2, R23, R13
	SUB	$1, R13
	MOVD	R13, 120(R0)
onext:
	ADD	$1, R2
	B	oloop

orep:
	// The previous offset matches 4 bytes: its length is the best so far,
	// and ends the search when sufficient or at the end.
	MOVD	R19, R24
	ADD	R1, R19, R13
	MOVD	$4, R17
orml:
	ADD	R2, R17, R19
	ADD	$8, R19
	CMP	R4, R19
	BHI	ormtail
	MOVD	(R14)(R17), R19
	MOVD	(R13)(R17), R26
	EOR	R19, R26, R19
	CBNZ	R19, ormdiff
	ADD	$8, R17
	B	orml
ormdiff:
	RBIT	R19, R19
	CLZ	R19, R19
	ADD	R19>>3, R17, R17
	B	ormdone
ormtail:
	ADD	R2, R17, R19
	CMP	R4, R19
	BHS	ormdone
	MOVBU	(R14)(R17), R19
	MOVBU	(R13)(R17), R26
	CMPW	R19, R26
	BNE	ormdone
	ADD	$1, R17
	B	ormtail
ormdone:
	MOVD	R17, R23
	MOVD	112(R0), R19
	CMP	R19, R23
	BGE	ofinal
	ADD	R2, R23, R19
	CMP	R4, R19
	BGE	ofinal
	B	orepdone

ogate:
	// A candidate past the gate: the first 4 bytes, then its length.
	MOVWU	(R13), R19
	CMPW	R19, R20
	BNE	onext2
	MOVD	$4, R17
oml:
	ADD	R2, R17, R19
	ADD	$8, R19
	CMP	R4, R19
	BHI	omtail
	MOVD	(R14)(R17), R19
	MOVD	(R13)(R17), R26
	EOR	R19, R26, R19
	CBNZ	R19, omdiff
	ADD	$8, R17
	B	oml
omdiff:
	RBIT	R19, R19
	CLZ	R19, R19
	ADD	R19>>3, R17, R17
	B	omdone
omtail:
	ADD	R2, R17, R19
	CMP	R4, R19
	BHS	omdone
	MOVBU	(R14)(R17), R19
	MOVBU	(R13)(R17), R26
	CMPW	R19, R26
	BNE	omdone
	ADD	$1, R17
	B	omtail
omdone:
	CMP	R23, R17
	BLE	onobetter
	MOVD	R17, R23
	MOVD	R21, R24
onobetter:
	SUB	$3, R23, R17
	MOVD	112(R0), R19
	CMP	R19, R23
	BGE	ofinal
	ADD	R2, R23, R19
	CMP	R4, R19
	BGE	ofinal
	B	onext2

otail:
	// The last positions: literals only.
	CMP	R4, R2
	BGE	odone
	MOVWU	(R15)(R2<<2), R19
	CMNW	$1, R19
	BEQ	otnext
	ADD	$1, R2, R13
	ADDW	R3, R19, R26
	MOVWU	(R15)(R13<<2), R14
	CMPW	R14, R26
	BHS	otnext
	MOVW	R26, (R15)(R13<<2)
	MOVH	ZR, (R11)(R13<<1)
otnext:
	ADD	$1, R2
	B	otail
odone:
	RET
