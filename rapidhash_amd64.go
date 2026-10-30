//go:build !purego

package zxc

// haveRapidLoopAsm reports whether the CPU has BMI2, which the assembly
// main loop of rapidhash needs (MULX): CPUID leaf 7, sub-leaf 0, EBX bit 8.
// Every x86-64 CPU since about 2013 (Intel Haswell, AMD Excavator) has it.
var haveRapidLoopAsm = func() bool {
	if maxLeaf, _, _, _ := cpuid(0, 0); maxLeaf < 7 {
		return false
	}
	_, ebx, _, _ := cpuid(7, 0)
	return ebx&(1<<8) != 0
}()

// rapidLoopAsm is rapidLoopGo in assembly (rapidhash_amd64.s). It requires
// len(p) > 112 and haveRapidLoopAsm.
//
//go:noescape
func rapidLoopAsm(p []byte, seed uint64) (h uint64, n int)

func cpuid(leaf, sub uint32) (a, b, c, d uint32)
