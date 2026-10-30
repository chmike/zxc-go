//go:build !purego

package zxc

// havePakAsm reports whether the CPU has SSSE3, whose PSHUFB pak_amd64.s
// uses for short-period matches: CPUID leaf 1, ECX bit 9. Every x86-64 CPU
// since about 2008 has it; on the others pakRun falls back to pakFast.
var havePakAsm = func() bool {
	_, _, ecx, _ := cpuid(1, 0)
	return ecx&(1<<9) != 0
}()
