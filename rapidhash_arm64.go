//go:build !purego

package zxc

// Every arm64 CPU has the instructions the assembly main loop of
// rapidhash uses.
const haveRapidLoopAsm = true

// rapidLoopAsm is rapidLoopGo in assembly (rapidhash_arm64.s). It requires
// len(p) > 112.
//
//go:noescape
func rapidLoopAsm(p []byte, seed uint64) (h uint64, n int)
