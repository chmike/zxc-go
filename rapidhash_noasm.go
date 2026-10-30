//go:build !(amd64 || arm64) || purego

package zxc

// No assembly on this platform, or the purego build tag: rapidhash runs
// its main loop in Go.
const haveRapidLoopAsm = false

func rapidLoopAsm(p []byte, seed uint64) (uint64, int) { return rapidLoopGo(p, seed) }
