//go:build !purego

package zxc

// Every arm64 CPU has the instructions pak_arm64.s uses.
const havePakAsm = true
