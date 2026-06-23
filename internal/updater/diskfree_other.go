//go:build !linux

package updater

// availBytes can't portably read free space off-Linux (the Windows dev/demo build),
// so it reports "unknown" and the space guard is skipped. The router target is always
// Linux, where diskfree_linux.go provides the real statfs-based reading.
func availBytes(dir string) (uint64, bool) { return 0, false }
