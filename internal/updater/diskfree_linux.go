//go:build linux

package updater

import "syscall"

// availBytes returns the free space (bytes available to the caller) on the filesystem
// holding dir. ok=false when it can't be determined — the caller then SKIPS the space
// guard rather than blocking an update on a stat failure. The router overlay is tiny
// (~60 MB), so a pre-flight check here stops a binary swap from failing mid-write.
func availBytes(dir string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return st.Bavail * uint64(st.Bsize), true
}
