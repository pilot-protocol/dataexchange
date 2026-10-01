// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package dataexchange

import "syscall"

// platformFreeDiskBytes reports the space available to this process on the
// filesystem holding dir.
func platformFreeDiskBytes(dir string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true // #nosec G115 -- block size is positive
}
