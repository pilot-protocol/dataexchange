// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows && !plan9

package dataexchange

import "syscall"

// diskFullErrors are what a write fails with when the filesystem has no room
// for it: out of space, or out of the user's disk quota.
var diskFullErrors = []error{syscall.ENOSPC, syscall.EDQUOT}
