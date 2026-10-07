// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import "syscall"

// diskFullErrors are what a write fails with when the volume has no room for
// it. syscall has no names for these Windows error codes.
var diskFullErrors = []error{
	syscall.Errno(112), // ERROR_DISK_FULL
	syscall.Errno(39),  // ERROR_HANDLE_DISK_FULL
}
