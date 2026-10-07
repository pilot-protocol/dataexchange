// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux && !darwin && !freebsd

package dataexchange

// platformFreeDiskBytes is not implemented on this platform; the receiver relies on
// its byte quota alone.
func platformFreeDiskBytes(string) (uint64, bool) { return 0, false }
