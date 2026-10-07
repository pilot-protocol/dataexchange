// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

// diskFullErrors is empty: Plan 9 reports errors as strings, with no code to
// match a full disk by. A write that fails for lack of space keeps its
// .partial, like any other failed write.
var diskFullErrors []error
