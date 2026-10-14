//go:build linux && !android

package firewall

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

// Only the probe's answer can make the guard unsupported, and only an
// answer that means no nf_tables: the errors of a kernel that has it
// (permissions, a missing object, an overflow) are ordinary failures.
func TestOnlyNoNFTablesIsUnsupported(t *testing.T) {
	for errno, want := range map[unix.Errno]bool{
		unix.EPROTONOSUPPORT: true, unix.EAFNOSUPPORT: true, unix.EOPNOTSUPP: true, unix.EINVAL: true,
		unix.EPERM: false, unix.ENOENT: false, unix.ENOBUFS: false, unix.EBUSY: false,
	} {
		if got := noNFTables(fmt.Errorf("netlink receive: %w", errno)); got != want {
			t.Errorf("%v: no nf_tables %v, want %v", errno, got, want)
		}
	}
}
