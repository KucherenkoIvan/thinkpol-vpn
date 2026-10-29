//go:build !darwin

package localapi

// systemGroup finds nothing beyond /etc/group here.
func systemGroup(string) (uint32, bool) { return 0, false }

// systemMembership is none: the recorded groups are the ones the file
// system uses too.
func systemMembership() Membership { return nil }
