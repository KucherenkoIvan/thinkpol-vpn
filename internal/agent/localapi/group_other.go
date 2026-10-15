//go:build !darwin

package localapi

// systemGroup finds nothing beyond /etc/group here.
func systemGroup(string) (uint32, bool) { return 0, false }
