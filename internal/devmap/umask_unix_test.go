//go:build unix

package devmap

import "syscall"

func setUmask(mask int) (restore func()) {
	old := syscall.Umask(mask)
	return func() { syscall.Umask(old) }
}
