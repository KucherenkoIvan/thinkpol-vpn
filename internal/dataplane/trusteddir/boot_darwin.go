package trusteddir

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// BootSession names this boot of the machine. A directory outlives a
// reboot and what its records name (routes, pf references) doesn't, so a
// record stamped with another boot session holds nothing.
func BootSession() (string, error) { return bootSession() }

var bootSession = sync.OnceValues(func() (string, error) {
	s, err := unix.Sysctl("kern.bootsessionuuid")
	if err == nil && s == "" {
		err = errors.New("empty")
	}
	if err != nil {
		return "", fmt.Errorf("kern.bootsessionuuid: %w", err)
	}
	return s, nil
})
