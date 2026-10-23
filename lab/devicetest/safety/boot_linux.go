package safety

import (
	"errors"
	"os"
	"strings"
)

// bootSession names this boot (the kernel's boot_id): a volatile change
// of another boot is gone with it.
func bootSession() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", errors.New("boot_id: empty")
	}
	return s, nil
}
