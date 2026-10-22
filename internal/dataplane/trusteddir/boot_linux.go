package trusteddir

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// bootIDPath is the kernel's random id of this boot.
const bootIDPath = "/proc/sys/kernel/random/boot_id"

// BootSession names this boot of the machine: the kernel's boot id. A
// directory under /run is gone after a reboot anyway, but nothing makes
// /run a tmpfs, so a record there is stamped as macOS's are.
func BootSession() (string, error) { return bootSession() }

var bootSession = sync.OnceValues(func() (string, error) { return readBootID(bootIDPath) })

func readBootID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("boot id: %w", err)
	}
	s := strings.TrimSpace(string(data))
	if f := strings.Fields(s); len(f) != 1 || f[0] != s {
		return "", fmt.Errorf("boot id %q: %w", s, errors.New("want one field"))
	}
	return s, nil
}
