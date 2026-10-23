package main

import (
	"errors"
	"os"
)

// tcpdumpPath decodes captures as a judge will (`tcpdump -n -A -r`).
var tcpdumpPath = func() string {
	for _, p := range []string{"/usr/bin/tcpdump", "/usr/sbin/tcpdump"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/usr/bin/tcpdump"
}()

// physicalInterface: on Linux (the lab only) the interface is given.
func physicalInterface() (string, error) {
	return "", errors.New("give the interface with -iface")
}
