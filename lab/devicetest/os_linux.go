package main

import "errors"

// physicalInterface: on Linux (the lab only) the interface is given with
// -iface.
func physicalInterface() (string, error) {
	return "", errors.New("give the interface with -iface")
}
