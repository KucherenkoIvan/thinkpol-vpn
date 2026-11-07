//go:build !unix

package lab

import "os/exec"

// killGroupOnCancel leaves cmd's default cancel: the lab runs on unix hosts
// only, this just keeps the package building everywhere.
func killGroupOnCancel(*exec.Cmd) {}
