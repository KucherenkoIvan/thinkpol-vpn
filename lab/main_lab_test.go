//go:build lab

package lab_test

import (
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// The binaries this run built go when it ends.
func TestMain(m *testing.M) { lab.Main(m) }
