//go:build !unix

package devmap

func setUmask(int) (restore func()) { return func() {} }
