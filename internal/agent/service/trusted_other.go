//go:build !unix

package service

import (
	"errors"
	"io/fs"
)

func checkTrusted(string) error { return errors.ErrUnsupported }

func ownedSafely(fs.FileInfo) bool { return false }
