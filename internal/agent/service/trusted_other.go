//go:build !unix

package service

import "errors"

func checkTrusted(string) error { return errors.ErrUnsupported }
