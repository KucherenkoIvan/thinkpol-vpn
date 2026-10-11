// Package nsthreadtest checks, from a lab test, that no thread of the test
// process was left in another network or mount namespace by a helper that
// enters one.
//
// It is Linux-only; on other systems the package is empty.
package nsthreadtest
