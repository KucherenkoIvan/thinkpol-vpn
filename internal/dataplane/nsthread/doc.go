// Package nsthread runs a function on an OS thread that the function moves
// into another network or mount namespace, and moves the thread back
// afterwards, so no thread of the process is left behind in a namespace that
// isn't its own. Every helper that moves a thread into another namespace
// goes through Do.
//
// It is Linux-only; on other systems the package is empty.
package nsthread
