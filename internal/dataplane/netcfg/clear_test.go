package netcfg

import (
	"errors"
	"testing"
)

// fakeConfigurator closes as told and records being abandoned.
type fakeConfigurator struct {
	Configurator
	closeErr  error
	abandoned bool
}

func (f *fakeConfigurator) Close() error { return f.closeErr }
func (f *fakeConfigurator) abandon()     { f.abandoned = true }

// A clear whose Close fails still frees the owner's place, so the next
// start isn't refused with ErrBusy; one that closes keeps nothing to free.
func TestAFailedClearFreesTheOwnersPlace(t *testing.T) {
	failing := &fakeConfigurator{closeErr: errors.New("netlink gone")}
	if err := clearWith(func() (Configurator, error) { return failing, nil }); err == nil {
		t.Error("the failed Close went unreported")
	}
	if !failing.abandoned {
		t.Error("a failed clear kept the owner's place")
	}
	ok := &fakeConfigurator{}
	if err := clearWith(func() (Configurator, error) { return ok, nil }); err != nil || ok.abandoned {
		t.Errorf("a clear that closed: %v, abandoned %v", err, ok.abandoned)
	}
	if err := clearWith(func() (Configurator, error) { return nil, ErrBusy }); !errors.Is(err, ErrBusy) {
		t.Errorf("a clear that couldn't open: %v", err)
	}
}
