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
	if err := ClearWith(func() (Configurator, error) { return failing, nil }, nil); err == nil {
		t.Error("the failed Close went unreported")
	}
	if !failing.abandoned {
		t.Error("a failed clear kept the owner's place")
	}
	ok := &fakeConfigurator{}
	if err := ClearWith(func() (Configurator, error) { return ok, nil }, nil); err != nil || ok.abandoned {
		t.Errorf("a clear that closed: %v, abandoned %v", err, ok.abandoned)
	}
	if err := ClearWith(func() (Configurator, error) { return nil, ErrBusy }, nil); !errors.Is(err, ErrBusy) {
		t.Errorf("a clear that couldn't open: %v", err)
	}
}

// What runs while the owner's place is held runs before the Close that
// lets go of it, never when the place can't be had, and its failure
// neither skips the Close nor hides it.
func TestClearRunsHeldOnlyWhileHoldingTheOwnersPlace(t *testing.T) {
	ran := false
	if err := ClearWith(func() (Configurator, error) { return nil, ErrBusy }, func() error { ran = true; return nil }); !errors.Is(err, ErrBusy) || ran {
		t.Errorf("a clear that couldn't open: %v, held ran %v", err, ran)
	}
	heldErr, closeErr := errors.New("guard gone"), errors.New("netlink gone")
	f := &fakeConfigurator{closeErr: closeErr}
	err := ClearWith(func() (Configurator, error) { return f, nil }, func() error {
		if f.abandoned {
			t.Error("held ran after the place was let go")
		}
		return heldErr
	})
	if !errors.Is(err, heldErr) || !errors.Is(err, closeErr) || !f.abandoned {
		t.Errorf("held and Close failing: %v, abandoned %v", err, f.abandoned)
	}
	ok := &fakeConfigurator{}
	if err := ClearWith(func() (Configurator, error) { return ok, nil }, func() error { return heldErr }); !errors.Is(err, heldErr) || ok.abandoned {
		t.Errorf("held failing, Close fine: %v, abandoned %v", err, ok.abandoned)
	}
}
