//go:build darwin || (linux && !android)

package netcfg

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

// fakeLinkOps is one interface, found by any of names. setMTU succeeds
// mtuOK times and fails after; setUp always fails.
type fakeLinkOps struct {
	names []string
	link  linkState
	mtuOK int
}

var errFake = errors.New("refused")

func (f *fakeLinkOps) linkByName(name string) (linkState, error) {
	for _, n := range f.names {
		if n == name {
			return f.link, nil
		}
	}
	return linkState{}, errors.New("no interface " + name)
}

func (f *fakeLinkOps) linkByIndex(int) (linkState, error) { return f.link, nil }

func (f *fakeLinkOps) setMTU(_ linkState, mtu int) error {
	if f.mtuOK == 0 {
		return errFake
	}
	f.mtuOK--
	f.link.mtu = mtu
	return nil
}

func (f *fakeLinkOps) setUp(linkState, bool) error       { return errFake }
func (f *fakeLinkOps) addrs(int) ([]netip.Prefix, error) { return nil, nil }
func (f *fakeLinkOps) addAddr(int, netip.Prefix) error   { return nil }
func (f *fakeLinkOps) delAddr(int, netip.Prefix) error   { return nil }

// A failed Apply that re-filed the interface's record (under another of
// its names, or with a fresh kernel name after a rename) and whose MTU
// revert fails gives the record back as it was but for the MTU the
// interface is left at, so a later restore still recognises it.
func TestAFailedRevertKeepsItsNoteWhenTheRecordMovesBack(t *testing.T) {
	for _, tc := range []struct{ name, config, kname string }{
		{"another_name", "overlay-alt", "ovl0"},
		{"renamed", "ovl0", "old0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := &fakeLinkOps{names: []string{"ovl0", "overlay-alt"}, link: linkState{name: "ovl0", index: 7, mtu: 1380}, mtuOK: 1}
			l := newLedger()
			l.changed["ovl0"] = linkChange{index: 7, kname: tc.kname, origMTU: 1500, mtu: 1380}
			var u undoLog
			if _, err := l.configure(context.Background(), ops, []Interface{{Name: tc.config, MTU: 1400, Up: true}}, &u); err == nil {
				t.Fatal("configure succeeded; the test wants bringing the interface up to fail")
			}
			if err := u.run(); err == nil {
				t.Fatal("the undo succeeded; the test wants the MTU revert to fail")
			}
			want := map[string]linkChange{"ovl0": {index: 7, kname: tc.kname, origMTU: 1500, mtu: 1400}}
			if !reflect.DeepEqual(l.changed, want) || ops.link.mtu != 1400 {
				t.Errorf("after the failed Apply: ledger %+v, interface MTU %d; want %+v, MTU 1400", l.changed, ops.link.mtu, want)
			}
		})
	}
}
