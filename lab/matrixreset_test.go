//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// A matrix row runs its cells in one lab or a few (rowLabs), each lab's
// one after another, so each cell must start from the state the lab's
// first one did: after a cell, the lab is reset to the state recorded when
// the row took it (lab.Lab.Snapshot, lab.Lab.Reset), and the reset is
// checked. A cell whose reset didn't hold is an error, and so is every
// later cell of its lab.

// matrixRow is one of a row's labs and the state each of its cells starts
// from.
type matrixRow struct {
	lab   *lab.Lab
	clean *lab.Snapshot
	// broken is set once a reset didn't hold: the rest of the row can't
	// be trusted.
	broken error
}

// startRow takes the row's lab from the censor pool (lab.Upstream's
// router, device-a, server-1 and camouflage), starts the camouflage site
// for every cell (the prober, server-hello and the rows that splice to it
// start it in vain) and empties the router's conntrack; that is the clean
// state.
//
// Those are the nodes the row's cells drive: device-a and server-1 are
// the transport's ends (the control rows' client and server, the
// reference VPNs' peers), the router runs censord, and the camouflage
// site is what the prober and server-hello compare every row's server
// with, what the relay-tcp and reality rows splice to, and, being outside
// the space and not the censor, where the thinkpol rows' maps are built.
// No cell reaches device-b, server-2 or internet, so they aren't started.
// The row waits for its lab in its turn among the matrix's labs
// (matrixLabs: the longest first).
func startRow(t *testing.T, turn int) *matrixRow {
	begin := time.Now()
	var up, cellsDone time.Time
	// Registered first, so it runs last, after the lab went back to the
	// pool: what taking the lab and giving it back cost next to the cells
	// is what splitting a row trades (transport.labs).
	t.Cleanup(func() {
		if !up.IsZero() && !cellsDone.IsZero() {
			t.Logf("lab: up in %v, cells %v, back in %v", up.Sub(begin).Round(time.Second), cellsDone.Sub(up).Round(time.Second), time.Since(cellsDone).Round(time.Second))
		}
	})
	l := censorPool.AcquireInOrder(t, turn)
	t.Cleanup(func() { cellsDone = time.Now() })
	lab.StartCamouflage(t, l)
	if _, err := execRead(l.Node(lab.Router), execTimeout, "censord", "-reset"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	clean, err := l.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Before the lab goes back: the row's copies of /etc are no part of
	// the pool's clean state.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
		defer cancel()
		if err := l.DropSnapshot(ctx, clean); err != nil {
			t.Logf("lab %s: the row's snapshot stays: %v", l.Project, err)
		}
	})
	up = time.Now()
	return &matrixRow{lab: l, clean: clean}
}

// reset puts the lab back in its clean state after a cell, whose own
// cleanups have stopped its processes and censord, and checks it held
// (lab.Lab.Reset): what still runs killed, every TCP connection left
// aborted, what the cell left removed (the verdict log with /run/censor),
// every node's conntrack emptied (the queue rule's ct match keeps
// conntrack on in the router, so a cell's flows would outlive it), every
// node read back.
func (r *matrixRow) reset(logf func(format string, args ...any)) error {
	if r.broken != nil {
		return r.broken
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	err := r.lab.Reset(ctx, r.clean, logf)
	if err != nil {
		r.broken = fmt.Errorf("an earlier cell's reset didn't hold: %w", err)
	}
	return err
}
