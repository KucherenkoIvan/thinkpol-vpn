package agent

import (
	"errors"
	"fmt"
	"io"
)

// RollbackReport is what Rollback did: the host's parts it cleared, in
// order, and the connect choice it recorded (RecordErr: why it couldn't).
type RollbackReport struct {
	Parts     []HostPart
	RecordErr error
}

// errRollbackLeft is Rollback's error when part of what it clears is
// left; the report says which.
var errRollbackLeft = errors.New("part of what a dead agent left is still on the host (above): fix what failed and run `sudo thinkpol rollback` again")

// Rollback puts the host back to no tunnel after an agent died
// (`thinkpol rollback`): under the host's agent lock, refused while an
// agent holds it (ErrAnotherAgent) with nothing touched, it clears what a
// dead run left (clearHost: a server's, the routing and leak guard, the
// OS's resolver configuration, the kill switch), then records the
// device's connect choice for this boot as down (ConnectRecord). The
// record keeps the crash posture from coming back: a service whose agent
// starts again in this boot comes up disconnected rather than putting the
// kill switch in place while meant up. Only the kill-switch toggle, on,
// puts it back at that start, in the down shape. Rollback is the member
// choosing no tunnel over failing closed (docs/design/security.md, "Kill
// switch").
//
// Every part is tried, and the choice recorded, whatever failed before:
// what failed is in the report, and the error says part of it is left.
func Rollback(p Platform) (RollbackReport, error) {
	if err := supported(ModeDevice); err != nil {
		return RollbackReport{}, err
	}
	unlock, err := p.LockHost()
	if errors.Is(err, ErrAnotherAgent) {
		return RollbackReport{}, fmt.Errorf("%w: rollback only undoes what a dead one left; "+
			"while it runs, `thinkpol kill-switch off` and `thinkpol disconnect` take the tunnel down, "+
			"or stop it (a stop leaves the kill switch in place) and run this again", err)
	}
	if err != nil {
		return RollbackReport{}, err
	}
	defer unlock()
	r := RollbackReport{Parts: p.clearHost(), RecordErr: p.ConnectRecord.Save(false)}
	if r.RecordErr != nil || partsErr(r.Parts) != nil {
		return r, errRollbackLeft
	}
	return r, nil
}

// Write prints the report, one line per part, and what comes next;
// nothing for a rollback that never ran (refused).
func (r RollbackReport) Write(w io.Writer) error {
	if len(r.Parts) == 0 {
		return nil
	}
	var lines []string
	for _, p := range r.Parts {
		for _, u := range p.Undone {
			lines = append(lines, fmt.Sprintf("undid: %s", u))
		}
		if p.Err != nil {
			lines = append(lines, fmt.Sprintf("LEFT: %s: %v", p.What, p.Err))
		} else {
			lines = append(lines, fmt.Sprintf("none left: %s", p.What))
		}
	}
	if r.RecordErr != nil {
		lines = append(lines, fmt.Sprintf("NOT RECORDED: the connect choice for this boot: %v; "+
			"the service's next start in this boot may connect and put the kill switch back", r.RecordErr))
	} else {
		lines = append(lines, "recorded: disconnected, as this boot's connect choice; "+
			"the service's next start in this boot comes up disconnected (`thinkpol connect` connects it again), "+
			"and puts the kill switch back, in the down shape, only if its toggle is on")
	}
	if r.RecordErr == nil && partsErr(r.Parts) == nil {
		lines = append(lines, "the host has no tunnel: traffic goes direct")
	}
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}
	return nil
}
