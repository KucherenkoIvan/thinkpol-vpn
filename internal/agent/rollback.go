package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// RollbackReport is what Rollback did: the host's parts it cleared, in
// order, and the connect choice it recorded (RecordErr: why it couldn't),
// with what a service's next start does after it.
type RollbackReport struct {
	Parts     []HostPart
	RecordErr error
	next      nextStart
}

// NeedsRootError is a command refused because it isn't run as root: what
// it changes is the host's (Why). Rollback and the service's install and
// uninstall return it, so a caller matches one type for all of them
// (errors.As); errors.Is still finds each one's own value. It is in a file
// every OS builds, not beside a per-OS check: the CLI matches it on every
// OS, including one whose commands refuse as unsupported first.
type NeedsRootError struct{ Why string }

func (e *NeedsRootError) Error() string { return e.Why + ": run it as root (sudo)" }

var (
	// ErrRollbackNeedsRoot: rollback was run without root.
	ErrRollbackNeedsRoot = &NeedsRootError{Why: "rollback changes the host's routing, firewall and resolvers"}
	// errRollbackLeft: part of what a dead agent left is still on the
	// host; the report says which.
	errRollbackLeft = errors.New("part of what a dead agent left is still on the host (above): fix what failed and run `sudo thinkpol rollback` again")
	// errRollbackNotRecorded: a device's connect choice wasn't recorded
	// down, so a start in this boot may still follow one recorded up.
	errRollbackNotRecorded = errors.New("this boot's connect choice wasn't recorded (above): a service's next start in this boot may connect and put the kill switch back; fix what failed and run `sudo thinkpol rollback` again")
)

// rollbackRefused is Rollback's error while another process holds the
// host's agent lock (Err, an ErrAnotherAgent, which it wraps): a running
// agent, or a service install, uninstall or rollback. Nothing was
// touched.
type rollbackRefused struct{ Err error }

func (r rollbackRefused) Error() string {
	return "another thinkpol process holds the host: a running agent, or a service install, uninstall or rollback; " +
		"rollback only undoes what a dead agent left. An install, uninstall or rollback: run this again once it ends. " +
		"A running agent: `thinkpol kill-switch off` and `thinkpol disconnect` take its tunnel down, " +
		"or stop it (a stop leaves the kill switch in place) and run this again. The host lock: " + r.Err.Error()
}

func (r rollbackRefused) Unwrap() error { return r.Err }

// Rollback puts the host back to no tunnel after an agent died
// (`thinkpol rollback`), as root: under the host's agent lock, refused
// while another process holds it (rollbackRefused, with a nil report)
// with nothing touched, it records the device's connect choice for this
// boot as down (ConnectRecord), then clears what a dead run left
// (ClearHost). The record keeps the crash posture from coming back: a
// service whose agent starts again in this boot comes up disconnected
// rather than putting the kill switch in place while meant up; only the
// kill-switch toggle, on, puts it back at that start, in the down shape.
// It is recorded first, so a rollback cut short still settles that. The
// node's settings in stateDir (its mode, the toggle) only word the
// report. Rollback is the member choosing no tunnel over failing closed
// (docs/design/security.md, "Kill switch").
//
// Every part is tried whatever failed before: what failed is in the
// report, and the error says what is left (errRollbackLeft) or that the
// choice wasn't recorded (errRollbackNotRecorded).
func Rollback(p Platform, stateDir string) (*RollbackReport, error) {
	if err := supported(ModeDevice); err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		return nil, ErrRollbackNeedsRoot
	}
	return rollback(p, stateDir)
}

// rollback is Rollback past its root check.
func rollback(p Platform, stateDir string) (*RollbackReport, error) {
	unlock, err := p.LockHost()
	if errors.Is(err, ErrAnotherAgent) {
		return nil, rollbackRefused{err}
	}
	if err != nil {
		return nil, err
	}
	defer unlock()
	r := &RollbackReport{RecordErr: p.ConnectRecord.Save(false), next: readNextStart(stateDir)}
	r.Parts = p.clearHost()
	return r, r.err()
}

// err is the error Rollback returns with r.
func (r *RollbackReport) err() error {
	var errs []error
	if partsLeft(r.Parts) {
		errs = append(errs, errRollbackLeft)
	}
	if r.RecordErr != nil && !r.next.server {
		errs = append(errs, errRollbackNotRecorded)
	}
	return errors.Join(errs...)
}

// nextStart is what a service's next start on the host does after a
// rollback, as far as the report says: a server's runs the server again,
// and a device's, recorded down, puts the kill switch back (in the down
// shape) only with its toggle on. err: the node's settings can't be read,
// so neither is known.
type nextStart struct {
	server     bool
	killSwitch bool
	err        error
}

// readNextStart reads the node of state directory dir as a service's
// start would: its mode (a server where its map shows one, as
// ServiceMode installs it), and the kill switch's toggle, the member's
// (DeviceFile) else the node file's.
func readNextStart(dir string) nextStart {
	s, err := ReadNodeFile(dir)
	if err != nil {
		return nextStart{err: err}
	}
	st, err := LoadState(dir, filepath.Join(dir, MapFileName))
	if err != nil {
		return nextStart{err: err}
	}
	switch mode, why := knownMode(s.Mode, st, nil); {
	case why == UnknownNotInMap:
		return nextStart{err: errors.New("its mode isn't known: its map has no section for it")}
	case why != ModeKnown || mode == ModeServer:
		return nextStart{server: true}
	}
	on := s.KillSwitch != nil && *s.KillSwitch
	if st.Device.KillSwitch != nil {
		on = *st.Device.KillSwitch
	}
	return nextStart{killSwitch: on}
}

// Print prints the report, one line per part, and what comes next;
// nothing for a nil report (a rollback refused).
func (r *RollbackReport) Print(w io.Writer) error {
	if r == nil {
		return nil
	}
	var lines []string
	for _, p := range r.Parts {
		for _, u := range p.Undone {
			lines = append(lines, "undid: "+u)
		}
		if p.Err != nil {
			lines = append(lines, fmt.Sprintf("LEFT: %s: %v", p.What, p.Err))
		} else {
			lines = append(lines, "none left: "+p.What)
		}
	}
	lines = append(lines, r.recordLine())
	if !partsLeft(r.Parts) {
		lines = append(lines, r.directLine())
	}
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}
	return nil
}

// recordLine says how the connect choice was recorded, for the node's
// mode.
func (r *RollbackReport) recordLine() string {
	switch {
	case r.next.server && r.RecordErr != nil:
		return fmt.Sprintf("not recorded: this boot's connect choice: %v; a server's start doesn't read it", r.RecordErr)
	case r.next.server:
		return "recorded: disconnected, as this boot's connect choice; a server's start doesn't read it"
	case r.RecordErr != nil:
		return fmt.Sprintf("NOT RECORDED: this boot's connect choice: %v; "+
			"a service's next start in this boot may connect and put the kill switch back", r.RecordErr)
	}
	return "recorded: disconnected, as this boot's connect choice: " +
		"a service's next start in this boot comes up disconnected (`thinkpol connect` connects it again)"
}

// directLine says that nothing of a dead agent's is left, and what a
// service's next start changes of that.
func (r *RollbackReport) directLine() string {
	const direct = "the host has no tunnel: traffic goes direct"
	switch {
	case r.next.server:
		return direct + " until a service's next start runs the server again"
	case r.RecordErr != nil:
		return direct
	case r.next.err != nil:
		return fmt.Sprintf("%s; a service's next start in this boot puts the kill switch back, in the down shape, "+
			"if its toggle is on (the node's settings can't be read: %v)", direct, r.next.err)
	case r.next.killSwitch:
		return direct + " until a service's next start in this boot puts the kill switch back, in the down shape: " +
			"its toggle is on (`thinkpol kill-switch off` once the agent runs)"
	}
	return direct + ", and stays so at a service's next start in this boot: the kill switch's toggle is off"
}
