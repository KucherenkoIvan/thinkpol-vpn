//go:build linux || darwin

package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// HostConnectRecord is the host's ConnectRecord: ConnectRecordFile in the
// host lock's directory (/run/thinkpol, /private/var/db/thinkpol on
// macOS), stamped with trusteddir.BootSession.
func HostConnectRecord() ConnectRecord {
	return fileConnectRecord{dir: filepath.Dir(hostLockPath), boot: trusteddir.BootSession}
}

// fileConnectRecord is ConnectRecordFile in dir, reached through
// trusteddir like the host lock next to it.
type fileConnectRecord struct {
	dir  string
	boot func() (string, error)
}

// Load reads the record, making nothing: a missing directory or file, or
// a record of another boot, is none.
func (r fileConnectRecord) Load() (bool, bool, error) {
	boot, err := r.boot()
	if err != nil {
		return false, false, err
	}
	d, err := trusteddir.Open(r.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	defer func() { _ = d.Close() }()
	body, err := trusteddir.ReadRecord(d, ConnectRecordFile, boot)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, trusteddir.ErrOtherBoot):
		return false, false, nil
	case err != nil:
		return false, false, err
	}
	connect, err := parseConnectRecord(body)
	if err != nil {
		return false, false, err
	}
	return connect, true, nil
}

// Save replaces the record atomically (0600; the directory made 0700 if
// missing). Only the goroutine that runs the node calls it.
func (r fileConnectRecord) Save(connect bool) error {
	boot, err := r.boot()
	if err != nil {
		return err
	}
	d, err := trusteddir.Make(r.dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return trusteddir.WriteRecord(d, ConnectRecordFile, connectRecordHeader, boot, connectRecordBody(connect))
}

const connectRecordHeader = "# thinkpol agent: the device's connect choice for this boot: its first start's, then each local API request"

// The record's body: one line.
var (
	connectLine    = []byte("request connect\n")
	disconnectLine = []byte("request disconnect\n")
)

func connectRecordBody(connect bool) []byte {
	if connect {
		return connectLine
	}
	return disconnectLine
}

func parseConnectRecord(body []byte) (bool, error) {
	switch {
	case bytes.Equal(body, connectLine):
		return true, nil
	case bytes.Equal(body, disconnectLine):
		return false, nil
	}
	return false, fmt.Errorf("connect record: unexpected body %q", body)
}
