//go:build !linux && !darwin

package agent

import "errors"

// HostConnectRecord keeps nothing here: no data plane on this OS yet
// (supported refuses before a request is made).
func HostConnectRecord() ConnectRecord { return noConnectRecord{} }

type noConnectRecord struct{}

func (noConnectRecord) Load() (bool, bool, error) { return false, false, nil }

func (noConnectRecord) Save(bool) error { return errors.ErrUnsupported }
