package agent

// ConnectRecordFile, next to the host's agent lock, is a device's last
// connect request through the local API in this boot (ConnectRecord).
const ConnectRecordFile = "connect"

// ConnectRecord keeps a device's last connect request through the local
// API, stamped with the boot it was made in. A start in the same boot (a
// crash and the service manager's restart, a restart by hand) takes it
// over the configuration, so it neither drops a connected member nor
// undoes their disconnect; a boot starts as configured (Config.Connect,
// connect-on-boot).
type ConnectRecord interface {
	// Load is the last request recorded in this boot: ok is false when
	// there is none, or only one of an earlier boot.
	Load() (connect, ok bool, err error)
	// Save records a request.
	Save(connect bool) error
}
