package agent

// ConnectRecordFile, next to the host's agent lock, is a device's connect
// choice for this boot (ConnectRecord).
const ConnectRecordFile = "connect"

// ConnectRecord keeps a device's connect choice for the boot it was made
// in, under the service (Config.ConnectOnBoot): the first start's (as
// connect-on-boot says), then each request through the local API and a
// failed Connect's down. A later start in the same boot (a crash and the
// service manager's restart) follows it, so it neither drops a connected
// member nor undoes their disconnect.
type ConnectRecord interface {
	// Load is the choice recorded in this boot: ok is false when there is
	// none, or only one of an earlier boot.
	Load() (connect, ok bool, err error)
	// Save records a choice.
	Save(connect bool) error
}
