package firewall

// The guard's pf readers, for what reads pf from outside the agent: the
// device-test harness (lab/devicetest) compares pf with its baseline
// through these, so a listing is read one way wherever it is read.

// TokenRecordName is the guard's record of its pf reference, in
// netcfg.StateDir.
const TokenRecordName = tokenRecord

// ListingLines is a pfctl listing as the guard reads it: its non-empty
// lines, trimmed, without pfctl's ALTQ chatter.
func ListingLines(listing []byte) []string { return lines(listing) }

// PfEnabled reads `pfctl -s info`: whether its Status line says Enabled;
// an error without one.
func PfEnabled(info []byte) (bool, error) { return parseEnabled(info) }
