//go:build linux && !android

package supervisor

var SetNetSysctls = setNetSysctls

// WithUnboundAccepts turns on the negative control of the forged-ICMP tests
// (Options.unboundAccepts): the accepts take any established or related
// flow, whoever owns it. Test-only: production never sets it.
func WithUnboundAccepts(opts Options) Options {
	opts.unboundAccepts = true
	return opts
}

// WithArpOnOutput turns on the negative control of the forged-ARP test
// (Options.arpOnOutput): the arp chain sits on the ARP output hook, where
// a space's ARP never matches. Test-only: production never sets it.
func WithArpOnOutput(opts Options) Options {
	opts.arpOnOutput = true
	return opts
}
