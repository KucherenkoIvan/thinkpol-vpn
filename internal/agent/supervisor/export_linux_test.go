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
