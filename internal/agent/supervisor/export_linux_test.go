//go:build linux && !android

package supervisor

var SetNetSysctls = setNetSysctls

// SetUnboundAccepts turns the negative control of the forged-ICMP tests on
// or off (unboundAccepts).
func SetUnboundAccepts(on bool) { unboundAccepts = on }
