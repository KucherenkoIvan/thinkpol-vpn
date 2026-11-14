//go:build !darwin && (!linux || android)

package firewall

// KillSwitchPlace: no kill switch on this OS yet (Windows: TP-076).
const KillSwitchPlace = "none on this OS"
