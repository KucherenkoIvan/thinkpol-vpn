package safety

import "github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"

// bootSession names this boot (kern.bootsessionuuid): a volatile change of
// another boot is gone with it.
func bootSession() (string, error) { return trusteddir.BootSession() }
