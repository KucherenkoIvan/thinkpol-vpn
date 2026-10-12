// Package egress finds the way a server's internet traffic leaves it: the
// uplink the root namespace's default routes use, and the families it
// carries. The supervisor's nftables tables forward a space's traffic out of
// it and masquerade it (internal/agent/supervisor), NAT66 included.
// Linux-only, and not on Android.
package egress
