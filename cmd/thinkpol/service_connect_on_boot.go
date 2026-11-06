package main

import (
	"context"
	"errors"
)

func init() {
	register(command{
		path:    "service connect-on-boot",
		summary: "replaced by thinkpol connect-on-boot",
		hidden:  true,
		run:     runServiceConnectOnBoot,
	})
}

func runServiceConnectOnBoot(context.Context, env, []string) error {
	return errConnectOnBootMoved
}

// errConnectOnBootMoved answers the service's connect-on-boot, which is
// the device's setting now.
var errConnectOnBootMoved = errors.New("connect-on-boot is the device's setting now, no longer the service's: thinkpol connect-on-boot [on|off] (no root needed)")
