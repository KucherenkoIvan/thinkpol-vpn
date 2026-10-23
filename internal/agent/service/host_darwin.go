package service

import "time"

func hostSystem() System { return Launchd{Poll: 500 * time.Millisecond} }
