package service

import "time"

func hostSystem() System { return Launchd{BootstrapRetry: 500 * time.Millisecond} }
