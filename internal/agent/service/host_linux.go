//go:build linux && !android

package service

func hostSystem() System { return Systemd{} }
