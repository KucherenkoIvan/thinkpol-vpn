package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
)

// The service's names and paths on the host.
const (
	// BinaryPath is where install puts the thinkpol binary the service
	// runs, in a directory root owns that no one else can write to.
	BinaryPath = "/usr/local/bin/thinkpol"
	// UnitPath is the systemd unit.
	UnitPath = "/etc/systemd/system/" + UnitName
	// UnitName is the systemd unit's name.
	UnitName = "thinkpol.service"
	// PlistPath is the launchd daemon's definition.
	PlistPath = "/Library/LaunchDaemons/" + Label + ".plist"
	// Label is the launchd daemon's label.
	Label = "org.thinkpol.agent"
	// Group is the local API's group (agent.Config.APIGroup's default):
	// install creates it and adds the installing user.
	Group = "thinkpol"
	// RestartAfterSeconds is how long the service manager waits before it
	// starts the agent again after it exited.
	RestartAfterSeconds = 5
	// StopTimeoutSeconds is how long a stop waits for the agent to take
	// its data plane down before it is killed (TimeoutStopSec, launchd's
	// ExitTimeOut).
	StopTimeoutSeconds = 60
)

// Definition is what the service runs: the agent (`thinkpol up`, with the
// node's defaults) and whether it connects at boot (THINKPOL_CONNECT_ON_BOOT,
// which also has it keep a device's connect choice for the boot).
type Definition struct {
	// Binary is the thinkpol binary's absolute path.
	Binary string
	// ConnectOnBoot is THINKPOL_CONNECT_ON_BOOT: whether a device connects
	// at the boot's first start (PRD D5: off unless the member turns it on).
	ConnectOnBoot bool
}

// SystemdUnit is the definition as a systemd unit.
func SystemdUnit(d Definition) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, `# Written by thinkpol service install; thinkpol service uninstall removes it.
# Connect-on-boot: thinkpol service connect-on-boot on|off.
[Unit]
Description=thinkpol node agent
After=network.target systemd-resolved.service
StartLimitIntervalSec=0

[Service]
ExecStart=%s up
# SIGHUP to the agent alone re-reads the map at once; a server's workers
# don't handle it, so never signal the whole unit.
ExecReload=/bin/kill -HUP $MAINPID
Environment=THINKPOL_CONNECT_ON_BOOT=%s
Restart=always
RestartSec=%d
KillMode=mixed
TimeoutStopSec=%d

[Install]
WantedBy=multi-user.target
`, d.Binary, OnOff(d.ConnectOnBoot), RestartAfterSeconds, StopTimeoutSeconds)
	return b.Bytes()
}

// LaunchdPlist is the definition as a launchd daemon's property list. It
// sets no StandardOutPath or StandardErrorPath: the agent writes no log
// to disk (PRD S2), and its log is the local API's.
func LaunchdPlist(d Definition) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by thinkpol service install; thinkpol service uninstall removes it. -->
<!-- Connect-on-boot: thinkpol service connect-on-boot on|off. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + escape(Label) + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + escape(d.Binary) + `</string>
		<string>up</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>THINKPOL_CONNECT_ON_BOOT</key>
		<string>` + OnOff(d.ConnectOnBoot) + `</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>` + strconv.Itoa(RestartAfterSeconds) + `</integer>
	<key>ExitTimeOut</key>
	<integer>` + strconv.Itoa(StopTimeoutSeconds) + `</integer>
</dict>
</plist>
`)
	return b.Bytes()
}

func escape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// OnOff is connect-on-boot as THINKPOL_CONNECT_ON_BOOT spells it.
func OnOff(on bool) string {
	if on {
		return agent.ConnectOnBootOn
	}
	return agent.ConnectOnBootOff
}

// ParseOnOff reads connect-on-boot as OnOff spells it: nil for "" (not
// given), an error for anything but on and off.
func ParseOnOff(s string) (*bool, error) {
	switch s {
	case "":
		return nil, nil
	case OnOff(true), OnOff(false):
		on := s == OnOff(true)
		return &on, nil
	}
	return nil, fmt.Errorf("connect-on-boot %q: want %s or %s", s, OnOff(true), OnOff(false))
}
