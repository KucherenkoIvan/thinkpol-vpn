package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
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
	// RestartAfter is how long the service manager waits before it starts
	// the agent again after it exited.
	RestartAfter = 5
)

// Definition is what the service runs: the agent (`thinkpol up`, with the
// node's defaults) and whether it connects at boot.
type Definition struct {
	// Binary is the thinkpol binary's absolute path.
	Binary string
	// ConnectOnBoot is THINKPOL_CONNECT: whether a device connects at
	// the boot's first start (PRD D5: off unless the member turns it on).
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
Environment=THINKPOL_CONNECT=%t
Restart=always
RestartSec=%d
KillMode=mixed
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
`, d.Binary, d.ConnectOnBoot, RestartAfter)
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
		<key>THINKPOL_CONNECT</key>
		<string>` + strconv.FormatBool(d.ConnectOnBoot) + `</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>` + strconv.Itoa(RestartAfter) + `</integer>
	<key>ExitTimeOut</key>
	<integer>60</integer>
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
