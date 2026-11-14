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
	// RestartAfterSeconds is how long the service manager waits before it
	// starts the agent again after it exited.
	RestartAfterSeconds = 5
	// StopTimeoutSeconds is how long a stop waits for the agent to take
	// its data plane down before it is killed (TimeoutStopSec, launchd's
	// ExitTimeOut).
	StopTimeoutSeconds = 60
)

// Definition is what the service runs: the agent, `thinkpol up -service`,
// with no other setting: the node's are in its node file, the member's
// (connect-on-boot among them) in the device's settings file.
type Definition struct {
	// Binary is the thinkpol binary's absolute path.
	Binary string
	// CrashTrace is where a device's agent's stderr goes, appended to
	// (agent.CrashTraceFile, which the agent empties at each start once it
	// has read it); "" for a server, whose stderr is the manager's: nowhere
	// under launchd, the journal under systemd (RESIDUAL-RISKS.md RR40).
	CrashTrace string
}

// SystemdUnit is the definition as a systemd unit.
func SystemdUnit(d Definition) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, `# Written by thinkpol service install; thinkpol service uninstall removes it.
# Settings: the node file (node.json in the state directory); connect-on-boot:
# thinkpol connect-on-boot on|off. Drop-ins are unsupported (thinkpol diag reports them).
[Unit]
Description=thinkpol node agent
After=network.target systemd-resolved.service
StartLimitIntervalSec=0

[Service]
ExecStart=%s up -service
# SIGHUP to the agent alone re-reads the map at once; a server's workers
# don't handle it, so never signal the whole unit.
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=%d
KillMode=mixed
TimeoutStopSec=%d
%s
[Install]
WantedBy=multi-user.target
`, d.Binary, RestartAfterSeconds, StopTimeoutSeconds, systemdStderr(d.CrashTrace))
	return b.Bytes()
}

// systemdStderr is the unit's stderr setting: a device's goes to its crash
// trace, appended (truncate: would empty it before the agent reads it);
// a server's stays the journal (RESIDUAL-RISKS.md RR40).
func systemdStderr(crashTrace string) string {
	if crashTrace == "" {
		return ""
	}
	return "# The crash trace: the agent reads the previous run's, then empties it.\nStandardError=append:" + crashTrace + "\n"
}

// LaunchdPlist is the definition as a launchd daemon's property list. It
// sets no StandardOutPath, and StandardErrorPath (launchd appends) only
// for a device's crash trace: the agent writes no log to disk (PRD S2),
// and its log is the local API's.
func LaunchdPlist(d Definition) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by thinkpol service install; thinkpol service uninstall removes it. -->
<!-- Settings: the node file (node.json in the state directory); connect-on-boot: thinkpol connect-on-boot on|off. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + escape(Label) + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + escape(d.Binary) + `</string>
		<string>up</string>
		<string>-service</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>` + strconv.Itoa(RestartAfterSeconds) + `</integer>
	<key>ExitTimeOut</key>
	<integer>` + strconv.Itoa(StopTimeoutSeconds) + `</integer>
`)
	if d.CrashTrace != "" {
		b.WriteString(`	<key>StandardErrorPath</key>
	<string>` + escape(d.CrashTrace) + `</string>
`)
	}
	b.WriteString(`</dict>
</plist>
`)
	return b.Bytes()
}

func escape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
