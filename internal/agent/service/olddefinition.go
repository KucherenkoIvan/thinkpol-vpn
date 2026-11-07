package service

import (
	"bytes"
	"fmt"
	"strconv"
)

// oldDefinitions are the definitions install wrote before connect-on-boot
// moved to the device's settings, with it on and with it off: an old
// definition that is neither was changed by hand too. Frozen: never
// change them with the current ones.
func oldDefinitions(sys System) [][]byte {
	var out [][]byte
	for _, on := range []string{"on", "off"} {
		switch sys.(type) {
		case Systemd:
			out = append(out, oldSystemdUnit(BinaryPath, on))
		case Launchd:
			out = append(out, oldLaunchdPlist(BinaryPath, on))
		}
	}
	return out
}

func oldSystemdUnit(binary, onOff string) []byte {
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
Environment=%s=%s
Restart=always
RestartSec=%d
KillMode=mixed
TimeoutStopSec=%d

[Install]
WantedBy=multi-user.target
`, binary, oldConnectOnBootVariable, onOff, RestartAfterSeconds, StopTimeoutSeconds)
	return b.Bytes()
}

func oldLaunchdPlist(binary, onOff string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by thinkpol service install; thinkpol service uninstall removes it. -->
<!-- Connect-on-boot: thinkpol service connect-on-boot on|off. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + escape(Label) + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + escape(binary) + `</string>
		<string>up</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>` + oldConnectOnBootVariable + `</key>
		<string>` + onOff + `</string>
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
}
