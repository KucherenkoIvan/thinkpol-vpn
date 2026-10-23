package safety

import "regexp"

func reads() map[string]readShape {
	return map[string]readShape{
		"pfctl": {pfctlPath, regexp.MustCompile(`^(-a [A-Za-z0-9._/*][A-Za-z0-9._/*-]* )?-s (rules|nat|info|Interfaces|References|Anchors|Tables|states|memory|timeouts)( -v| -vv)?$` +
			`|^-a [A-Za-z0-9._/][A-Za-z0-9._/-]* -t [A-Za-z0-9_]+ -T show$`)},
		"scutil":   {scutilPath, regexp.MustCompile(`^--dns$`)},
		"netstat":  {"/usr/sbin/netstat", regexp.MustCompile(`^-rn( -f inet6?)?$`)},
		"ifconfig": {"/sbin/ifconfig", regexp.MustCompile(`^(-l|[a-z]+[0-9]*)?$`)},
	}
}
