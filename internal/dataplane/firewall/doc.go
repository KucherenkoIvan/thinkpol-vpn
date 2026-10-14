// Package firewall keeps traffic from leaving around the tunnel where
// routing can't: the IPv6 leak guard, an adapter for routetable's Guard
// port that the agent composes with the route table (TP-021: nftables on
// Linux; pf on macOS once TP-019's data plane is in) and, later, the kill
// switch (TP-048: pf, nftables, WFP). Desktop-only: it imports routetable,
// never the other way round.
package firewall
