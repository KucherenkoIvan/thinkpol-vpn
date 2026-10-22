package routetable

import "net/netip"

// GuardReport is the leak guard as the host shows it, for diagnostics
// (`thinkpol diag`): read, never changed, by the firewall's inspector,
// whether or not a Guard runs (what a crash left shows too). A part that
// couldn't be read says why in its Unreadable; one that could is all
// there is.
type GuardReport struct {
	// Unreadable: why nothing of the guard could be read (no nf_tables,
	// no pfctl, an OS without a guard).
	Unreadable string
	// Where names the guard's place on the host: "nftables table inet
	// thinkpol-guard", "pf anchor com.apple/000.thinkpol".
	Where string
	// Present: the host holds the guard (the table exists; the anchor
	// lists rules). Without it the rest is empty. PresentUnknown: that
	// couldn't be told (the anchor's rules unreadable).
	Present, PresentUnknown bool
	// Rules are the guard's rules in order, as the host lists them, with
	// their counters.
	Rules           []GuardRuleReport
	RulesUnreadable string
	// Exempt is what the guard lets out of the physical interfaces by
	// destination (the exempt set or table), as the fewest prefixes.
	Exempt           []netip.Prefix
	ExemptUnreadable string
	// NFTables is the table's own state, on Linux.
	NFTables *NFTablesReport
	// PF is pf's state as it concerns the guard, on macOS.
	PF *PFReport
}

// GuardRuleReport is one rule of the guard as the host lists it.
type GuardRuleReport struct {
	// Chain is the nftables chain it is in (Linux).
	Chain string
	// Text is the rule as the host lists it: pfctl's line on macOS; on
	// Linux its expressions rendered nft-like (raw payloads as
	// `@nh,192,128`; an expression the renderer doesn't know shows as its
	// type).
	Text string
	// Counted: the rule has counters (on Linux only the rules with a
	// counter expression; on macOS every rule, read with -v).
	Counted        bool
	Packets, Bytes uint64
	// Evaluations and States are pf's (macOS).
	Evaluations, States uint64
}

// NFTablesReport is the guard table's own state.
type NFTablesReport struct {
	// Dormant: the table's chains are unhooked, so it guards nothing.
	Dormant          bool
	ChainsUnreadable string
	Chains           []NFTChainReport
}

// NFTChainReport is a chain of the guard's table.
type NFTChainReport struct {
	Name string
	// Hook ("output", or "" for a regular chain), Priority and Policy
	// ("accept", "drop") are a base chain's.
	Hook     string
	Priority int
	Policy   string
}

// PFReport is pf's state as it concerns the guard. Each part that
// couldn't be read says why.
type PFReport struct {
	Enabled           bool
	EnabledUnreadable string
	// GuardCheck is the guard's own check of the main ruleset: "hooked"
	// (`anchor "com.apple/*"` reached), "bypassed" (a quick pass above it),
	// "missing"; MainRules its evidence, the main ruleset's lines up to
	// the hook (all of them without one).
	GuardCheck string
	MainRules  []string
	// Skipped is every name pf lists as skipped (`set skip on`);
	// AnchorsBefore the anchors under com.apple that sort before the
	// guard's.
	Skipped, AnchorsBefore []string
	GuardCheckUnreadable   string
	// Reference is the `pfctl -E` reference the guard's record names, and
	// whether pf still lists it as taken by that process;
	// ReferenceUnreadable says why the record couldn't be read.
	Reference           *PFReferenceReport
	ReferenceUnreadable string
}

// PFReferenceReport is the guard's pf reference, by the pid of the pfctl
// that took it; the token, which names it to `pfctl -X`, stays in the
// record.
type PFReferenceReport struct {
	// Recorded: the guard's record names a reference (false: none, and
	// the rest is empty).
	Recorded bool
	// Stale: the record is of another boot session, and holds nothing
	// now. (A record that isn't a regular file or can't be parsed is
	// unreadable.)
	Stale bool
	Pid   int
	// PidOnly: the record names it by the pid alone (`pfctl -E` printed
	// no readable token and the lookup by pid hasn't found it yet).
	PidOnly bool
	// Held: pf lists the token as taken by that pid; HeldUnreadable says
	// why pf's listing couldn't tell.
	Held           bool
	HeldUnreadable string
}
