package censor

// actionOf is a module's Decision as the engine applies it.
func actionOf(d Decision) Action {
	return Action{Verdict: d.Verdict, Hold: d.Hold, Held: d.Held, Reason: d.Reason}
}
