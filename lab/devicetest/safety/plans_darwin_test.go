package safety

import (
	"encoding/json"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plans"
)

// Every read and change a plan lists is one the core runs: a plan never
// meets a refusal on the owner's Mac that a test could have shown.
func TestEveryPlansReadsAndChangesAreTheCores(t *testing.T) {
	for _, p := range plans.All() {
		for _, st := range p.Steps {
			for _, op := range st.Ops {
				var err error
				switch op.Kind {
				case plan.OpRead:
					_, err = rootRead(op.Argv)
				case plan.OpDo:
					params, _ := json.Marshal(op.Change.Params)
					_, err = decode(Spec{Kind: op.Change.Kind, Params: params})
				}
				if err != nil {
					t.Errorf("%s %s: %v", p.Ticket, st.Name, err)
				}
			}
		}
	}
}
