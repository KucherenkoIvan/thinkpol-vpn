package plan

import (
	"strings"
	"testing"
	"time"
)

func TestAPlanUndoesOnlyItsOwnChanges(t *testing.T) {
	base := Plan{Ticket: "TP-900", Budget: time.Minute}
	for name, tc := range map[string]struct {
		ops  []Op
		want string
	}{
		"an undo before any change":  {[]Op{UndoLast()}, "no change of the plan's"},
		"two undos after one change": {[]Op{Do(PfSkip("lo")), UndoLast(), UndoLast()}, "no change of the plan's"},
		"a change, then its undo":    {[]Op{Do(PfSkip("lo")), Read("pfctl", "-s", "rules"), UndoLast()}, ""},
		"a change without a kind":    {[]Op{Do(Change{})}, "without a kind"},
		"an empty read":              {[]Op{Read()}, "empty root read"},
	} {
		p := base
		p.Steps = []Step{{Name: "s", Ops: tc.ops}}
		err := p.Validate()
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, ok := Lookup([]Plan{base}, "tp-900"); !ok {
		t.Error("lookup in another case")
	}
}
