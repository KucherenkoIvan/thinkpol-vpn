package safety

import (
	"encoding/json"
	"errors"
)

// KindPfMain is the macOS pf action's kind; Linux has none.
const KindPfMain = "pf-main"

func decodePfMain(json.RawMessage) (Action, error) {
	return nil, errors.New("pf-main: macOS only")
}
