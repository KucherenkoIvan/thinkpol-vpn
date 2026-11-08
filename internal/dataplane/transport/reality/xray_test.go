package reality

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// xrayConfigPath is where lab/reality_xray_test.go, which starts a lab node
// and stock Xray's REALITY server beside it, writes this test's config
// before running it in the node. Without the lab or the config it skips.
const xrayConfigPath = "/run/reality-xray/config.json"

type xrayConfig struct {
	Server    string `json:"server"`     // Xray's REALITY inbound, ip:port
	Target    string `json:"target"`     // where this test's target listens: Xray's target
	PublicKey []byte `json:"public_key"` // Xray's X25519 public key
	ShortID   []byte `json:"short_id"`   // the short id Xray accepts
}

// TestStockXray is the two-handshake check against stock Xray: the dialer's
// seal verifies with the right short id, and a wrong one is spliced to the
// target, raw and whole, whose real certificate fails the dial.
func TestStockXray(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	raw, err := os.ReadFile(xrayConfigPath)
	if err != nil {
		t.Skipf("no stock Xray in this lab: %v", err)
	}
	var cfg xrayConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	tg := newTargetAt(t, cfg.Target)
	k := keys{public: cfg.PublicKey}
	tr := newTransport(Options{})

	t.Run("right short id", func(t *testing.T) {
		if _, err := dial(t, tr, cfg.Server, k, cfg.ShortID); err != nil {
			t.Fatalf("Xray didn't prove its key: %v", err)
		}
	})
	t.Run("wrong short id", func(t *testing.T) {
		wrong, _ := shortIDs()
		tp := newTap(t, cfg.Server)
		if _, err := dial(t, tr, tp.addr(), k, wrong); !errors.Is(err, ErrNotAuthenticated) {
			t.Fatalf("dial with a wrong short id: %v, want %v", err, ErrNotAuthenticated)
		}
		if !splicedWhole(tg, tp) {
			t.Error("the target didn't receive exactly what the dialer sent")
		}
	})
}
