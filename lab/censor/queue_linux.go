//go:build linux

package censor

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"
)

// table is the nftables table the censor owns in the router. It is deleted
// again on shutdown; a stale one from an unclean stop is deleted at start.
const table = "censor"

// Run drives the censor: it installs the router's queue rule, serves the
// queue with the engine until ctx is done, and removes the rule after. It
// logs "censor ready" once packets are being served.
func Run(ctx context.Context, cfg Config, eng *Engine) error {
	if err := installQueueRule(cfg.Queue); err != nil {
		return err
	}
	defer removeQueueRule()
	return serveQueue(ctx, cfg, eng)
}

// serveQueue opens the queue and serves it with the engine. The queue rule
// itself is the caller's (Run's forward hook; tests queue output instead).
func serveQueue(ctx context.Context, cfg Config, eng *Engine) error {
	nf, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      cfg.Queue,
		MaxPacketLen: 0xffff,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("censor: open queue %d: %w", cfg.Queue, err)
	}
	defer nf.Close()
	// A full socket buffer must not kill the receive loop; the missed
	// packets stay queued.
	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		return fmt.Errorf("censor: netlink option: %w", err)
	}

	rst, err := newRSTSender()
	if err != nil {
		return err
	}
	defer rst.close()

	var applyErr error
	failed := func(err error) int {
		if ctx.Err() != nil {
			return 0
		}
		log.Printf("censor: queue: %v", err)
		applyErr = err
		return 1
	}
	err = nf.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		if a.PacketID == nil || a.Payload == nil {
			return 0
		}
		id := *a.PacketID
		p, ok := decodePacket(*a.Payload)
		if !ok {
			setVerdict(nf, id, Accept)
			return 0
		}
		setVerdictFor := func(v Verdict) { setVerdict(nf, id, v) }
		decide(eng, rst, &p, setVerdictFor)
		return 0
	}, failed)
	if err != nil {
		return fmt.Errorf("censor: register on queue %d: %w", cfg.Queue, err)
	}
	log.Printf("censor ready: queue=%d", cfg.Queue)
	<-ctx.Done()
	return applyErr
}

// decide applies the engine's action: mostly a verdict for the kernel,
// once a RST the censor sends itself first, once a held packet whose
// verdict comes later from another goroutine, which the netlink conn
// tolerates.
func decide(eng *Engine, rst *rstSender, p *Packet, setVerdict func(Verdict)) {
	a := eng.Handle(p)
	switch a.Verdict {
	case Reset:
		if err := rst.send(p); err != nil {
			log.Printf("censor: %s: RST: %v", p, err)
		}
		setVerdict(Drop)
	case Throttle:
		held, hold := a.Held, a.Hold
		go func() {
			time.Sleep(hold)
			setVerdict(held)
		}()
	default:
		setVerdict(a.Verdict)
	}
}

func setVerdict(nf *nfqueue.Nfqueue, id uint32, v Verdict) {
	nfv := nfqueue.NfDrop
	if v == Accept {
		nfv = nfqueue.NfAccept
	}
	if err := nf.SetVerdict(id, nfv); err != nil {
		log.Printf("censor: verdict for packet %d: %v", id, err)
	}
}

// installQueueRule sends every forwarded packet, IPv4 and IPv6, to the
// queue. The router forwards only the lab's own traffic, so the rule needs
// no match of its own.
func installQueueRule(queue uint16) error {
	removeQueueRule()
	rule := fmt.Sprintf(`
table inet %s {
  chain forward {
    type filter hook forward priority filter; policy accept;
    queue num %d
  }
}
`, table, queue)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rule)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("censor: nftables: %w: %s", err, out)
	}
	return nil
}

func removeQueueRule() {
	_ = exec.Command("nft", "delete", "table", "inet", table).Run()
}
