//go:build linux

package censor

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
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
	// serveQueue returns once the queue is closed and its callback has
	// returned, so nothing publishes to the active modules' channels when
	// Shutdown closes them.
	err := serveQueue(ctx, cfg, eng)
	eng.Shutdown()
	if n := eng.Unnoticed(); n > 0 {
		log.Printf("censor: %d new flows never reached an active module (its channel was full)", n)
	}
	return err
}

// serveQueue opens the queue and serves it with the engine. The queue rule
// itself is the caller's (Run's forward hook; tests queue output instead).
func serveQueue(ctx context.Context, cfg Config, eng *Engine) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	nf, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      cfg.Queue,
		MaxPacketLen: 0xffff,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("censor: open queue %d: %w", cfg.Queue, err)
	}
	defer func() { _ = nf.Close() }()
	// ENOBUFS on a full socket buffer must not stop the receive loop.
	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		return fmt.Errorf("censor: netlink option: %w", err)
	}

	rst, err := newRSTSender()
	if err != nil {
		return err
	}
	defer rst.close()

	var applyMu sync.Mutex
	var applyErr error
	failed := func(err error) int {
		if ctx.Err() != nil {
			return 0
		}
		log.Printf("censor: queue: %v", err)
		applyMu.Lock()
		applyErr = err
		applyMu.Unlock()
		cancel()
		return 1
	}
	err = nf.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		if a.PacketID == nil || a.Payload == nil {
			return 0
		}
		id := *a.PacketID
		ip := *a.Payload
		if isFragment(ip) {
			log.Printf("censor: a fragment escaped reassembly, dropping it")
			setVerdict(nf, id, Drop)
			return 0
		}
		p, ok := decodePacket(ip)
		if !ok {
			// Malformed: nothing for a module to judge, and the
			// receiver's stack discards it anyway.
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
	applyMu.Lock()
	err = applyErr
	applyMu.Unlock()
	return err
}

// decide applies the engine's action: a verdict for the kernel, after
// the RSTs the censor sends itself for Reset. Nothing waits: a throttled
// packet is already accepted or dropped by its flow's policer.
func decide(eng *Engine, rst *rstSender, p *Packet, setVerdict func(Verdict)) {
	a := eng.Handle(p)
	if a.Verdict == Reset {
		if err := rst.send(p); err != nil {
			log.Printf("censor: %s: RST: %v", p, err)
		}
		setVerdict(Drop)
		return
	}
	setVerdict(a.Verdict)
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
// queue, whole: the ct match makes the kernel turn on conntrack and its
// defragmentation in this network namespace for both families (it
// reassembles before the forward hook), so modules see whole datagrams,
// not a first fragment whose rest passes unjudged. A fragment that still
// arrives escaped reassembly and is dropped, counted; the masks leave DF
// out, which nearly every TCP segment carries. The router forwards only the
// lab's own traffic, so the rule needs no match of its own.
func installQueueRule(queue uint16) error {
	removeQueueRule()
	rule := fmt.Sprintf(`
table inet %s {
  chain forward {
    type filter hook forward priority filter; policy accept;
    ct state invalid counter
    ip frag-off & 0x3fff != 0 counter drop
    exthdr frag exists counter drop
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
