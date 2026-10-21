//go:build linux && !android

package supervisor

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/logring"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// worker is one space's worker across its restarts.
type worker struct {
	space   netmap.SpaceID
	slot    int
	link    string
	transit transit
	uid     uint32
	inbound map[string][]transport.PeerLink // under Supervisor.mu
	output  *logring.Ring
	cg      *cgroup // nil when cgroups are unavailable
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{} // closed once stopped and cleaned up
	notify  chan struct{} // config changed; coalesced
	// listenersChanged: the shared listeners changed; coalesced
	listenersChanged chan struct{}
	// egressChanged: the space's egress changed, for its namespace's
	// table; coalesced
	egressChanged chan struct{}

	mu        sync.Mutex
	config    []byte
	egress    EgressGrant
	dials     []Dial
	seeds     func() [][]byte
	pid       int
	ready     bool
	starts    int
	startedAt time.Time
	readyAt   time.Time
	nextStart time.Time
	lastExit  string
	// lastExitReason is lastExit's code.
	lastExitReason ExitReason
}

func (s *Supervisor) newWorker(sp Space, slot int) *worker {
	ctx, cancel := context.WithCancel(context.Background())
	w := &worker{
		space:   sp.ID,
		slot:    slot,
		link:    linkName(slot),
		transit: s.opts.transit(slot),
		uid:     s.opts.UIDBase + uint32(slot),
		egress:  sp.Egress,
		dials:   slices.Clone(sp.Dials),
		inbound: sp.Inbound,
		config:  sp.Config,
		seeds:   sp.Seeds,
		output:  logring.New(s.opts.OutputBytes),
		ctx:     ctx,
		cancel:  cancel,
		done:    make(chan struct{}),
		notify:  make(chan struct{}, 1),

		listenersChanged: make(chan struct{}, 1),
		egressChanged:    make(chan struct{}, 1),
	}
	if s.cgroups != nil {
		cg, err := s.cgroups.child(w.link, s.opts.MemoryMax, s.opts.PidsMax)
		if err != nil {
			s.log.Warn("creating a worker's cgroup", "space", w.space.String(), "err", err)
		} else {
			w.cg = cg
		}
	}
	return w
}

// setConfig stores a new config and its seeds, and signals the running
// worker to send them.
func (w *worker) setConfig(config []byte, seeds func() [][]byte) {
	w.mu.Lock()
	same := string(w.config) == string(config)
	w.config, w.seeds = config, seeds
	w.mu.Unlock()
	if !same {
		w.signal(w.notify)
	}
}

// setEgress stores the space's egress grant and dials; applyTables tells
// the running worker's loop once the root's tables follow.
func (w *worker) setEgress(e EgressGrant, dials []Dial) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.egress, w.dials = e, slices.Clone(dials)
}

// egressRules are the space's egress grant and dials.
func (w *worker) egressRules() (EgressGrant, []Dial) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.egress, slices.Clone(w.dials)
}

// signal wakes the worker's run loop through ch, coalescing.
func (w *worker) signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (w *worker) currentSeeds() func() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seeds
}

func (w *worker) currentConfig() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.config
}

func (w *worker) info() WorkerInfo {
	w.mu.Lock()
	defer w.mu.Unlock()
	return WorkerInfo{
		Space:          w.space,
		Link:           w.link,
		RootAddrs:      slices.Clone(w.transit.root[:]),
		SpaceAddrs:     slices.Clone(w.transit.space[:]),
		UID:            w.uid,
		PID:            w.pid,
		Ready:          w.ready,
		Starts:         w.starts,
		StartedAt:      w.startedAt,
		ReadyAt:        w.readyAt,
		NextStart:      w.nextStart,
		LastExit:       w.lastExit,
		LastExitReason: w.lastExitReason,
		OutputDropped:  w.output.Dropped(),
	}
}
