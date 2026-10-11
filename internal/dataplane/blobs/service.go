package blobs

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

const (
	// MaxBlobSize bounds one blob: lists are a few hundred KB (TP-016).
	MaxBlobSize = 16 << 20
	// MaxHeldSize bounds the current map's blobs together.
	MaxHeldSize = 64 << 20
	// DefaultServeRate is what a node serves to all its peers together,
	// in bytes per second.
	DefaultServeRate = 2 << 20
)

// Limits bound what a Service holds, serves and how hard it tries; zero
// fields take the defaults.
type Limits struct {
	// MaxBlob bounds one blob (MaxBlobSize), MaxHeld the current map's
	// blobs together (MaxHeldSize): larger ones, and those past the bound
	// in the map's order, are skipped.
	MaxBlob, MaxHeld int64
	// ServeRate is bytes per second served to all peers together
	// (DefaultServeRate).
	ServeRate int64
	// MaxConns bounds the connections served at once (16),
	// MaxConnsPerPeer those from one peer address (2). Past either, a
	// request is answered busy.
	MaxConns, MaxConnsPerPeer int
	// RetryMin and RetryMax pace the rounds of fetching while a blob is
	// missing: 2 s doubling to 1 min. ListenRetry is how soon a listener
	// that couldn't open is tried again (5 s).
	RetryMin, RetryMax, ListenRetry time.Duration
	// DialTimeout bounds a connection's setup through the tunnel (15 s,
	// which leaves room for WireGuard's handshake); IdleTimeout any wait
	// for the other end during a transfer (30 s).
	DialTimeout, IdleTimeout time.Duration
}

func (l Limits) withDefaults() Limits {
	def := func(v *int64, d int64) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&l.MaxBlob, MaxBlobSize)
	def(&l.MaxHeld, MaxHeldSize)
	def(&l.ServeRate, DefaultServeRate)
	defInt := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	defInt(&l.MaxConns, 16)
	defInt(&l.MaxConnsPerPeer, 2)
	defDur := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	defDur(&l.RetryMin, 2*time.Second)
	defDur(&l.RetryMax, time.Minute)
	defDur(&l.ListenRetry, 5*time.Second)
	defDur(&l.DialTimeout, 15*time.Second)
	defDur(&l.IdleTimeout, 30*time.Second)
	l.RetryMax = max(l.RetryMax, l.RetryMin)
	return l
}

// Store keeps blobs across a node's restarts. The Service checks whatever
// Load returns against the map before using it, and calls the Store from
// one goroutine at a time.
type Store interface {
	// Load returns what the store has for ref, nil if nothing.
	Load(ref netmap.BlobRef) []byte
	// Save keeps a checked blob.
	Save(ref netmap.BlobRef, data []byte) error
	// Prune drops every blob but keep's.
	Prune(keep []netmap.BlobRef) error
}

// Options configure a Service.
type Options struct {
	// Store keeps blobs across restarts; nil holds them in memory only.
	Store Store
	// Log gets the service's events; local only.
	Log    *slog.Logger
	Limits Limits

	// Listen and Dial replace the network (tests). By default the service
	// listens on and dials from the node's overlay addresses, bound to
	// Plan.Interface.
	Listen func(addr netip.AddrPort) (net.Listener, error)
	Dial   func(ctx context.Context, local netip.Addr, remote netip.AddrPort) (net.Conn, error)
	// Port replaces Port (tests).
	Port uint16
	// Now replaces time.Now (tests of the rate limit).
	Now func() time.Time
}

// Peer is a node the service may fetch from: a WireGuard peer, reached at
// its overlay addresses (tried in order).
type Peer struct {
	ID    netmap.NodeID
	Addrs []netip.Addr
}

// Plan is what the node's current map asks of the service.
type Plan struct {
	// Want are the blobs to hold, in priority order: a device's own (its
	// section's, named), a server's every blob of the header (the set it
	// passes on). Only blobs the header lists, with the same kind and
	// size, belong here.
	Want []netmap.BlobRef
	// Peers are where to fetch from, in order.
	Peers []Peer
	// Listen are the node's own overlay addresses: served on Port, and
	// the source addresses of fetches.
	Listen []netip.Addr
	// Interface is the overlay's TUN, to which every socket is bound.
	Interface string
}

// Status is what a service holds and did: counts only, nothing from the
// map or about peers, so it may go into telemetry.
type Status struct {
	// Wanted is how many blobs the map asks for (within the limits),
	// Held how many of them the node holds, Skipped how many it won't
	// (over a limit), Failed how many the map names wrongly (they match
	// their reference but don't decode).
	Wanted, Held, Skipped, Failed int
	// Fetched counts blobs fetched from peers, Loaded those taken from
	// the store, Rejected what peers sent that didn't check, and
	// StoreRejected what the store had that didn't.
	Fetched, Loaded, Rejected, StoreRejected uint64
	// Served counts blobs (ServedBytes their bytes) sent to peers,
	// NotHere requests for what the node doesn't hold, Busy requests
	// refused for lack of room.
	Served, ServedBytes, NotHere, Busy uint64
}

// Service holds, fetches and serves the blobs a node's map asks for.
type Service struct {
	o      Options
	limits Limits
	log    *slog.Logger
	port   uint16
	now    func() time.Time
	rate   *limiter

	mu      sync.Mutex
	plan    Plan
	gen     uint64
	want    map[[32]byte]netmap.BlobRef
	skipped int
	held    map[[32]byte]netmap.BlobRef
	data    map[[32]byte][]byte
	// failed are wanted blobs that match their reference and don't
	// decode: not fetched again for this plan.
	failed map[[32]byte]bool
	// stored are wanted blobs already looked for in the store under this
	// plan: the store is asked once per plan.
	stored map[[32]byte]bool
	conns  map[netip.Addr]int
	nconns int
	st     Status

	wakeFetch, wakeListen, changed chan struct{}
}

// New makes a service holding nothing; Update gives it a plan, Run runs it.
func New(o Options) *Service {
	s := &Service{
		o:          o,
		limits:     o.Limits.withDefaults(),
		log:        o.Log,
		port:       o.Port,
		now:        o.Now,
		want:       map[[32]byte]netmap.BlobRef{},
		held:       map[[32]byte]netmap.BlobRef{},
		data:       map[[32]byte][]byte{},
		failed:     map[[32]byte]bool{},
		stored:     map[[32]byte]bool{},
		conns:      map[netip.Addr]int{},
		wakeFetch:  make(chan struct{}, 1),
		wakeListen: make(chan struct{}, 1),
		changed:    make(chan struct{}, 1),
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.port == 0 {
		s.port = Port
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.rate = newLimiter(s.limits.ServeRate, s.now)
	return s
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// Update replaces the plan: what to hold, where to fetch it, where to
// serve. Blobs the previous plan held stay held, and served, until every
// blob of the new one is held.
func (s *Service) Update(p Plan) {
	p.Want = slices.Clone(p.Want)
	p.Peers = slices.Clone(p.Peers)
	p.Listen = slices.Clone(p.Listen)
	s.mu.Lock()
	s.plan = p
	s.gen++
	previous := s.want
	s.want = map[[32]byte]netmap.BlobRef{}
	s.failed = map[[32]byte]bool{}
	s.stored = map[[32]byte]bool{}
	s.skipped = 0
	var total int64
	for _, ref := range p.Want {
		if _, dup := s.want[ref.SHA256]; dup {
			continue
		}
		size := int64(min(ref.Size, uint64(s.limits.MaxBlob)+1))
		switch {
		case size > s.limits.MaxBlob:
			s.skipped++
			s.log.Warn("blob skipped: larger than a node holds", "blob", short(ref), "kind", ref.Kind, "size", ref.Size, "limit", s.limits.MaxBlob)
		case total+size > s.limits.MaxHeld:
			s.skipped++
			s.log.Warn("blob skipped: the map's blobs together are more than a node holds", "blob", short(ref), "kind", ref.Kind, "size", ref.Size, "limit", s.limits.MaxHeld)
		default:
			total += size
			s.want[ref.SHA256] = ref
			if _, ok := s.held[ref.SHA256]; ok {
				s.held[ref.SHA256] = ref // the current name
			}
		}
	}
	// What the new plan doesn't want stays only as a stand-in: a named
	// blob while the plan wants one of its kind and name, an unnamed one
	// (a server's) for one plan.
	for sha, ref := range s.held {
		if _, ok := s.want[sha]; ok {
			continue
		}
		_, wasWanted := previous[sha]
		if ref.Name != "" && s.wantsNameLocked(ref.Kind, ref.Name) || ref.Name == "" && wasWanted {
			continue
		}
		delete(s.held, sha)
		delete(s.data, sha)
		signal(s.changed)
	}
	s.mu.Unlock()
	signal(s.wakeFetch)
	signal(s.wakeListen)
}

// Run fetches, keeps and serves blobs until ctx ends, then closes its
// listeners and the connections it serves.
func (s *Service) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.fetchLoop(ctx) }()
	go func() { defer wg.Done(); s.listenLoop(ctx) }()
	wg.Wait()
}

// Get returns the blob with this SHA-256 if the service holds it (checked;
// the caller must not modify it).
func (s *Service) Get(sha [32]byte) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.data[sha]
	return d, ok
}

// Latest returns the blob the current plan names name, of that kind, or,
// while that one isn't held yet, the one of the same kind and name the
// previous plan held: a list in use is replaced only once its successor
// is verified.
func (s *Service) Latest(kind netmap.BlobKind, name string) (netmap.BlobRef, []byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var fallback netmap.BlobRef
	found := false
	for sha, ref := range s.held {
		if ref.Kind != kind || ref.Name != name {
			continue
		}
		if _, current := s.want[sha]; current {
			return ref, s.data[sha], true
		}
		fallback, found = ref, true
	}
	if !found {
		return netmap.BlobRef{}, nil, false
	}
	return fallback, s.data[fallback.SHA256], true
}

// Changed is signalled whenever the set of held blobs changes.
func (s *Service) Changed() <-chan struct{} { return s.changed }

// Status is what the service holds and did.
func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	st.Wanted, st.Skipped, st.Failed = len(s.want), s.skipped, len(s.failed)
	for sha := range s.want {
		if _, ok := s.held[sha]; ok {
			st.Held++
		}
	}
	return st
}

// short names a blob in the log by the start of its hash.
func short(ref netmap.BlobRef) string { return hex.EncodeToString(ref.SHA256[:6]) }

// missing is what the plan of generation gen still needs: the wanted
// blobs neither held nor failed, in the plan's order, and whether the
// plan is complete (everything held; failed blobs keep it incomplete).
func (s *Service) missing() (refs []netmap.BlobRef, gen uint64, complete bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	complete = len(s.failed) == 0
	for _, ref := range s.plan.Want {
		w, ok := s.want[ref.SHA256]
		if !ok || w != ref || slices.ContainsFunc(refs, func(r netmap.BlobRef) bool { return r.SHA256 == ref.SHA256 }) {
			continue
		}
		if _, held := s.held[ref.SHA256]; held || s.failed[ref.SHA256] {
			continue
		}
		refs = append(refs, ref)
		complete = false
	}
	return refs, s.gen, complete
}

func (s *Service) current(gen uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen == gen
}

// hold adds a checked blob if the current plan still wants it.
func (s *Service) hold(ref netmap.BlobRef, data []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.want[ref.SHA256]
	if !ok {
		return false
	}
	s.held[ref.SHA256], s.data[ref.SHA256] = w, data
	// It replaces any stand-in of its kind and name.
	for sha, old := range s.held {
		if _, wanted := s.want[sha]; !wanted && w.Name != "" && old.Kind == w.Kind && old.Name == w.Name {
			delete(s.held, sha)
			delete(s.data, sha)
		}
	}
	signal(s.changed)
	return true
}

func (s *Service) wantsNameLocked(kind netmap.BlobKind, name string) bool {
	for _, ref := range s.want {
		if ref.Kind == kind && ref.Name == name {
			return true
		}
	}
	return false
}

// firstLook reports whether the store is yet to be asked for ref under
// the plan of generation gen, and notes that it now is.
func (s *Service) firstLook(gen uint64, ref netmap.BlobRef) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen || s.stored[ref.SHA256] {
		return false
	}
	s.stored[ref.SHA256] = true
	return true
}

func (s *Service) fail(gen uint64, ref netmap.BlobRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen == gen {
		s.failed[ref.SHA256] = true
	}
}

// complete drops what the previous plans left once the plan of generation
// gen holds everything, and returns what is kept (false: the plan changed
// meanwhile).
func (s *Service) complete(gen uint64) ([]netmap.BlobRef, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		return nil, false
	}
	var keep []netmap.BlobRef
	dropped := false
	for sha, ref := range s.held {
		if _, ok := s.want[sha]; ok {
			keep = append(keep, ref)
			continue
		}
		delete(s.held, sha)
		delete(s.data, sha)
		dropped = true
	}
	if dropped {
		signal(s.changed)
	}
	return keep, true
}

func (s *Service) snapshot() Plan {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.plan
}

func (s *Service) count(f func(st *Status)) {
	s.mu.Lock()
	f(&s.st)
	s.mu.Unlock()
}

// fetchLoop gets what the plan lacks, a round at a time: from the store,
// else from the peers in order. Rounds that leave something missing are
// repeated with backoff; a new plan starts one at once.
func (s *Service) fetchLoop(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	var backoff time.Duration
	var pruned uint64 // the generation last pruned
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wakeFetch:
			backoff = 0
		case <-timer.C:
		}
		refs, gen, _ := s.missing()
		for _, ref := range refs {
			if ctx.Err() != nil || !s.current(gen) {
				break
			}
			s.obtain(ctx, gen, ref)
		}
		if ctx.Err() != nil {
			return
		}
		if !s.current(gen) {
			continue // the new plan's wake is pending
		}
		refs, _, complete := s.missing()
		if complete {
			timer.Stop()
			if pruned == gen {
				continue
			}
			if keep, ok := s.complete(gen); ok {
				pruned = gen
				if s.o.Store != nil {
					if err := s.o.Store.Prune(keep); err != nil {
						s.log.Warn("pruning stored blobs", "err", err)
					}
				}
			}
			continue
		}
		if len(refs) == 0 {
			continue // only failed blobs: nothing to retry until the map changes
		}
		backoff = min(max(2*backoff, s.limits.RetryMin), s.limits.RetryMax)
		timer.Reset(backoff)
		s.log.Debug("blobs missing, retrying", "missing", len(refs), "in", backoff)
	}
}

// obtain gets one blob: from the store if it has a good copy, else from
// the first peer that sends one that checks.
func (s *Service) obtain(ctx context.Context, gen uint64, ref netmap.BlobRef) {
	if s.o.Store != nil && s.firstLook(gen, ref) {
		if data := s.o.Store.Load(ref); data != nil {
			err := Check(ref, data)
			switch {
			case err == nil:
				if s.hold(ref, data) {
					s.count(func(st *Status) { st.Loaded++ })
					s.log.Debug("blob loaded", "blob", short(ref), "kind", ref.Kind, "name", ref.Name)
				}
				return
			case errors.Is(err, ErrUndecodable):
				s.fail(gen, ref)
				s.log.Error("the map names a blob that is not a valid one of its kind", "blob", short(ref), "kind", ref.Kind, "name", ref.Name, "err", err)
				return
			default:
				s.count(func(st *Status) { st.StoreRejected++ })
				s.log.Warn("stored blob rejected: it doesn't match the map; fetching it again", "blob", short(ref), "kind", ref.Kind, "name", ref.Name)
			}
		}
	}
	p := s.snapshot()
	for _, peer := range p.Peers {
		if ctx.Err() != nil || !s.current(gen) {
			return
		}
		data, err := s.fetchFrom(ctx, p, peer, ref)
		if err == nil {
			err = Check(ref, data)
		}
		switch {
		case err == nil:
			if !s.hold(ref, data) {
				return
			}
			s.count(func(st *Status) { st.Fetched++ })
			s.log.Info("blob fetched", "blob", short(ref), "kind", ref.Kind, "name", ref.Name, "size", ref.Size, "peer", peer.ID)
			if s.o.Store != nil {
				if err := s.o.Store.Save(ref, data); err != nil {
					s.log.Warn("storing a blob", "blob", short(ref), "err", err)
				}
			}
			return
		case errors.Is(err, ErrUndecodable):
			s.fail(gen, ref)
			s.log.Error("the map names a blob that is not a valid one of its kind", "blob", short(ref), "kind", ref.Kind, "name", ref.Name, "err", err)
			return
		case errors.Is(err, ErrMismatch), errors.Is(err, errProtocol):
			s.count(func(st *Status) { st.Rejected++ })
			s.log.Warn("blob rejected: the peer sent something else; trying another peer", "blob", short(ref), "kind", ref.Kind, "name", ref.Name, "peer", peer.ID, "err", err)
		default:
			s.log.Debug("blob not fetched from peer", "blob", short(ref), "peer", peer.ID, "err", err)
		}
	}
}
