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
	// MaxHeldSize bounds a device's blobs of the current map together.
	MaxHeldSize = 64 << 20
	// ServerMaxHeldSize bounds a server's: the header's whole set, held in
	// a worker's memory per space it serves. A map builder keeps the
	// header within it.
	ServerMaxHeldSize = 16 << 20
	// DefaultServeRate is what a node serves to all its peers together,
	// in bytes per second.
	DefaultServeRate = 2 << 20
	// DefaultMinRate is the slowest a transfer may go, on average, before
	// it is given up.
	DefaultMinRate = 16 << 10
)

// Limits bound what a Service holds, serves and how hard it tries; zero
// fields take the defaults.
type Limits struct {
	// MaxBlob bounds one blob (MaxBlobSize), MaxHeld the current map's
	// blobs together (MaxHeldSize): larger ones, and those past the bound
	// in the map's order, are skipped.
	MaxBlob, MaxHeld int64
	// ServeRate is bytes per second served to all peers together
	// (DefaultServeRate). MinRate is the average rate below which a
	// transfer is abandoned, either way (DefaultMinRate): a transfer of n
	// bytes gets DialTimeout + n/MinRate in all.
	ServeRate, MinRate int64
	// MaxConns bounds the connections served at once (16),
	// MaxConnsPerPeer those from one peer (2). Past either, a request is
	// answered busy.
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
	def(&l.MinRate, DefaultMinRate)
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

// transferTimeout is how long moving n bytes may take in all.
func (l Limits) transferTimeout(n uint64, rate int64) time.Duration {
	return l.DialTimeout + time.Duration(float64(n)/float64(rate)*float64(time.Second))
}

// Store keeps the blobs a node uses (named in its section) across its
// restarts; the set a server only passes on stays in memory. The Service
// checks whatever the store returns against the map before using it, and
// calls the store from one goroutine at a time.
type Store interface {
	// Load returns what the store has for ref, nil if nothing.
	Load(ref netmap.BlobRef) []byte
	// Save keeps a checked, named blob.
	Save(ref netmap.BlobRef, data []byte) error
	// Prune drops every blob but keep's.
	Prune(keep []netmap.BlobRef) error
	// Index is what the store holds, as named when saved: where the
	// previous version of a list comes from after a restart, while the
	// current map's isn't held yet.
	Index() []netmap.BlobRef
}

// Options configure a Service.
type Options struct {
	// Store keeps blobs across restarts; nil holds them in memory only.
	Store Store
	// Log gets the service's events; local only.
	Log    *slog.Logger
	Limits Limits
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
	// Local are the node's own overlay addresses, the sources of fetches.
	Local []netip.Addr
	// Listen are the addresses served on Port: a server's overlay
	// addresses; none on a device, which only fetches.
	Listen []netip.Addr
	// Interface is the overlay's TUN, to which every socket is bound.
	Interface string
	// Skipped are the section's blobs PlanFrom left out, and why: for the
	// log.
	Skipped []Skipped
}

// Skipped is a blob of the section a plan leaves out.
type Skipped struct {
	Ref    netmap.BlobRef
	Reason string
}

// Status is what a service holds and did: counts only, nothing from the
// map or about peers, so it may go into telemetry.
type Status struct {
	// Wanted is how many blobs the map asks for (within the limits),
	// Held how many of them the node holds, StandIns how many previous
	// versions it holds while their successors aren't, Skipped how many
	// it won't (over a limit), Failed how many the map names wrongly
	// (they match their reference but don't decode).
	Wanted, Held, StandIns, Skipped, Failed int
	// Fetched counts blobs fetched from peers, Loaded those taken from
	// the store, Rejected what peers sent that didn't check, and
	// StoreRejected what the store had that didn't. Abandoned counts
	// transfers given up as too slow or overtaken by a new map.
	Fetched, Loaded, Rejected, StoreRejected, Abandoned uint64
	// Served counts blobs (ServedBytes their bytes) sent to peers,
	// NotHere requests for what the node doesn't hold, Busy requests
	// refused for lack of room, NotPeer connections from no peer, closed
	// unanswered.
	Served, ServedBytes, NotHere, Busy, NotPeer uint64
}

// Net replaces the node's network for a service (tests and labs): a
// loopback overlay stands in for the overlay's TUN, whose sockets Listen
// and Dial would otherwise be bound to (see openListener and openConn).
// The zero value is the node's real network.
type Net struct {
	Listen func(addr netip.AddrPort) (net.Listener, error)
	Dial   func(ctx context.Context, local netip.Addr, remote netip.AddrPort) (net.Conn, error)
}

// Service holds, fetches and serves the blobs a node's map asks for.
type Service struct {
	store  Store
	limits Limits
	log    *slog.Logger
	// net is the service's network: a loopback overlay in tests and labs,
	// the node's real network (both functions nil) in production.
	net  Net
	rate *limiter

	mu   sync.Mutex
	plan Plan
	// peerOf is the plan's peers by overlay address, built with the plan
	// in Update: who may be served (admit, and every chunk after).
	peerOf  map[netip.Addr]string
	gen     uint64
	want    map[[32]byte]netmap.BlobRef
	skipped int
	// held are checked blobs: the current plan's, and stand-ins (blobs no
	// longer wanted, kept until their successor is held).
	held map[[32]byte]netmap.BlobRef
	data map[[32]byte][]byte
	// failed are wanted blobs that match their reference and don't
	// decode: not fetched again for this plan.
	failed map[[32]byte]bool
	// stored are wanted blobs already looked for in the store under this
	// plan, standIns whether its index was searched: once per plan.
	stored   map[[32]byte]bool
	standIns uint64 // the generation whose stand-ins were looked for
	// cancelFetch ends the transfer under way when the plan changes.
	cancelFetch context.CancelFunc
	conns       map[string]int
	nconns      int
	st          Status
	subscribers []chan struct{}

	wakeFetch, wakeListen chan struct{}
}

// New makes a service on the node's real network; Update gives it a plan,
// Run runs it.
func New(o Options) *Service {
	return NewOnNet(o, Net{})
}

// NewOnNet is New on n instead of the node's real network: the listener
// and dialer of a lab's loopback overlay. A Net with exactly one of the
// two functions set has no meaning and panics.
func NewOnNet(o Options, n Net) *Service {
	if (n.Listen == nil) != (n.Dial == nil) {
		panic("blobs: a Net sets both Listen and Dial, or neither")
	}
	s := &Service{
		store:      o.Store,
		limits:     o.Limits.withDefaults(),
		log:        o.Log,
		net:        n,
		want:       map[[32]byte]netmap.BlobRef{},
		held:       map[[32]byte]netmap.BlobRef{},
		data:       map[[32]byte][]byte{},
		failed:     map[[32]byte]bool{},
		stored:     map[[32]byte]bool{},
		conns:      map[string]int{},
		wakeFetch:  make(chan struct{}, 1),
		wakeListen: make(chan struct{}, 1),
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	s.rate = newLimiter(s.limits.ServeRate, time.Now)
	return s
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// Subscribe returns a channel of its own, signalled (coalescing) whenever
// what Get or Latest return changes: a blob held or dropped, or a held
// blob renamed by a new map.
func (s *Service) Subscribe() <-chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.subscribers = append(s.subscribers, ch)
	s.mu.Unlock()
	return ch
}

func (s *Service) changedLocked() {
	for _, ch := range s.subscribers {
		signal(ch)
	}
}

func (s *Service) dropLocked(sha [32]byte) {
	delete(s.held, sha)
	delete(s.data, sha)
	s.changedLocked()
}

// Update replaces the plan: what to hold, where to fetch it, where to
// serve. Blobs the previous plan held stay held, and served, until every
// blob of the new one is held. A transfer under way is abandoned.
func (s *Service) Update(p Plan) {
	p.Want = slices.Clone(p.Want)
	p.Peers = slices.Clone(p.Peers)
	p.Local = slices.Clone(p.Local)
	p.Listen = slices.Clone(p.Listen)
	for _, sk := range p.Skipped {
		s.log.Warn("blob left out of the plan", "blob", short(sk.Ref), "kind", sk.Ref.Kind, "name", sk.Ref.Name, "reason", sk.Reason)
	}
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		signal(s.wakeFetch)
		signal(s.wakeListen)
	}()
	if s.cancelFetch != nil {
		s.cancelFetch()
		s.cancelFetch = nil
	}
	s.plan = p
	s.peerOf = map[netip.Addr]string{}
	for _, peer := range p.Peers {
		for _, a := range peer.Addrs {
			if _, dup := s.peerOf[a.Unmap()]; !dup {
				s.peerOf[a.Unmap()] = peer.ID.String()
			}
		}
	}
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
			continue
		case total+size > s.limits.MaxHeld:
			s.skipped++
			s.log.Warn("blob skipped: the map's blobs together are more than this node holds", "blob", short(ref), "kind", ref.Kind, "size", ref.Size, "limit", s.limits.MaxHeld)
			continue
		}
		total += size
		s.want[ref.SHA256] = ref
		old, ok := s.held[ref.SHA256]
		switch {
		case !ok || old == ref:
		case old.Kind != ref.Kind && Check(ref, s.data[ref.SHA256]) != nil:
			// The same bytes under another kind are checked as that kind.
			s.dropLocked(ref.SHA256)
		default:
			s.held[ref.SHA256] = ref // the current kind and name
			s.changedLocked()
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
		s.dropLocked(sha)
	}
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
// while that one isn't held yet, the one of the same kind and name held
// before (from the previous map, or from the store's index after a
// restart): a list in use is replaced only once its successor is verified.
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

// Status is what the service holds and did.
func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	st.Wanted, st.Skipped, st.Failed = len(s.want), s.skipped, len(s.failed)
	for sha := range s.held {
		if _, ok := s.want[sha]; ok {
			st.Held++
		} else {
			st.StandIns++
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

// hold adds a checked blob if the current plan still wants it, and counts
// it with counted under the same lock: a blob Get returns is already in
// Status.
func (s *Service) hold(ref netmap.BlobRef, data []byte, counted func(st *Status)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.want[ref.SHA256]
	if !ok || w.Kind != ref.Kind {
		return false
	}
	counted(&s.st)
	s.held[ref.SHA256], s.data[ref.SHA256] = w, data
	// It replaces any stand-in of its kind and name.
	for sha, old := range s.held {
		if _, wanted := s.want[sha]; !wanted && w.Name != "" && old.Kind == w.Kind && old.Name == w.Name {
			delete(s.held, sha)
			delete(s.data, sha)
		}
	}
	s.changedLocked()
	return true
}

// holdStandIn adds a checked blob from the store's index as the stand-in
// for a named blob the plan of generation gen wants and doesn't hold yet,
// unless something of that kind and name is held already.
func (s *Service) holdStandIn(gen uint64, ref netmap.BlobRef, data []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen || !s.wantsNameLocked(ref.Kind, ref.Name) {
		return false
	}
	if _, wanted := s.want[ref.SHA256]; wanted {
		return false // the store is asked for wanted blobs directly
	}
	for _, h := range s.held {
		if h.Kind == ref.Kind && h.Name == ref.Name {
			return false
		}
	}
	s.held[ref.SHA256], s.data[ref.SHA256] = ref, data
	s.changedLocked()
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
// gen holds everything, and returns what is kept and named, what the
// store keeps (false: the plan changed meanwhile).
func (s *Service) complete(gen uint64) ([]netmap.BlobRef, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		return nil, false
	}
	var keep []netmap.BlobRef
	for sha, ref := range s.held {
		if _, ok := s.want[sha]; !ok {
			s.dropLocked(sha)
		} else if ref.Name != "" {
			keep = append(keep, ref)
		}
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

// fetchContext is ctx, ended also when the plan of generation gen is
// replaced (false: it already was).
func (s *Service) fetchContext(ctx context.Context, gen uint64) (context.Context, context.CancelFunc, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		return nil, nil, false
	}
	fctx, cancel := context.WithCancel(ctx)
	s.cancelFetch = cancel
	return fctx, cancel, true
}

// fetchLoop gets what the plan lacks, a round at a time: stand-ins from
// the store's index once per plan, then each missing blob from the store,
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
		if len(refs) > 0 {
			s.loadStandIns(gen)
		}
		for _, ref := range refs {
			if ctx.Err() != nil || !s.current(gen) {
				break
			}
			fctx, cancel, ok := s.fetchContext(ctx, gen)
			if !ok {
				break
			}
			s.obtain(fctx, gen, ref)
			cancel()
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
				if s.store != nil {
					if err := s.store.Prune(keep); err != nil {
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

// loadStandIns holds, once per plan, the previous versions the store's
// index has of the named blobs the plan wants and doesn't hold: after a
// restart they stand in until their successors are verified.
func (s *Service) loadStandIns(gen uint64) {
	s.mu.Lock()
	first := s.standIns != gen
	s.standIns = gen
	s.mu.Unlock()
	if !first || s.store == nil {
		return
	}
	for _, ref := range s.store.Index() {
		if ref.Name == "" || !s.current(gen) {
			continue
		}
		s.mu.Lock()
		_, wanted := s.want[ref.SHA256]
		needed := !wanted && s.wantsNameLocked(ref.Kind, ref.Name)
		s.mu.Unlock()
		if !needed {
			continue
		}
		data := s.store.Load(ref)
		if data == nil || Check(ref, data) != nil {
			continue
		}
		if s.holdStandIn(gen, ref, data) {
			s.log.Info("previous blob in use until its successor is verified", "blob", short(ref), "kind", ref.Kind, "name", ref.Name)
		}
	}
}

// obtain gets one blob: from the store if it has a good copy, else from
// the first peer that sends one that checks.
func (s *Service) obtain(ctx context.Context, gen uint64, ref netmap.BlobRef) {
	if s.store != nil && s.firstLook(gen, ref) {
		if data := s.store.Load(ref); data != nil {
			err := Check(ref, data)
			switch {
			case err == nil:
				if s.hold(ref, data, func(st *Status) { st.Loaded++ }) {
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
			if !s.hold(ref, data, func(st *Status) { st.Fetched++ }) {
				return
			}
			s.log.Info("blob fetched", "blob", short(ref), "kind", ref.Kind, "name", ref.Name, "size", ref.Size, "peer", peer.ID)
			if s.store != nil && ref.Name != "" {
				if err := s.store.Save(ref, data); err != nil {
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
		case errors.Is(err, errTooSlow) || ctx.Err() != nil:
			s.count(func(st *Status) { st.Abandoned++ })
			s.log.Info("blob transfer abandoned", "blob", short(ref), "peer", peer.ID, "err", err)
		default:
			s.log.Debug("blob not fetched from peer", "blob", short(ref), "peer", peer.ID, "err", err)
		}
	}
}
