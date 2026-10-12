package dns

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// Port is the port the resolver serves on and asks exits' resolvers at.
const Port = 53

// RouteKind is where a name's query goes.
type RouteKind uint8

const (
	// RouteDirect asks the domestic upstream, around the tunnel.
	RouteDirect RouteKind = iota + 1
	// RouteTunnel asks the resolver at an exit, through the tunnel.
	RouteTunnel
	// RouteBlock asks no one: the query fails.
	RouteBlock
)

// Route is where one name's query goes.
type Route struct {
	Kind RouteKind
	// Via are the exit's overlay addresses, for RouteTunnel: its resolver
	// is there, at Options.TunnelPort.
	Via []netip.Addr
}

// Config is what the server serves; the engine gives it a new one with
// every map and rule change (Server.Update).
type Config struct {
	// Listen are the addresses to serve on, Options.Port on each: the
	// node's overlay addresses. None: the server doesn't listen.
	Listen []netip.Addr
	// Clients are the sources that may ask; anyone else is refused.
	Clients []netip.Prefix
	// Zone is the space's zone, `<space>.internal`, lowercase without the
	// trailing dot; empty: no overlay names.
	Zone string
	// Names are the overlay names in Zone, by label, and their addresses.
	Names map[string][]netip.Addr
	// Overlay are the space's overlay networks: their reverse names are
	// answered from Names, never forwarded.
	Overlay []netip.Prefix
	// Route decides where a name outside `.internal` is resolved (the name
	// lowercase, without the trailing dot). Nil: every name direct.
	Route func(name string) Route
}

// Options are the server's for life.
type Options struct {
	// Upstreams are the direct upstream resolvers, tried in order.
	Upstreams []netip.AddrPort
	// Control marks the direct upstream's sockets, as the links' are, so
	// they leave around the tunnel in route-table mode.
	Control func(network, address string, c syscall.RawConn) error
	// TunnelControl binds the sockets asking exits to the overlay
	// interface (BindToInterface), so those queries can leave through the
	// tunnel only.
	TunnelControl func(network, address string, c syscall.RawConn) error
	// Port is the port to serve on; 0 is Port.
	Port uint16
	// TunnelPort is the port exits' resolvers are asked at; 0 is Port.
	TunnelPort uint16
	// Timeout bounds one upstream exchange; 0 is two seconds.
	Timeout time.Duration
	// CacheSize bounds the cached answers; 0 is DefaultCacheSize, below
	// zero caches nothing.
	CacheSize int
	// Log gets failures to listen, never anything about a query.
	Log *slog.Logger
}

// DefaultCacheSize is how many answers a server caches by default.
const DefaultCacheSize = 2048

// maxInflight bounds the queries forwarded at once; more are refused with
// SERVFAIL.
const maxInflight = 256

// Counters are what a server reports: figures only, never a name.
type Counters struct {
	Queries   uint64 // queries taken
	Refused   uint64 // from a source that may not ask, or not a query
	Overlay   uint64 // answered from the overlay's names (or not found there)
	Direct    uint64 // for the direct upstream (cache hits included)
	Tunnel    uint64 // for an exit, through the tunnel (cache hits included)
	Blocked   uint64 // blocked by the rules
	CacheHits uint64
	Failed    uint64 // no upstream answered, or too many queries at once
}

type counters struct {
	queries, refused, overlay, direct, tunnel, blocked, cacheHits, failed atomic.Uint64
}

// Server is a DNS server on the node's overlay addresses.
type Server struct {
	opts     Options
	cache    *cache
	inflight chan struct{}
	n        counters

	mu      sync.Mutex
	closed  bool
	cfg     *Config
	serving map[netip.Addr]*listening
	retry   *time.Timer
	// failing are the addresses it couldn't listen on, said once each.
	failing map[netip.Addr]bool
}

type listening struct {
	udp, tcp *dns.Server
}

// New makes a server; it serves once Update gives it addresses.
func New(o Options) *Server {
	if o.Port == 0 {
		o.Port = Port
	}
	if o.TunnelPort == 0 {
		o.TunnelPort = Port
	}
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	if o.CacheSize == 0 {
		o.CacheSize = DefaultCacheSize
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	s := &Server{opts: o, cache: newCache(max(o.CacheSize, 0)), inflight: make(chan struct{}, maxInflight), serving: map[netip.Addr]*listening{}, failing: map[netip.Addr]bool{}}
	s.cfg = &Config{}
	return s
}

// Update replaces the configuration: the cache is flushed (answers were
// cached under the old routes) and the server listens on c.Listen and no
// longer elsewhere. An address it can't listen on yet is retried.
func (s *Server) Update(c Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	cc := c
	s.cfg = &cc
	s.cache.flush()
	s.reconcile()
}

func (s *Server) config() *Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// reconcile listens on the configured addresses; s.mu is held.
func (s *Server) reconcile() {
	want := make(map[netip.Addr]bool, len(s.cfg.Listen))
	for _, a := range s.cfg.Listen {
		want[a.Unmap()] = true
	}
	for a, l := range s.serving {
		if !want[a] {
			l.shutdown()
			delete(s.serving, a)
		}
	}
	failed := false
	for a := range want {
		if s.serving[a] != nil {
			continue
		}
		l, err := s.listen(a)
		if err != nil {
			if !s.failing[a] {
				s.opts.Log.Warn("DNS: can't listen yet, retrying", "address", a, "err", err)
				s.failing[a] = true
			}
			failed = true
			continue
		}
		delete(s.failing, a)
		s.serving[a] = l
	}
	if s.retry != nil {
		s.retry.Stop()
		s.retry = nil
	}
	if failed {
		s.retry = time.AfterFunc(time.Second, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if !s.closed {
				s.reconcile()
			}
		})
	}
}

func (s *Server) listen(a netip.Addr) (*listening, error) {
	addr := net.JoinHostPort(a.String(), strconv.Itoa(int(s.opts.Port)))
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	h := dns.HandlerFunc(s.serveDNS)
	l := &listening{
		udp: &dns.Server{PacketConn: pc, Handler: h},
		tcp: &dns.Server{Listener: ln, Handler: h, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: func() time.Duration { return 10 * time.Second }},
	}
	// Shutdown refuses a server that hasn't started: wait for both.
	var started sync.WaitGroup
	for _, srv := range []*dns.Server{l.udp, l.tcp} {
		started.Add(1)
		var once sync.Once
		done := func() { once.Do(started.Done) }
		srv.NotifyStartedFunc = done
		go func() {
			_ = srv.ActivateAndServe()
			done()
		}()
	}
	started.Wait()
	return l, nil
}

func (l *listening) shutdown() {
	for _, srv := range []*dns.Server{l.udp, l.tcp} {
		_ = srv.Shutdown()
	}
}

// Counters reports what the server did.
func (s *Server) Counters() Counters {
	return Counters{
		Queries: s.n.queries.Load(), Refused: s.n.refused.Load(), Overlay: s.n.overlay.Load(),
		Direct: s.n.direct.Load(), Tunnel: s.n.tunnel.Load(), Blocked: s.n.blocked.Load(),
		CacheHits: s.n.cacheHits.Load(), Failed: s.n.failed.Load(),
	}
}

// Close stops serving.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.retry != nil {
		s.retry.Stop()
	}
	for a, l := range s.serving {
		l.shutdown()
		delete(s.serving, a)
	}
	s.cache.flush()
	return nil
}
