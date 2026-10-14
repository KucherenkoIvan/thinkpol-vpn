package wg

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Overhead is what WireGuard adds to each packet it carries: a TUN's MTU is
// the path layer's message budget less this.
const Overhead = device.MessageTransportSize

// ErrClosed is returned by a closed device.
var ErrClosed = errors.New("wg: device closed")

// Peer is one of a device's WireGuard peers.
type Peer struct {
	Key netmap.WireGuardKey
	// Node is the peer's node id: the path layer's name for it, and so
	// WireGuard's endpoint.
	Node path.NodeID
	// AllowedIPs are the destinations routed to the peer and the sources
	// accepted from it. No two peers of a device may overlap.
	AllowedIPs []netip.Prefix
}

// PeerStatus is what WireGuard reports about a peer.
type PeerStatus struct {
	Key           netmap.WireGuardKey
	Node          path.NodeID
	LastHandshake time.Time // zero before the first
	RxBytes       uint64
	TxBytes       uint64
}

// Device is one WireGuard device (wireguard-go): it reads its TUN, a router
// egress, and its only network is a path.Bind. It never has a listen port
// or a firewall mark.
type Device struct {
	name string
	dev  *device.Device
	bind *path.Bind

	hs *handshakeLog // nil without a log

	mu     sync.Mutex
	key    netmap.WireGuardPrivateKey
	peers  map[netmap.WireGuardKey]Peer // as configured
	synced bool                         // peers is what WireGuard has
	up     bool
	closed bool
}

// New starts a device named name (for logs) on t and b; it comes up with
// its first Configure. The device owns both: Close closes t and b, and
// releases b from its node. A nil log discards WireGuard's messages.
//
// WireGuard logs every failed send as an error, and a peer without a path
// (path.ErrNoPath, counted by the path layer as NoPath) fails every
// packet and every handshake retry: those go to the debug level. Its
// verbose messages go to the debug level too, but for a peer's first
// handshake that didn't complete in time and the first one done after
// that (info), so a log at info level explains a drop.
func New(name string, t tun.Device, b *path.Bind, log *slog.Logger) *Device {
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	var hs *handshakeLog
	if log != nil {
		log = log.With("wireguard", name)
		logger.Errorf = func(format string, args ...any) {
			level := slog.LevelError
			if noPath(args) {
				level = slog.LevelDebug
			}
			log.Log(context.Background(), level, fmt.Sprintf(format, args...))
		}
		hs = &handshakeLog{log: log, late: make(map[string]bool)}
		logger.Verbosef = hs.verbosef
	}
	return &Device{
		name:   name,
		hs:     hs,
		dev:    device.NewDevice(t, b, logger),
		bind:   b,
		peers:  make(map[netmap.WireGuardKey]Peer),
		synced: true,
	}
}

// handshakeLog sorts WireGuard's verbose messages: the first handshake of
// a peer that timed out goes to the info level (WireGuard's retries after
// it to debug), and so does the next handshake of that peer done, ending
// the outage; everything else is debug.
type handshakeLog struct {
	log  *slog.Logger
	mu   sync.Mutex
	late map[string]bool // peers (as WireGuard names them) whose handshake timed out, until one is done
}

// keep forgets the peers not in keys, so peers the map took away while
// their handshakes failed don't stay behind.
func (h *handshakeLog) keep(keys map[netmap.WireGuardKey]Peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.late) == 0 {
		return
	}
	names := make(map[string]bool, len(keys))
	for k := range keys {
		names[peerName(k)] = true
	}
	for p := range h.late {
		if !names[p] {
			delete(h.late, p)
		}
	}
}

// peerName is how WireGuard names a peer in its messages (device.Peer's
// String): its key in base64, abbreviated.
func peerName(k netmap.WireGuardKey) string {
	b := base64.StdEncoding.EncodeToString(k[:])
	return "peer(" + b[0:4] + "…" + b[39:43] + ")"
}

func (h *handshakeLog) verbosef(format string, args ...any) {
	peer := ""
	if len(args) > 0 {
		peer = fmt.Sprint(args[0])
	}
	level := slog.LevelDebug
	h.mu.Lock()
	switch {
	case strings.Contains(format, "Handshake did not complete") || strings.Contains(format, "stopped hearing back"):
		if !h.late[peer] {
			h.late[peer] = true
			level = slog.LevelInfo
		}
	case h.late[peer] && (strings.Contains(format, "Received handshake response") || strings.Contains(format, "Sending handshake response")):
		delete(h.late, peer)
		level = slog.LevelInfo
	}
	h.mu.Unlock()
	if h.log.Enabled(context.Background(), level) {
		h.log.Log(context.Background(), level, fmt.Sprintf(format, args...))
	}
}

func noPath(args []any) bool {
	for _, a := range args {
		if err, ok := a.(error); ok && errors.Is(err, path.ErrNoPath) {
			return true
		}
	}
	return false
}

// Name returns the device's name.
func (d *Device) Name() string { return d.name }

// Bind returns the device's path.Bind.
func (d *Device) Bind() *path.Bind { return d.bind }

// Configure makes key the device's private key and peers its whole peer
// set, and brings the device up. Only what changed is touched: a peer that
// stays keeps its session and the endpoint WireGuard last adopted for it
// (which tells the Bind the path its peer chose). It refuses, changing
// nothing, a zero key, a peer with the device's own key or a zero node id,
// a key or node twice, and allowed IPs that are invalid or overlap.
func (d *Device) Configure(key netmap.WireGuardPrivateKey, peers []Peer) error {
	next, err := check(key, peers)
	if err != nil {
		return fmt.Errorf("wg: device %s: %w", d.name, err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}

	var b strings.Builder
	if key != d.key || !d.synced {
		fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(key[:]))
	}
	if !d.synced {
		b.WriteString("replace_peers=true\n")
		clear(d.peers)
	}
	for k := range d.peers {
		if p, ok := next[k]; !ok || p.Node != d.peers[k].Node {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", k)
		}
	}
	for _, k := range sortedKeys(next) {
		p := next[k]
		old, had := d.peers[k]
		switch {
		case had && old.Node == p.Node && slices.Equal(old.AllowedIPs, p.AllowedIPs):
			continue
		case had && old.Node == p.Node:
			fmt.Fprintf(&b, "public_key=%s\nupdate_only=true\n", k)
		default:
			fmt.Fprintf(&b, "public_key=%s\nendpoint=%s\n", k, hex.EncodeToString(p.Node[:]))
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
		}
	}
	if b.Len() > 0 {
		if err := d.dev.IpcSet(b.String()); err != nil {
			// Part of it may have applied: start over next time.
			d.synced = false
			return fmt.Errorf("wg: device %s: %w", d.name, err)
		}
	}
	d.key, d.peers, d.synced = key, next, true
	if d.hs != nil {
		d.hs.keep(next)
	}
	if !d.up {
		if err := d.dev.Up(); err != nil {
			return fmt.Errorf("wg: device %s: up: %w", d.name, err)
		}
		d.up = true
	}
	return nil
}

func check(key netmap.WireGuardPrivateKey, peers []Peer) (map[netmap.WireGuardKey]Peer, error) {
	if key == (netmap.WireGuardPrivateKey{}) {
		return nil, errors.New("zero private key")
	}
	own := key.Public()
	next := make(map[netmap.WireGuardKey]Peer, len(peers))
	nodes := make(map[path.NodeID]bool, len(peers))
	var all []netip.Prefix
	for _, p := range peers {
		switch {
		case p.Key.IsZero():
			return nil, fmt.Errorf("peer %s: zero key", p.Node)
		case p.Key == own:
			return nil, fmt.Errorf("peer %s: the device's own key", p.Node)
		case p.Node == path.NodeID{}:
			return nil, fmt.Errorf("peer %s: zero node id", p.Key)
		case next[p.Key].Key == p.Key:
			return nil, fmt.Errorf("peer %s: key listed twice", p.Key)
		case nodes[p.Node]:
			return nil, fmt.Errorf("peer %s: node listed twice", p.Node)
		}
		ips := make([]netip.Prefix, 0, len(p.AllowedIPs))
		for _, ip := range p.AllowedIPs {
			if !ip.IsValid() || ip.Addr().Zone() != "" || ip.Addr().Is4In6() {
				return nil, fmt.Errorf("peer %s: allowed IP %s", p.Node, ip)
			}
			ip = ip.Masked()
			for _, other := range all {
				if other.Overlaps(ip) {
					return nil, fmt.Errorf("peer %s: allowed IP %s overlaps %s", p.Node, ip, other)
				}
			}
			all = append(all, ip)
			ips = append(ips, ip)
		}
		slices.SortFunc(ips, comparePrefixes)
		p.AllowedIPs = ips
		next[p.Key] = p
		nodes[p.Node] = true
	}
	return next, nil
}

func sortedKeys(m map[netmap.WireGuardKey]Peer) []netmap.WireGuardKey {
	keys := make([]netmap.WireGuardKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b netmap.WireGuardKey) int { return strings.Compare(string(a[:]), string(b[:])) })
	return keys
}

// Peers reports on the device's peers, in key order.
func (d *Device) Peers() ([]PeerStatus, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, ErrClosed
	}
	s, err := d.dev.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("wg: device %s: %w", d.name, err)
	}
	var out []PeerStatus
	var sec, nsec int64
	flush := func() {
		if len(out) > 0 && (sec != 0 || nsec != 0) {
			out[len(out)-1].LastHandshake = time.Unix(sec, nsec)
		}
		sec, nsec = 0, 0
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	err = nil
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			key, err := netmap.ParseWireGuardKey(v)
			if err != nil {
				return nil, fmt.Errorf("wg: device %s: %w", d.name, err)
			}
			out = append(out, PeerStatus{Key: key, Node: d.peers[key].Node})
		case "last_handshake_time_sec":
			sec, err = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, err = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			if len(out) > 0 {
				out[len(out)-1].RxBytes, err = strconv.ParseUint(v, 10, 64)
			}
		case "tx_bytes":
			if len(out) > 0 {
				out[len(out)-1].TxBytes, err = strconv.ParseUint(v, 10, 64)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("wg: device %s: status %s: %w", d.name, k, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("wg: device %s: status: %w", d.name, err)
	}
	flush()
	slices.SortFunc(out, func(a, b PeerStatus) int { return strings.Compare(string(a.Key[:]), string(b.Key[:])) })
	return out, nil
}

// Close closes the device, its TUN and its Bind, and releases the Bind
// from its node. Closing twice is a no-op.
func (d *Device) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	d.mu.Unlock()
	d.dev.Close()
	d.bind.Release()
	return nil
}

func comparePrefixes(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}
