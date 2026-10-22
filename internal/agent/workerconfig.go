package agent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// WorkerConfig is what a server's supervisor gives a space's worker
// (supervisor.Space.Config): the worker runs as an unprivileged user in
// its own mount namespace and can't read the state directory, so its
// keys, its space's trust and the map come over its control socket (a
// sealed memfd when large), never through a file.
type WorkerConfig struct {
	Keys  NodeKeys
	Trust netmap.Trust
	// Map is the newest envelope; the worker verifies it again.
	Map       []byte
	Interface string
	LinkMTU   int
	// DNS runs the space's resolver, asking DNSUpstreams, which the node
	// picks (serverSpaces.workerUpstreams); the worker never falls back
	// (see docs/design/routing.md "Upstreams").
	DNS          bool
	DNSUpstreams []netip.AddrPort
}

// workerConfigVersion changes with the encoding; supervisor and worker are
// always one build, so a mismatch is a bug, refused.
const workerConfigVersion = 1

type workerConfigJSON struct {
	Version      int              `json:"version"`
	NodeID       string           `json:"node-id"`
	MapKey       string           `json:"map-key"`
	WireGuardKey string           `json:"wireguard-key"`
	SpaceID      string           `json:"space-id"`
	SigningKey   string           `json:"signing-key"`
	RecoveryKey  string           `json:"recovery-key"`
	Map          []byte           `json:"map"`
	Interface    string           `json:"interface"`
	LinkMTU      int              `json:"link-mtu"`
	DNS          bool             `json:"dns"`
	DNSUpstreams []netip.AddrPort `json:"dns-upstreams"`
}

// String keeps the keys out of logs.
func (c WorkerConfig) String() string {
	return fmt.Sprintf("WorkerConfig(%v, space %v, map %d bytes)", c.Keys, c.Trust.SpaceID, len(c.Map))
}

// Encode is the config as the supervisor sends it.
func (c WorkerConfig) Encode() ([]byte, error) {
	return json.Marshal(workerConfigJSON{
		Version:      workerConfigVersion,
		NodeID:       c.Keys.ID.String(),
		MapKey:       hex.EncodeToString(c.Keys.Map[:]),
		WireGuardKey: hex.EncodeToString(c.Keys.WireGuard[:]),
		SpaceID:      c.Trust.SpaceID.String(),
		SigningKey:   hex.EncodeToString(c.Trust.SigningKey),
		RecoveryKey:  hex.EncodeToString(c.Trust.RecoveryKey),
		Map:          c.Map,
		Interface:    c.Interface,
		LinkMTU:      c.LinkMTU,
		DNS:          c.DNS,
		DNSUpstreams: c.DNSUpstreams,
	})
}

// DecodeWorkerConfig reads what Encode wrote.
func DecodeWorkerConfig(b []byte) (WorkerConfig, error) {
	var j workerConfigJSON
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return WorkerConfig{}, fmt.Errorf("worker config: %w", err)
	}
	if j.Version != workerConfigVersion {
		return WorkerConfig{}, fmt.Errorf("worker config version %d, want %d", j.Version, workerConfigVersion)
	}
	var c WorkerConfig
	var errs []error
	var err error
	if c.Keys.ID, err = netmap.ParseNodeID(j.NodeID); err != nil || c.Keys.ID.IsZero() {
		errs = append(errs, errors.New("node-id"))
	}
	if c.Keys.Map, err = netmap.ParseNodePrivateKey(j.MapKey); err != nil {
		errs = append(errs, errors.New("map-key"))
	}
	if c.Keys.WireGuard, err = netmap.ParseWireGuardPrivateKey(j.WireGuardKey); err != nil {
		errs = append(errs, errors.New("wireguard-key"))
	}
	if c.Trust.SpaceID, err = netmap.ParseSpaceID(j.SpaceID); err != nil || c.Trust.SpaceID.IsZero() {
		errs = append(errs, errors.New("space-id"))
	}
	for _, k := range []struct {
		name, hex string
		to        *ed25519.PublicKey
	}{{"signing-key", j.SigningKey, &c.Trust.SigningKey}, {"recovery-key", j.RecoveryKey, &c.Trust.RecoveryKey}} {
		b, err := hex.DecodeString(k.hex)
		if err != nil || len(b) != ed25519.PublicKeySize {
			errs = append(errs, errors.New(k.name))
			continue
		}
		*k.to = b
	}
	if len(errs) > 0 {
		return WorkerConfig{}, fmt.Errorf("worker config: bad %w", errors.Join(errs...))
	}
	c.Map, c.Interface, c.LinkMTU = j.Map, j.Interface, j.LinkMTU
	c.DNS, c.DNSUpstreams = j.DNS, j.DNSUpstreams
	return c, nil
}

// sameNode reports whether two configs are for the same node of the same
// space: a worker keeps its keys and trust for life.
func (c WorkerConfig) sameNode(o WorkerConfig) bool {
	return c.Keys == o.Keys && c.Trust.SpaceID == o.Trust.SpaceID &&
		c.Trust.SigningKey.Equal(o.Trust.SigningKey) && c.Trust.RecoveryKey.Equal(o.Trust.RecoveryKey)
}
