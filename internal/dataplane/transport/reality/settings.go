package reality

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	transportv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/transport/v1"
)

// Name is the transport's name in the map.
const Name = "reality"

const (
	// ShortIDSize is the size of a credential: the short id a device seals
	// into its ClientHello, a shared secret.
	ShortIDSize = 8
	// KeySize is the size of the listener's X25519 keys.
	KeySize = 32
	// FingerprintChrome is the ClientHello the dialer imitates by default.
	FingerprintChrome = "chrome"
)

// ErrSettings marks map entries reality can't use.
var ErrSettings = errors.New("reality: unusable settings")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrSettings, fmt.Sprintf(format, args...))
}

// shortID is a credential.
type shortID [ShortIDSize]byte

func parseShortID(b []byte) (shortID, error) {
	var id shortID
	if len(b) != ShortIDSize {
		return id, invalid("a short id is %d bytes, not %d", len(b), ShortIDSize)
	}
	copy(id[:], b)
	return id, nil
}

// listenSettings is a checked RealityListenSettings.
type listenSettings struct {
	key    *ecdh.PrivateKey
	target netip.AddrPort
	names  map[string]bool
	window time.Duration
}

func parseListen(b []byte) (listenSettings, error) {
	var pb transportv1.RealityListenSettings
	if err := proto.Unmarshal(b, &pb); err != nil {
		return listenSettings{}, invalid("listener settings: %v", err)
	}
	var s listenSettings
	if len(pb.GetPrivateKey()) != KeySize {
		return s, invalid("the private key is %d bytes, not %d", len(pb.GetPrivateKey()), KeySize)
	}
	key, err := ecdh.X25519().NewPrivateKey(pb.GetPrivateKey())
	if err != nil {
		return s, invalid("private key: %v", err)
	}
	s.key = key
	if s.target, err = transport.ParseEndpoint(pb.GetTarget()); err != nil {
		return s, invalid("target: %v", err)
	}
	if len(pb.GetServerNames()) == 0 {
		return s, invalid("no server names")
	}
	s.names = make(map[string]bool, len(pb.GetServerNames()))
	for _, n := range pb.GetServerNames() {
		if n == "" {
			return s, invalid("an empty server name")
		}
		s.names[n] = true
	}
	s.window = time.Duration(pb.GetTimeWindowS()) * time.Second
	switch {
	case s.window == 0:
		s.window = transport.MaxClockSkew
	case s.window > transport.MaxClockSkew:
		return s, invalid("a time window of %v, at most %v", s.window, transport.MaxClockSkew)
	}
	return s, nil
}

// dialSettings is a checked RealityDialSettings.
type dialSettings struct {
	serverName string
	serverKey  *ecdh.PublicKey
}

func parseDial(b []byte) (dialSettings, error) {
	var pb transportv1.RealityDialSettings
	if err := proto.Unmarshal(b, &pb); err != nil {
		return dialSettings{}, invalid("dial settings: %v", err)
	}
	var s dialSettings
	if s.serverName = pb.GetServerName(); s.serverName == "" {
		return s, invalid("no server name")
	}
	if len(pb.GetPublicKey()) != KeySize {
		return s, invalid("the public key is %d bytes, not %d", len(pb.GetPublicKey()), KeySize)
	}
	key, err := ecdh.X25519().NewPublicKey(pb.GetPublicKey())
	if err != nil {
		return s, invalid("public key: %v", err)
	}
	s.serverKey = key
	if f := pb.GetFingerprint(); f != "" && f != FingerprintChrome {
		return s, invalid("fingerprint %q: only %q so far", f, FingerprintChrome)
	}
	return s, nil
}

func parseInbound(b []byte) error {
	if err := proto.Unmarshal(b, &transportv1.RealityInboundSettings{}); err != nil {
		return invalid("inbound settings: %v", err)
	}
	return nil
}
