package reality

import (
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// ErrNotAuthenticated is a dial whose far end didn't prove it holds the
// listener's key: it answered with a certificate of its own (a real site
// the connection was spliced to, or a man in the middle).
var ErrNotAuthenticated = errors.New("reality: the server didn't authenticate")

// Dial implements transport.Dialer.
func (t *Transport) Dial(ctx context.Context, endpoint string, cfg transport.DialConfig) (transport.Link, error) {
	if err := t.CheckEndpoint(endpoint, cfg); err != nil {
		return nil, err
	}
	ap, _ := parseAddrPort(endpoint)
	ds, _ := parseDial(cfg.Settings)
	id, _ := parseShortID(cfg.Credential)

	d := net.Dialer{Control: t.control}
	tcp, err := d.DialContext(ctx, "tcp", ap.String())
	if err != nil {
		return nil, fmt.Errorf("reality: %w", err)
	}
	tlsConn, err := t.handshake(ctx, tcp, ds, id)
	if err != nil {
		_ = tcp.Close()
		return nil, err
	}
	return newLink(tlsConn, tcp, cfg.Shaping, t.sent, nil), nil
}

// handshake runs the client side: a Chrome ClientHello with the short id
// sealed in its session id, and a server certificate that must prove the
// listener's key. A real certificate fails the dial only after the
// handshake completes, as a browser's preconnect it never used would end,
// rather than with an alert no browser sends to a site whose certificate
// is valid.
func (t *Transport) handshake(ctx context.Context, tcp net.Conn, ds dialSettings, id shortID) (*utls.UConn, error) {
	var authKey []byte
	authenticated := false
	uc := utls.UClient(tcp, &utls.Config{
		ServerName:                  ds.serverName,
		InsecureSkipVerify:          true, // VerifyPeerCertificate is the check
		SessionTicketsDisabled:      true,
		DynamicRecordSizingDisabled: true, // one write, one record: shaping sizes records
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			authenticated = provesKey(rawCerts, authKey)
			return nil
		},
	}, utls.HelloChrome_Auto)
	if err := uc.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("reality: build the ClientHello: %w", err)
	}
	hello := uc.HandshakeState.Hello
	if len(hello.Raw) < sessionIDOffset+sessionIDSize || hello.Raw[sessionIDOffset-1] != sessionIDSize {
		return nil, errors.New("reality: the ClientHello has no 32-byte session id")
	}
	priv := clientShare(uc)
	if priv == nil {
		return nil, errors.New("reality: the ClientHello has no X25519 key share")
	}
	shared, err := priv.ECDH(ds.serverKey)
	if err != nil {
		return nil, fmt.Errorf("reality: %w", err)
	}
	var aead cipher.AEAD
	if authKey, aead, err = sealKey(shared, hello.Random); err != nil {
		return nil, fmt.Errorf("reality: %w", err)
	}
	clear(hello.Raw[sessionIDOffset : sessionIDOffset+sessionIDSize])
	seal(aead, hello.Raw, hello.Random, id, uint32(t.now().Unix()))
	hello.SessionId = hello.Raw[sessionIDOffset : sessionIDOffset+sessionIDSize]

	if err := uc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("reality: TLS handshake: %w", err)
	}
	if !authenticated {
		_ = uc.Close()
		return nil, ErrNotAuthenticated
	}
	return uc, nil
}

// clientShare is the private half of the share the seal is keyed with,
// chosen by the listener's rule (parseHello): the standalone X25519 share,
// else X25519MLKEM768's X25519 half.
func clientShare(uc *utls.UConn) *ecdh.PrivateKey {
	keys := uc.HandshakeState.State13.KeyShareKeys
	if keys == nil {
		return nil
	}
	if keys.Ecdhe != nil {
		return keys.Ecdhe
	}
	return keys.MlkemEcdhe
}

// provesKey reports whether the leaf is REALITY's: an Ed25519 key whose
// certificate signature is HMAC-SHA512(auth key, public key).
func provesKey(rawCerts [][]byte, authKey []byte) bool {
	if len(rawCerts) == 0 || authKey == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return false
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return false
	}
	mac := hmac.New(sha512.New, authKey)
	mac.Write(pub)
	return hmac.Equal(mac.Sum(nil), leaf.Signature)
}
