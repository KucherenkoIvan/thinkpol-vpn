// Package reality is throwaway prototype code for TP-064: a REALITY client
// reimplemented from the protocol description on uTLS, to be tested against
// an unmodified Xray server in the lab. Nothing here is meant for internal/.
//
// Wire format (TP-064 findings): a uTLS browser ClientHello whose 32-byte
// session id (at handshake offset 39) carries 16 sealed plaintext bytes —
// the Xray core version x.y.z, a zero byte, a Unix time in seconds, and the
// 8-byte short id. The seal is AES-256-GCM keyed by HKDF-SHA256 of the
// X25519 shared secret (client key share × server static key), salted with
// Random[:20] and info "REALITY"; the nonce is Random[20:32]; the additional
// data is the ClientHello with the session id zeroed. A server that opens
// the seal answers with a certificate whose Ed25519 signature is
// HMAC-SHA512(AuthKey, leaf public key); anything else splices the raw
// connection to its target.
package reality

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	authInfo          = "REALITY"
	sessionIDOffset   = 39
	sessionIDSize     = 32
	sealedPlaintext   = 16
	shortIDSize       = 8
	gcmNonceSize      = 12
	gcmSealOverhead   = 16
	fingerprintChrome = "chrome"
)

// ClientConfig is what a client needs to authenticate to one REALITY listener.
type ClientConfig struct {
	// ServerName is the SNI, which the listener must list in serverNames.
	ServerName string
	// ServerPublicKey is the listener's static X25519 public key, 32 raw bytes.
	ServerPublicKey []byte
	// ShortID is the credential, 8 bytes.
	ShortID []byte
	// Version is the Xray core version to present as x.y.z. The stock server
	// skips the version check when minClientVer and maxClientVer are unset,
	// but the bytes are still part of the sealed plaintext.
	Version [3]byte
}

// Client is one REALITY connection. After a successful Handshake, Verified
// says whether the server answered as a REALITY listener (and not as the
// camouflage target reached through the splice).
type Client struct {
	conn    *utls.UConn
	Hello   []byte // the ClientHello exactly as sent, sealed session id included
	AuthKey []byte

	verified   bool
	realSigned bool
}

// timeNow is stubbed by the tests to seal a stale timestamp.
var timeNow = time.Now

// Verified reports that the server's certificate carried REALITY's
// HMAC-SHA512 signature over the leaf public key.
func (c *Client) Verified() bool { return c.verified }

// Read and Write carry application data over the established TLS session.
func (c *Client) Read(p []byte) (int, error)  { return c.conn.Read(p) }
func (c *Client) Write(p []byte) (int, error) { return c.conn.Write(p) }

// Close closes the underlying TLS connection.
func (c *Client) Close() error { return c.conn.Close() }

// PeerCertificates returns the certificate chain the server presented.
func (c *Client) PeerCertificates() []*x509.Certificate {
	return c.conn.ConnectionState().PeerCertificates
}

// NewClient prepares a REALITY client on conn. The connection's ClientHello
// is built and sealed but not sent; call Handshake to send it.
func NewClient(conn net.Conn, cfg ClientConfig) (*Client, error) {
	if len(cfg.ServerPublicKey) != 32 {
		return nil, fmt.Errorf("reality: server public key must be 32 bytes, got %d", len(cfg.ServerPublicKey))
	}
	if len(cfg.ShortID) != shortIDSize {
		return nil, fmt.Errorf("reality: short id must be %d bytes, got %d", shortIDSize, len(cfg.ShortID))
	}
	c := &Client{}
	uconn := utls.UClient(conn, &utls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: true, // the check is VerifyPeerCertificate below
		// Session tickets would add PSK binders on later handshakes; Xray's
		// client disables them too.
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  c.verifyServerCertificate,
	}, utls.HelloChrome_Auto)
	c.conn = uconn

	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("reality: build ClientHello: %w", err)
	}
	hello := uconn.HandshakeState.Hello
	if len(hello.Raw) <= sessionIDOffset+sessionIDSize {
		return nil, fmt.Errorf("reality: ClientHello too short: %d bytes", len(hello.Raw))
	}
	if hello.Raw[sessionIDOffset-1] != sessionIDSize {
		return nil, fmt.Errorf("reality: ClientHello session id length %d, want %d", hello.Raw[sessionIDOffset-1], sessionIDSize)
	}
	// Zero the session id in the marshaled hello first: it is the additional
	// data the seal is computed over, on both ends.
	hello.SessionId = make([]byte, sessionIDSize)
	copy(hello.Raw[sessionIDOffset:], hello.SessionId)

	plaintext := make([]byte, sealedPlaintext)
	plaintext[0], plaintext[1], plaintext[2] = cfg.Version[0], cfg.Version[1], cfg.Version[2]
	binary.BigEndian.PutUint32(plaintext[4:], uint32(timeNow().Unix()))
	copy(plaintext[8:], cfg.ShortID)

	shared, err := x25519Shared(uconn, cfg.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	c.AuthKey, err = hkdf.Key(sha256.New, shared, hello.Random[:20], authInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("reality: HKDF: %w", err)
	}
	aead, err := aesGCM(c.AuthKey)
	if err != nil {
		return nil, err
	}
	// Seal appends to hello.SessionId[:0]: the ciphertext and tag (32 bytes)
	// fill the session id in place.
	aead.Seal(hello.SessionId[:0], hello.Random[20:20+gcmNonceSize], plaintext, hello.Raw)
	copy(hello.Raw[sessionIDOffset:], hello.SessionId)
	c.Hello = append([]byte(nil), hello.Raw...)
	return c, nil
}

// Handshake sends the sealed ClientHello and completes the TLS handshake,
// whichever server answers.
func (c *Client) Handshake(ctx context.Context) error {
	if err := c.conn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("reality: TLS handshake: %w", err)
	}
	if !c.realSigned {
		// The splice path answered with a certificate no REALITY listener
		// would sign: this is the camouflage target (or a MITM).
		return errRealCertificate
	}
	c.verified = true
	return nil
}

var errRealCertificate = errors.New("reality: server presented a real certificate (spliced to the target, MITM, or redirection)")

// verifyServerCertificate mirrors REALITY's client check: the leaf must be
// Ed25519 and its signature must be HMAC-SHA512(AuthKey, leaf public key).
// Anything else is treated as the camouflage target's own certificate.
func (c *Client) verifyServerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("reality: server sent no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("reality: parse leaf: %w", err)
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil // not REALITY's certificate shape
	}
	mac := hmac.New(sha512.New, c.AuthKey)
	mac.Write(pub)
	if hmac.Equal(mac.Sum(nil), leaf.Signature) {
		c.realSigned = true
		return nil
	}
	return nil
}

// x25519Shared multiplies the client's ephemeral key share (the one inside
// the ClientHello just built) with the server's static public key.
func x25519Shared(uconn *utls.UConn, serverPublic []byte) ([]byte, error) {
	ecdhe := uconn.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		// No standalone X25519 share; fall back to the X25519 half of
		// X25519MLKEM768. The Chrome hello carries a standalone share, so
		// this path is not exercised by the prototype.
		ecdhe = uconn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, fmt.Errorf("reality: %s fingerprint has no X25519 key share", fingerprintChrome)
	}
	serverKey, err := ecdh.X25519().NewPublicKey(serverPublic)
	if err != nil {
		return nil, fmt.Errorf("reality: server public key: %w", err)
	}
	shared, err := ecdhe.ECDH(serverKey)
	if err != nil {
		return nil, fmt.Errorf("reality: ECDH: %w", err)
	}
	return shared, nil
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("reality: AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("reality: GCM: %w", err)
	}
	if aead.NonceSize() != gcmNonceSize {
		return nil, fmt.Errorf("reality: unexpected GCM nonce size %d", aead.NonceSize())
	}
	return aead, nil
}
