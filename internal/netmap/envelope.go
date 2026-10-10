package netmap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"

	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	netmapv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/netmap/v1"
)

const (
	// Format is the envelope format this package reads and writes.
	Format = 1
	// MaxEnvelopeSize bounds what Verify reads, so a gossiped envelope can't
	// make a node allocate without limit.
	MaxEnvelopeSize = 16 << 20

	// signatureContext is the Ed25519ctx context of map signatures. The
	// recovery key signs with "thinkpol-vpn recovery v1" (TP-036), so neither
	// signature can be passed off as the other.
	signatureContext = "thinkpol-vpn netmap v1"
)

var (
	// ErrMalformed: the envelope or a section can't be decoded, or breaks a
	// rule of the format.
	ErrMalformed = errors.New("netmap: malformed map")
	// ErrBadSignature: the signature doesn't verify with the given key.
	ErrBadSignature = errors.New("netmap: bad signature")
	// ErrUnsupportedFormat: the envelope is a format this node can't read.
	ErrUnsupportedFormat = errors.New("netmap: unsupported map format")
	// ErrNotRecipient: no section of the map opens with the node's key.
	ErrNotRecipient = errors.New("netmap: no section for this node key")
	// ErrOtherSpace: the candidate map belongs to another space.
	ErrOtherSpace = errors.New("netmap: map of another space")
	// ErrKeysChanged: the candidate map names other space keys. Signing-key
	// rotation by the recovery key is TP-036.
	ErrKeysChanged = errors.New("netmap: space keys changed")
	// ErrNotNewer: the candidate map's version isn't higher than the
	// current one.
	ErrNotNewer = errors.New("netmap: map version not newer")
	// ErrInvalidContents: Build was given contents it won't publish.
	ErrInvalidContents = errors.New("netmap: invalid map contents")
)

// Header is the public part of a map, readable by anyone holding the
// envelope.
type Header struct {
	SpaceID SpaceID
	// Version only goes up.
	Version uint64
	// SigningKey signs the envelope.
	SigningKey ed25519.PublicKey
	// RecoveryKey is the space's offline recovery key (PRD A11).
	RecoveryKey ed25519.PublicKey
	// Blobs are the content-addressed files the space uses (GeoIP lists).
	Blobs []BlobRef
}

// BlobRef names a blob by the SHA-256 of its content.
type BlobRef struct {
	SHA256 [32]byte
	Size   uint64
}

func (h Header) clone() Header {
	h.SigningKey = bytes.Clone(h.SigningKey)
	h.RecoveryKey = bytes.Clone(h.RecoveryKey)
	h.Blobs = append([]BlobRef(nil), h.Blobs...)
	return h
}

// Map is an envelope whose signature has been verified. Only Verify makes
// one, so holding a *Map means the content is the space admin's.
type Map struct {
	raw      []byte
	header   Header
	sections [][]byte
}

// Header returns the map's header.
func (m *Map) Header() Header { return m.header.clone() }

// Bytes returns the exact envelope bytes, to store or pass on. Never
// re-encode a map: the signature covers these bytes.
func (m *Map) Bytes() []byte { return bytes.Clone(m.raw) }

// SectionCount is the number of sections including the padding.
func (m *Map) SectionCount() int { return len(m.sections) }

// Contents is a map to build.
type Contents struct {
	SpaceID     SpaceID
	Version     uint64
	RecoveryKey ed25519.PublicKey
	Blobs       []BlobRef
	Sections    []Recipient
}

// Recipient is a node's section and the key it is sealed to.
type Recipient struct {
	Key     NodePublicKey
	Section Section
}

// Build seals each section to its recipient, pads, shuffles and signs, and
// returns the envelope bytes. Every call seals afresh, so no section is
// shared between two envelopes.
func Build(signingKey ed25519.PrivateKey, c Contents) ([]byte, error) {
	if len(signingKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: signing key of %d bytes", ErrInvalidContents, len(signingKey))
	}
	header := Header{
		SpaceID:     c.SpaceID,
		Version:     c.Version,
		SigningKey:  signingKey.Public().(ed25519.PublicKey),
		RecoveryKey: c.RecoveryKey,
		Blobs:       c.Blobs,
	}
	if err := header.validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidContents, err)
	}
	count := sectionCount(len(c.Sections))
	if count > maxSections {
		return nil, fmt.Errorf("%w: %d sections, at most %d", ErrInvalidContents, len(c.Sections), maxSections)
	}

	keys := make(map[NodePublicKey]bool, len(c.Sections))
	nodes := make(map[NodeID]bool, len(c.Sections))
	plain := make([][]byte, len(c.Sections))
	largest := 0
	for i, r := range c.Sections {
		if r.Key.IsZero() || keys[r.Key] {
			return nil, fmt.Errorf("%w: section %d: recipient key zero or repeated", ErrInvalidContents, i)
		}
		keys[r.Key] = true
		if err := r.Section.validate(); err != nil {
			return nil, fmt.Errorf("%w: section %d: %v", ErrInvalidContents, i, err)
		}
		if nodes[r.Section.Node.ID] {
			return nil, fmt.Errorf("%w: section %d: node %v has two sections", ErrInvalidContents, i, r.Section.Node.ID)
		}
		nodes[r.Section.Node.ID] = true
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(sectionToProto(&r.Section, c.SpaceID, c.Version))
		if err != nil {
			return nil, fmt.Errorf("netmap: encoding section %d: %w", i, err)
		}
		plain[i] = b
		largest = max(largest, len(b))
	}
	size := sectionSize(largest)
	if size > maxSectionSize {
		return nil, fmt.Errorf("%w: a section of %d bytes, at most %d", ErrInvalidContents, largest, maxSectionSize-1)
	}

	sealed := make([][]byte, 0, count)
	for i, r := range c.Sections {
		s, err := box.SealAnonymous(nil, pad(plain[i], size), (*[32]byte)(&r.Key), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("netmap: sealing section %d: %w", i, err)
		}
		sealed = append(sealed, s)
	}
	// Dummies are real sealed boxes to throwaway keys, so they come from the
	// same distribution as real sections (random bytes wouldn't: an X25519
	// public key never has its top bit set).
	for len(sealed) < count {
		throwaway := GenerateNodeKey().Public()
		s, err := box.SealAnonymous(nil, make([]byte, size), (*[32]byte)(&throwaway), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("netmap: sealing a dummy section: %w", err)
		}
		sealed = append(sealed, s)
	}
	var seed [32]byte
	_, _ = rand.Read(seed[:])
	mrand.New(mrand.NewChaCha8(seed)).Shuffle(len(sealed), func(i, j int) { sealed[i], sealed[j] = sealed[j], sealed[i] })

	body := &netmapv1.Body{Format: Format, Header: header.toProto()}
	for _, s := range sealed {
		body.Sections = append(body.Sections, &netmapv1.SealedSection{Sealed: s})
	}
	bodyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("netmap: encoding the body: %w", err)
	}
	sig, err := signingKey.Sign(nil, bodyBytes, &ed25519.Options{Context: signatureContext})
	if err != nil {
		return nil, fmt.Errorf("netmap: signing: %w", err)
	}
	env, err := proto.MarshalOptions{Deterministic: true}.Marshal(&netmapv1.Envelope{Body: bodyBytes, Signature: sig})
	if err != nil {
		return nil, fmt.Errorf("netmap: encoding the envelope: %w", err)
	}
	if len(env) > MaxEnvelopeSize {
		return nil, fmt.Errorf("%w: envelope of %d bytes, at most %d", ErrInvalidContents, len(env), MaxEnvelopeSize)
	}
	return env, nil
}

// Verify checks that envelope is a well-formed map signed by signingKey,
// the key the node trusts for the space, and returns it. The signature is
// checked over the exact body bytes before anything inside is decoded.
func Verify(envelope []byte, signingKey ed25519.PublicKey) (*Map, error) {
	if len(signingKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("netmap: signing key of %d bytes", len(signingKey))
	}
	if len(envelope) > MaxEnvelopeSize {
		return nil, fmt.Errorf("%w: envelope of %d bytes, at most %d", ErrMalformed, len(envelope), MaxEnvelopeSize)
	}
	var env netmapv1.Envelope
	if err := proto.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	// Only the canonical encoding is accepted, so no byte outside the signed
	// body can change without the envelope being rejected.
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(&env)
	if err != nil || len(env.ProtoReflect().GetUnknown()) != 0 || !bytes.Equal(canonical, envelope) {
		return nil, fmt.Errorf("%w: envelope not in canonical form", ErrMalformed)
	}
	if len(env.GetSignature()) != ed25519.SignatureSize ||
		ed25519.VerifyWithOptions(signingKey, env.GetBody(), env.GetSignature(), &ed25519.Options{Context: signatureContext}) != nil {
		return nil, ErrBadSignature
	}

	if f, err := bodyFormat(env.GetBody()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	} else if f != Format {
		return nil, fmt.Errorf("%w: format %d, this node reads %d", ErrUnsupportedFormat, f, Format)
	}
	var body netmapv1.Body
	if err := proto.Unmarshal(env.GetBody(), &body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if body.GetFormat() != Format {
		return nil, fmt.Errorf("%w: format field repeated", ErrMalformed)
	}
	header, err := headerFromProto(body.GetHeader())
	if err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	if !bytes.Equal(header.SigningKey, signingKey) {
		return nil, fmt.Errorf("%w: header names another signing key", ErrMalformed)
	}

	n := len(body.GetSections())
	if !isPowerOfTwo(n) || n < minSections || n > maxSections {
		return nil, fmt.Errorf("%w: %d sections", ErrMalformed, n)
	}
	sections := make([][]byte, n)
	for i, s := range body.GetSections() {
		sections[i] = s.GetSealed()
		if len(sections[i]) != len(sections[0]) {
			return nil, fmt.Errorf("%w: sections of different lengths", ErrMalformed)
		}
	}
	if size := len(sections[0]) - box.AnonymousOverhead; !isPowerOfTwo(size) || size < minSectionSize || size > maxSectionSize {
		return nil, fmt.Errorf("%w: sections of %d bytes", ErrMalformed, len(sections[0]))
	}
	return &Map{raw: bytes.Clone(envelope), header: header, sections: sections}, nil
}

// Open finds and decrypts the section sealed to key. A node can open only
// its own section; every other section, dummies included, looks the same
// to it.
func Open(m *Map, key NodePrivateKey) (Section, error) {
	pub := key.Public()
	var plain []byte
	opened := 0
	// Every section is tried, so a map carrying two sections for one key is
	// caught rather than read inconsistently.
	for _, s := range m.sections {
		if p, ok := box.OpenAnonymous(nil, s, (*[32]byte)(&pub), (*[32]byte)(&key)); ok {
			plain = p
			opened++
		}
	}
	switch {
	case opened == 0:
		return Section{}, ErrNotRecipient
	case opened > 1:
		return Section{}, fmt.Errorf("%w: %d sections for one key", ErrMalformed, opened)
	}
	content, err := unpad(plain)
	if err != nil {
		return Section{}, fmt.Errorf("%w: section: %v", ErrMalformed, err)
	}
	var pb netmapv1.Section
	if err := proto.Unmarshal(content, &pb); err != nil {
		return Section{}, fmt.Errorf("%w: section: %v", ErrMalformed, err)
	}
	if !bytes.Equal(pb.GetSpaceId(), m.header.SpaceID[:]) || pb.GetMapVersion() != m.header.Version {
		return Section{}, fmt.Errorf("%w: section belongs to another space or version", ErrMalformed)
	}
	s, err := sectionFromProto(&pb)
	if err != nil {
		return Section{}, fmt.Errorf("%w: section: %v", ErrMalformed, err)
	}
	if err := s.validate(); err != nil {
		return Section{}, fmt.Errorf("%w: section: %v", ErrMalformed, err)
	}
	return s, nil
}

// Accept reports whether a node running current may switch to candidate:
// same space, same space keys, strictly higher version. A nil current
// accepts any candidate. Both maps must come from Verify, which is where
// the trusted signing key is checked.
func Accept(current, candidate *Map) error {
	if candidate == nil {
		return errors.New("netmap: no candidate map")
	}
	if current == nil {
		return nil
	}
	cur, cand := &current.header, &candidate.header
	if cand.SpaceID != cur.SpaceID {
		return ErrOtherSpace
	}
	if !bytes.Equal(cand.SigningKey, cur.SigningKey) || !bytes.Equal(cand.RecoveryKey, cur.RecoveryKey) {
		return ErrKeysChanged
	}
	if cand.Version <= cur.Version {
		return fmt.Errorf("%w: version %d, running %d", ErrNotNewer, cand.Version, cur.Version)
	}
	return nil
}

func (h *Header) validate() error {
	if h.SpaceID.IsZero() {
		return errors.New("space id is zero")
	}
	if h.Version == 0 {
		return errors.New("version is zero")
	}
	if len(h.SigningKey) != ed25519.PublicKeySize {
		return fmt.Errorf("signing key of %d bytes", len(h.SigningKey))
	}
	if len(h.RecoveryKey) != ed25519.PublicKeySize {
		return fmt.Errorf("recovery key of %d bytes", len(h.RecoveryKey))
	}
	if bytes.Equal(h.SigningKey, h.RecoveryKey) {
		return errors.New("signing and recovery keys are the same key")
	}
	seen := make(map[[32]byte]bool, len(h.Blobs))
	for _, b := range h.Blobs {
		if b.SHA256 == ([32]byte{}) || seen[b.SHA256] {
			return fmt.Errorf("blob %x zero or repeated", b.SHA256)
		}
		seen[b.SHA256] = true
	}
	return nil
}

func (h *Header) toProto() *netmapv1.Header {
	pb := &netmapv1.Header{
		SpaceId:           bytes.Clone(h.SpaceID[:]),
		Version:           h.Version,
		SigningPublicKey:  h.SigningKey,
		RecoveryPublicKey: h.RecoveryKey,
	}
	for _, b := range h.Blobs {
		pb.Blobs = append(pb.Blobs, &netmapv1.BlobRef{Sha256: bytes.Clone(b.SHA256[:]), Size: b.Size})
	}
	return pb
}

func headerFromProto(pb *netmapv1.Header) (Header, error) {
	var h Header
	if pb == nil {
		return h, errors.New("missing")
	}
	var err error
	if h.SpaceID, err = toID[SpaceID]("space id", pb.GetSpaceId()); err != nil {
		return h, err
	}
	h.Version = pb.GetVersion()
	h.SigningKey = bytes.Clone(pb.GetSigningPublicKey())
	h.RecoveryKey = bytes.Clone(pb.GetRecoveryPublicKey())
	for _, b := range pb.GetBlobs() {
		sum, err := toID[[32]byte]("blob hash", b.GetSha256())
		if err != nil {
			return h, err
		}
		h.Blobs = append(h.Blobs, BlobRef{SHA256: sum, Size: b.GetSize()})
	}
	return h, h.validate()
}

// bodyFormat reads the format field of a serialized Body without decoding
// the rest, which a newer format may lay out differently.
func bodyFormat(body []byte) (uint64, error) {
	for len(body) > 0 {
		num, typ, n := protowire.ConsumeTag(body)
		if n < 0 {
			return 0, protowire.ParseError(n)
		}
		body = body[n:]
		if num == 1 && typ == protowire.VarintType {
			v, n := protowire.ConsumeVarint(body)
			if n < 0 {
				return 0, protowire.ParseError(n)
			}
			return v, nil
		}
		n = protowire.ConsumeFieldValue(num, typ, body)
		if n < 0 {
			return 0, protowire.ParseError(n)
		}
		body = body[n:]
	}
	return 0, nil
}
