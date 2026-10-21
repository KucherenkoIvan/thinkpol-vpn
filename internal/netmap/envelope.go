package netmap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net/netip"
	"strconv"

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
	// MaxVersion is the highest version Build writes: 2^53 leaves room for
	// any real space and stays exact in a float64 (JSON, JavaScript).
	MaxVersion = 1 << 53

	// signatureContext is the Ed25519ctx context of map signatures. The
	// recovery key signs with "thinkpol-vpn recovery v1" (TP-036), so neither
	// signature can be passed off as the other.
	signatureContext = "thinkpol-vpn netmap v1"
)

var (
	// ErrMalformed: the envelope or a section can't be decoded, or breaks a
	// rule of the format.
	ErrMalformed = errors.New("netmap: malformed map")
	// ErrBadSignature: the signature doesn't verify with the trusted key.
	ErrBadSignature = errors.New("netmap: bad signature")
	// ErrUnsupportedFormat: the envelope or the node's section needs a newer
	// reader than this one.
	ErrUnsupportedFormat = errors.New("netmap: unsupported map format")
	// ErrNotRecipient: no section of the map opens with the node's key.
	ErrNotRecipient = errors.New("netmap: no section for this node key")
	// ErrOtherSpace: the map belongs to another space than the trusted one.
	ErrOtherSpace = errors.New("netmap: map of another space")
	// ErrKeysChanged: the map names other space keys or another key epoch.
	// Following a signing-key rotation is TP-036.
	ErrKeysChanged = errors.New("netmap: space keys changed")
	// ErrNotNewer: the candidate map isn't after the current one.
	ErrNotNewer = errors.New("netmap: map version not newer")
	// ErrInvalidContents: Build was given contents it won't publish.
	ErrInvalidContents = errors.New("netmap: invalid map contents")
	// ErrUnverified: a *Map that didn't come from Verify or Next.
	ErrUnverified = errors.New("netmap: map not verified")

	// errSectionsExceedEnvelope is Build's refusal before sealing.
	errSectionsExceedEnvelope = errors.New("the sections alone exceed the envelope size limit")
)

// Trust is what a node trusts for a space: the keys a map must be signed
// with and name. A node starts from an invite and then follows its maps
// ([Map.Trust]).
type Trust struct {
	// SpaceID, when set, is the only space accepted.
	SpaceID SpaceID
	// SigningKey must have signed the map.
	SigningKey ed25519.PublicKey
	// RecoveryKey, when set, must be the map's recovery key.
	RecoveryKey ed25519.PublicKey
}

// Header is the public part of a map, readable by anyone holding the
// envelope.
type Header struct {
	SpaceID SpaceID
	// KeyEpoch counts signing-key rotations; maps are ordered by
	// (KeyEpoch, Version).
	KeyEpoch uint64
	Version  uint64
	// SigningKey signs the envelope.
	SigningKey ed25519.PublicKey
	// RecoveryKey is the space's offline recovery key (PRD A11).
	RecoveryKey ed25519.PublicKey
	// Blobs are every blob the space uses, unnamed: the set relays cache.
	Blobs []BlobRef
}

// BlobKind is what a blob holds.
type BlobKind uint8

const (
	BlobGeoIP BlobKind = iota + 1
	BlobGeoSite
)

func (k BlobKind) known() bool { return k == BlobGeoIP || k == BlobGeoSite }

func (k BlobKind) String() string {
	switch k {
	case BlobGeoIP:
		return "geoip"
	case BlobGeoSite:
		return "geosite"
	}
	return "BlobKind(" + strconv.Itoa(int(k)) + ")"
}

// BlobRef names a blob by the SHA-256 of its content.
type BlobRef struct {
	Kind   BlobKind
	SHA256 [32]byte
	Size   uint64
	// Name is how rules refer to the blob; set in sections only.
	Name string
}

func (h Header) clone() Header {
	h.SigningKey = bytes.Clone(h.SigningKey)
	h.RecoveryKey = bytes.Clone(h.RecoveryKey)
	h.Blobs = append([]BlobRef(nil), h.Blobs...)
	return h
}

// Map is a verified envelope. Only [Verify] and [Map.Next] make a usable
// one; the zero Map and a nil *Map are refused by every method.
type Map struct {
	verified bool
	raw      []byte
	header   Header
	sections [][]byte
}

func (m *Map) usable() error {
	if m == nil || !m.verified {
		return ErrUnverified
	}
	return nil
}

// Header returns the map's header, or the zero Header for an unverified map.
func (m *Map) Header() Header {
	if m.usable() != nil {
		return Header{}
	}
	return m.header.clone()
}

// Trust returns what the map establishes for the space: its id and keys.
func (m *Map) Trust() Trust {
	if m.usable() != nil {
		return Trust{}
	}
	h := m.header.clone()
	return Trust{SpaceID: h.SpaceID, SigningKey: h.SigningKey, RecoveryKey: h.RecoveryKey}
}

// Bytes returns the exact envelope bytes, to store or pass on. Never
// re-encode a map: the signature covers these bytes.
func (m *Map) Bytes() []byte {
	if m.usable() != nil {
		return nil
	}
	return bytes.Clone(m.raw)
}

// SectionCount is the number of sections including dummies: a power of two
// that tells only which bucket the number of nodes falls in.
func (m *Map) SectionCount() int {
	if m.usable() != nil {
		return 0
	}
	return len(m.sections)
}

// Next verifies envelope against the trust m establishes and accepts it
// only if it comes after m. This is how a node takes a map from gossip.
func (m *Map) Next(envelope []byte) (*Map, error) {
	if err := m.usable(); err != nil {
		return nil, err
	}
	candidate, err := Verify(envelope, m.Trust())
	if err != nil {
		return nil, err
	}
	if err := Accept(m, candidate); err != nil {
		return nil, err
	}
	return candidate, nil
}

// Contents is a map to build.
type Contents struct {
	SpaceID     SpaceID
	KeyEpoch    uint64
	Version     uint64
	RecoveryKey ed25519.PublicKey
	// Blobs are every blob the space uses, unnamed.
	Blobs      []BlobRef
	Recipients []Recipient
}

// Recipient is a node's section and the key it is sealed to.
type Recipient struct {
	Key     NodePublicKey
	Section Section
}

// hiddenFromDevices is Build's check across sections that a server with
// ingress off stays out of devices' reach:
//   - no link between a device and such a server, whichever of them dials
//     (validate already keeps devices' inbound links out of the server's
//     own section);
//   - every inbound link's peer kind is its peer's kind, so a device can't
//     pass for a server;
//   - no device dials an IP such a server listens on (a listener on a
//     concrete address) or is dialed at by anyone, whatever node id the
//     link names: its address can't reach a device under another id.
//
// Kinds and settings are known for recipients only; a node outside the map
// (a shared node, used through a hosting grant) is checked by the builder
// of the map that has it.
func hiddenFromDevices(recipients []Recipient) error {
	nodes := make(map[NodeID]*NodeSettings, len(recipients))
	for i := range recipients {
		n := &recipients[i].Section.Node
		nodes[n.ID] = n
	}
	addrs := make(map[netip.Addr]bool)
	for _, r := range recipients {
		if n := &r.Section.Node; n.HiddenFromDevices() {
			for _, l := range n.Listeners {
				if !l.Address.Addr().IsUnspecified() {
					addrs[l.Address.Addr()] = true
				}
			}
		}
		for _, l := range r.Section.Links {
			if to, ok := nodes[l.Peer]; ok && to.HiddenFromDevices() {
				for _, e := range l.Endpoints {
					addrs[e.Address.Addr()] = true
				}
			}
		}
	}
	for i, r := range recipients {
		n := &r.Section.Node
		for _, l := range r.Section.Links {
			if to, ok := nodes[l.Peer]; ok && !MayLink(n, to) {
				return fmt.Errorf("recipient %d: a %v links to %v, a %v: no links between devices and servers with ingress off", i, n.Kind, l.Peer, to.Kind)
			}
			if n.Kind != NodeDevice {
				continue
			}
			for _, e := range l.Endpoints {
				if addrs[e.Address.Addr()] {
					return fmt.Errorf("recipient %d: a device dials %v, an address of a server with ingress off", i, e.Address)
				}
			}
		}
		for _, in := range r.Section.Inbound {
			from, ok := nodes[in.Peer]
			switch {
			case !ok:
			case from.Kind != in.PeerKind:
				return fmt.Errorf("recipient %d: inbound link from %v as a %v, which is a %v", i, in.Peer, in.PeerKind, from.Kind)
			case !MayLink(n, from):
				return fmt.Errorf("recipient %d: a %v accepts %v, a %v: no links between devices and servers with ingress off", i, n.Kind, in.Peer, from.Kind)
			}
		}
	}
	return nil
}

// Build seals each section to its recipient, pads, shuffles and signs, and
// returns the envelope bytes. Every call seals afresh, so no section is
// shared between two envelopes.
func Build(signingKey ed25519.PrivateKey, c Contents) ([]byte, error) {
	header, err := contentsHeader(signingKey, c)
	if err != nil {
		return nil, err
	}
	count := sectionCount(len(c.Recipients))
	if count > maxSections {
		return nil, fmt.Errorf("%w: %d sections, at most %d", ErrInvalidContents, len(c.Recipients), maxSections)
	}
	plain, err := encodeSections(c.Recipients, &header)
	if err != nil {
		return nil, err
	}
	if err := hiddenFromDevices(c.Recipients); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidContents, err)
	}
	if err := chainsEndAtExits(c.Recipients); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidContents, err)
	}
	size, err := paddedSectionSize(plain, count)
	if err != nil {
		return nil, err
	}
	sealed, err := sealSections(c.Recipients, plain, size, count)
	if err != nil {
		return nil, err
	}
	return signBody(signingKey, &header, sealed)
}

// contentsHeader is the validated header Build writes for c, signed with
// signingKey.
func contentsHeader(signingKey ed25519.PrivateKey, c Contents) (Header, error) {
	if len(signingKey) != ed25519.PrivateKeySize {
		return Header{}, fmt.Errorf("%w: signing key of %d bytes", ErrInvalidContents, len(signingKey))
	}
	header := Header{
		SpaceID:     c.SpaceID,
		KeyEpoch:    c.KeyEpoch,
		Version:     c.Version,
		SigningKey:  signingKey.Public().(ed25519.PublicKey),
		RecoveryKey: c.RecoveryKey,
		Blobs:       c.Blobs,
	}
	if err := header.validate(); err != nil {
		return Header{}, fmt.Errorf("%w: %v", ErrInvalidContents, err)
	}
	return header, nil
}

// encodeSections validates each recipient's key and section, checks that
// no key or node repeats, and returns the encoded sections, unpadded.
func encodeSections(recipients []Recipient, header *Header) ([][]byte, error) {
	keys := make(map[NodePublicKey]bool, len(recipients))
	nodes := make(map[NodeID]bool, len(recipients))
	plain := make([][]byte, len(recipients))
	for i, r := range recipients {
		if err := r.Key.Check(); err != nil {
			return nil, fmt.Errorf("%w: recipient %d: %v", ErrInvalidContents, i, err)
		}
		if keys[r.Key] {
			return nil, fmt.Errorf("%w: recipient %d: key repeated", ErrInvalidContents, i)
		}
		keys[r.Key] = true
		if err := r.Section.validate(header.Blobs); err != nil {
			return nil, fmt.Errorf("%w: recipient %d: %v", ErrInvalidContents, i, err)
		}
		if nodes[r.Section.Node.ID] {
			return nil, fmt.Errorf("%w: recipient %d: node %v has two sections", ErrInvalidContents, i, r.Section.Node.ID)
		}
		nodes[r.Section.Node.ID] = true
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(sectionToProto(&r.Section, header))
		if err != nil {
			return nil, fmt.Errorf("netmap: encoding section %d: %w", i, err)
		}
		plain[i] = b
	}
	return plain, nil
}

// paddedSectionSize is the size every section is padded to, given the
// encoded sections and the section count, refused when the sections can't
// fit in an envelope.
func paddedSectionSize(plain [][]byte, count int) (int, error) {
	largest := 0
	for _, b := range plain {
		largest = max(largest, len(b))
	}
	size := sectionSize(largest)
	if size > maxSectionSize {
		return 0, fmt.Errorf("%w: a section of %d bytes, at most %d", ErrInvalidContents, largest, maxSectionSize-1)
	}
	// The sealed sections alone, with their exact framing (a SealedSection
	// field inside a Body field), are a lower bound of the envelope's size:
	// refuse before sealing anything when even they don't fit. The check
	// after signing covers the header and the outer framing.
	sealedField := protowire.SizeTag(1) + protowire.SizeBytes(size+box.AnonymousOverhead)
	if total := count * (protowire.SizeTag(3) + protowire.SizeBytes(sealedField)); total > MaxEnvelopeSize {
		return 0, fmt.Errorf("%w: %w: %d sections of %d bytes take %d bytes", ErrInvalidContents, errSectionsExceedEnvelope, count, size, total)
	}
	return size, nil
}

// sealSections pads and seals each section to its recipient, adds dummy
// sections up to count and shuffles them all.
func sealSections(recipients []Recipient, plain [][]byte, size, count int) ([][]byte, error) {
	sealed := make([][]byte, 0, count)
	for i, r := range recipients {
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
	return sealed, nil
}

// signBody encodes the body of header and the sealed sections, signs
// it and returns the envelope bytes.
func signBody(signingKey ed25519.PrivateKey, header *Header, sealed [][]byte) ([]byte, error) {
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
	env := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), bodyBytes)
	env = protowire.AppendBytes(protowire.AppendTag(env, 2, protowire.BytesType), sig)
	if len(env) > MaxEnvelopeSize {
		return nil, fmt.Errorf("%w: envelope of %d bytes, at most %d", ErrInvalidContents, len(env), MaxEnvelopeSize)
	}
	return env, nil
}

// Verify checks that envelope is a well-formed map signed with
// trust.SigningKey, of trust.SpaceID and with trust.RecoveryKey when those
// are set, and returns it. The signature is checked over the exact body
// bytes before anything inside is decoded.
func Verify(envelope []byte, trust Trust) (*Map, error) {
	if len(trust.SigningKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("netmap: trusted signing key of %d bytes", len(trust.SigningKey))
	}
	if len(envelope) > MaxEnvelopeSize {
		return nil, fmt.Errorf("%w: envelope of %d bytes, at most %d", ErrMalformed, len(envelope), MaxEnvelopeSize)
	}
	// One copy, read once: the caller may change its buffer at any time.
	envelope = bytes.Clone(envelope)
	body, sig, err := parseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	if ed25519.VerifyWithOptions(trust.SigningKey, body, sig, &ed25519.Options{Context: signatureContext}) != nil {
		return nil, ErrBadSignature
	}

	if f, err := scanVarint(body, 1); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	} else if f != Format {
		return nil, fmt.Errorf("%w: format %d, this node reads %d", ErrUnsupportedFormat, f, Format)
	}
	var b netmapv1.Body
	if err := proto.Unmarshal(body, &b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if b.GetFormat() != Format {
		return nil, fmt.Errorf("%w: format field repeated", ErrMalformed)
	}
	header, err := headerFromProto(b.GetHeader())
	if err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	if !bytes.Equal(header.SigningKey, trust.SigningKey) {
		return nil, fmt.Errorf("%w: header names another signing key", ErrMalformed)
	}
	if !trust.SpaceID.IsZero() && header.SpaceID != trust.SpaceID {
		return nil, ErrOtherSpace
	}
	if len(trust.RecoveryKey) != 0 && !bytes.Equal(header.RecoveryKey, trust.RecoveryKey) {
		return nil, fmt.Errorf("%w: another recovery key", ErrKeysChanged)
	}

	n := len(b.GetSections())
	if !isPowerOfTwo(n) || n < minSections || n > maxSections {
		return nil, fmt.Errorf("%w: %d sections", ErrMalformed, n)
	}
	sections := make([][]byte, n)
	for i, s := range b.GetSections() {
		sections[i] = s.GetSealed()
		if len(sections[i]) != len(sections[0]) {
			return nil, fmt.Errorf("%w: sections of different lengths", ErrMalformed)
		}
	}
	if size := len(sections[0]) - box.AnonymousOverhead; !isPowerOfTwo(size) || size < minSectionSize || size > maxSectionSize {
		return nil, fmt.Errorf("%w: sections of %d bytes", ErrMalformed, len(sections[0]))
	}
	return &Map{verified: true, raw: envelope, header: header, sections: sections}, nil
}

// parseEnvelope splits a canonical envelope into its body and signature
// without copying: field 1, then field 2 holding 64 bytes, each with a
// minimal tag and length, and nothing after but recovery records.
func parseEnvelope(b []byte) (body, sig []byte, err error) {
	if body, b, err = consumeBytesField(b, 1); err != nil {
		return nil, nil, err
	}
	if sig, b, err = consumeBytesField(b, 2); err != nil {
		return nil, nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("%w: signature of %d bytes", ErrMalformed, len(sig))
	}
	if len(b) > 0 {
		if num, typ, n := protowire.ConsumeTag(b); n > 0 && num == 3 && typ == protowire.BytesType {
			return nil, nil, fmt.Errorf("%w: the envelope carries recovery records", ErrUnsupportedFormat)
		}
		return nil, nil, fmt.Errorf("%w: trailing bytes after the signature", ErrMalformed)
	}
	return body, sig, nil
}

func consumeBytesField(b []byte, want protowire.Number) (value, rest []byte, err error) {
	num, typ, n := protowire.ConsumeTag(b)
	if n < 0 || num != want || typ != protowire.BytesType || n != protowire.SizeTag(num) {
		return nil, nil, fmt.Errorf("%w: envelope field %d missing or not canonical", ErrMalformed, want)
	}
	b = b[n:]
	value, n = protowire.ConsumeBytes(b)
	if n < 0 || n != protowire.SizeBytes(len(value)) {
		return nil, nil, fmt.Errorf("%w: envelope field %d not canonical", ErrMalformed, want)
	}
	return value, b[n:], nil
}

// Open finds and decrypts the section sealed to key. A node can open only
// its own section; every other section, dummies included, looks the same
// to it. Only reader checks run here (lengths, encodings, ids); builder
// policy is Build's.
func (m *Map) Open(key NodePrivateKey) (Section, error) {
	if err := m.usable(); err != nil {
		return Section{}, err
	}
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
	reader, err := scanVarint(content, 1)
	switch {
	case err != nil:
		return Section{}, fmt.Errorf("%w: section: %v", ErrMalformed, err)
	case reader == 0:
		return Section{}, fmt.Errorf("%w: section without a reader version", ErrMalformed)
	case reader > SectionReader:
		return Section{}, fmt.Errorf("%w: section needs reader %d, this node is %d", ErrUnsupportedFormat, reader, SectionReader)
	}
	var pb netmapv1.Section
	if err := proto.Unmarshal(content, &pb); err != nil {
		return Section{}, fmt.Errorf("%w: section: %v", ErrMalformed, err)
	}
	h := &m.header
	if uint64(pb.GetMinReader()) != reader || !bytes.Equal(pb.GetSpaceId(), h.SpaceID[:]) ||
		pb.GetKeyEpoch() != h.KeyEpoch || pb.GetMapVersion() != h.Version {
		return Section{}, fmt.Errorf("%w: section belongs to another map", ErrMalformed)
	}
	s, err := sectionFromProto(&pb)
	if err == nil {
		err = s.wellFormed()
	}
	switch {
	case errors.Is(err, ErrUnsupportedFormat):
		return Section{}, err
	case err != nil:
		return Section{}, fmt.Errorf("%w: section: %v", ErrMalformed, err)
	}
	s.MinReader = uint32(reader)
	return s, nil
}

// Accept reports whether a node running current may switch to candidate:
// same space, keys and key epoch, and a strictly higher version. A nil
// current accepts any verified candidate. Both maps must come from Verify,
// which is where the trusted signing key is checked; [Map.Next] does both.
func Accept(current, candidate *Map) error {
	if err := candidate.usable(); err != nil {
		return err
	}
	if current == nil {
		return nil
	}
	if err := current.usable(); err != nil {
		return err
	}
	cur, cand := &current.header, &candidate.header
	if cand.SpaceID != cur.SpaceID {
		return ErrOtherSpace
	}
	if cand.KeyEpoch != cur.KeyEpoch {
		return fmt.Errorf("%w: key epoch %d, running %d", ErrKeysChanged, cand.KeyEpoch, cur.KeyEpoch)
	}
	if !bytes.Equal(cand.SigningKey, cur.SigningKey) || !bytes.Equal(cand.RecoveryKey, cur.RecoveryKey) {
		return ErrKeysChanged
	}
	if cand.Version <= cur.Version {
		return fmt.Errorf("%w: version %d, running %d", ErrNotNewer, cand.Version, cur.Version)
	}
	return nil
}

// wellFormed is what every reader checks in a header.
func (h *Header) wellFormed() error {
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
	return blobsWellFormed(h.Blobs)
}

// validate is Build's check of a header.
func (h *Header) validate() error {
	if err := h.wellFormed(); err != nil {
		return err
	}
	if h.Version > MaxVersion {
		return fmt.Errorf("version %d above %d", h.Version, uint64(MaxVersion))
	}
	for _, b := range h.Blobs {
		if !b.Kind.known() {
			return fmt.Errorf("blob %x: kind %v", b.SHA256, b.Kind)
		}
		if b.Name != "" {
			return fmt.Errorf("blob %x: named in the header", b.SHA256)
		}
	}
	return nil
}

func (h *Header) toProto() *netmapv1.Header {
	return &netmapv1.Header{
		SpaceId:           bytes.Clone(h.SpaceID[:]),
		KeyEpoch:          h.KeyEpoch,
		Version:           h.Version,
		SigningPublicKey:  h.SigningKey,
		RecoveryPublicKey: h.RecoveryKey,
		Blobs:             blobsToProto(h.Blobs),
	}
}

func headerFromProto(pb *netmapv1.Header) (Header, error) {
	var h Header
	if pb == nil {
		return h, errors.New("missing")
	}
	var err error
	if h.SpaceID, err = toArray[SpaceID]("space id", pb.GetSpaceId()); err != nil {
		return h, err
	}
	h.KeyEpoch = pb.GetKeyEpoch()
	h.Version = pb.GetVersion()
	h.SigningKey = bytes.Clone(pb.GetSigningPublicKey())
	h.RecoveryKey = bytes.Clone(pb.GetRecoveryPublicKey())
	if h.Blobs, err = blobsFromProto(pb.GetBlobs()); err != nil {
		return h, err
	}
	return h, h.wellFormed()
}

// scanVarint reads varint field num of a serialized message without
// decoding the rest, which a newer layout may lay out differently. An
// absent field reads as 0.
func scanVarint(b []byte, num protowire.Number) (uint64, error) {
	for len(b) > 0 {
		n, typ, l := protowire.ConsumeTag(b)
		if l < 0 {
			return 0, protowire.ParseError(l)
		}
		b = b[l:]
		if n == num && typ == protowire.VarintType {
			v, l := protowire.ConsumeVarint(b)
			if l < 0 {
				return 0, protowire.ParseError(l)
			}
			return v, nil
		}
		l = protowire.ConsumeFieldValue(n, typ, b)
		if l < 0 {
			return 0, protowire.ParseError(l)
		}
		b = b[l:]
	}
	return 0, nil
}
