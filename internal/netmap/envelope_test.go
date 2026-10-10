package netmap

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"math"
	mrand "math/rand/v2"
	"net/netip"
	"reflect"
	"testing"

	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	netmapv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/netmap/v1"
)

// signEnvelope wraps a serialized body as the space admin would, so tests
// can hand-craft signed content that Build would refuse to make.
func signEnvelope(t testing.TB, priv ed25519.PrivateKey, body []byte) []byte {
	t.Helper()
	sig, err := priv.Sign(nil, body, &ed25519.Options{Context: signatureContext})
	if err != nil {
		t.Fatal(err)
	}
	env, err := proto.MarshalOptions{Deterministic: true}.Marshal(&netmapv1.Envelope{Body: body, Signature: sig})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func marshal(t testing.TB, m proto.Message) []byte {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// decodeBody returns the decoded body of a valid envelope, for tests that
// tamper with it and re-sign.
func decodeBody(t testing.TB, env []byte) *netmapv1.Body {
	t.Helper()
	var e netmapv1.Envelope
	var b netmapv1.Body
	if err := proto.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(e.GetBody(), &b); err != nil {
		t.Fatal(err)
	}
	return &b
}

func seal(t testing.TB, to NodePublicKey, plain []byte) []byte {
	t.Helper()
	s, err := box.SealAnonymous(nil, plain, (*[32]byte)(&to), nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name             string
		servers, devices int
		wantSections     int
	}{
		{"empty space", 0, 0, 8},
		{"one server", 1, 0, 8},
		{"M0 lab", 1, 2, 8},
		{"exactly eight", 2, 6, 8},
		{"nine pads to sixteen", 2, 7, 16},
		{"thirty", 10, 20, 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, tt.servers, tt.devices)
			env := f.build(t)
			m := f.verify(t, env)

			if got := m.SectionCount(); got != tt.wantSections {
				t.Errorf("SectionCount() = %d, want %d", got, tt.wantSections)
			}
			h := m.Header()
			want := Header{
				SpaceID: f.contents.SpaceID, Version: f.contents.Version,
				SigningKey: f.signingPublic(), RecoveryKey: f.contents.RecoveryKey, Blobs: f.contents.Blobs,
			}
			if !reflect.DeepEqual(h, want) {
				t.Errorf("Header() = %+v, want %+v", h, want)
			}
			if !bytes.Equal(m.Bytes(), env) {
				t.Error("Bytes() differs from the verified envelope")
			}
			for i, r := range f.contents.Sections {
				got, err := Open(m, f.keys[i])
				if err != nil {
					t.Fatalf("node %d: Open: %v", i, err)
				}
				if !reflect.DeepEqual(got, r.Section) {
					t.Errorf("node %d: Open() = %+v, want %+v", i, got, r.Section)
				}
			}
		})
	}
}

func TestMapIsImmutable(t *testing.T) {
	f := newFixture(t, 1, 1)
	env := f.build(t)
	m := f.verify(t, env)

	clear(env) // the caller reuses its buffer
	h := m.Header()
	h.SigningKey[0] ^= 0xff
	h.Blobs[0].Size = 0
	b := m.Bytes()
	b[1] ^= 0xff

	if _, err := Verify(m.Bytes(), f.signingPublic()); err != nil {
		t.Fatalf("map changed through a returned or passed slice: %v", err)
	}
	if got := m.Header(); !bytes.Equal(got.SigningKey, f.signingPublic()) || got.Blobs[0].Size != 4096 {
		t.Fatal("header changed through a returned slice")
	}
	for i, key := range f.keys {
		if _, err := Open(m, key); err != nil {
			t.Fatalf("node %d: sections changed through the caller's buffer: %v", i, err)
		}
	}
}

func TestVerifyRejectsAnyChangedByte(t *testing.T) {
	f := newFixture(t, 1, 2)
	env := f.build(t)
	pub := f.signingPublic()
	for i := range env {
		for _, x := range []byte{0x01, 0x80, 0xff} {
			tampered := bytes.Clone(env)
			tampered[i] ^= x
			if _, err := Verify(tampered, pub); err == nil {
				t.Fatalf("byte %d xor %#x: Verify accepted a tampered envelope", i, x)
			}
		}
	}
}

func TestVerifyRejectsTruncatedOrExtended(t *testing.T) {
	f := newFixture(t, 1, 2)
	env := f.build(t)
	pub := f.signingPublic()
	for n := range len(env) {
		if _, err := Verify(env[:n], pub); err == nil {
			t.Fatalf("Verify accepted the envelope truncated to %d of %d bytes", n, len(env))
		}
	}
	suffixes := map[string][]byte{
		"zero byte":            {0},
		"unknown varint field": protowire.AppendVarint(protowire.AppendTag(nil, 15, protowire.VarintType), 1),
		"reserved field 3":     protowire.AppendBytes(protowire.AppendTag(nil, 3, protowire.BytesType), []byte("record")),
		"repeated signature":   protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), make([]byte, 64)),
		"repeated body":        protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), nil),
	}
	for name, suffix := range suffixes {
		if _, err := Verify(append(bytes.Clone(env), suffix...), pub); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s appended: err = %v, want ErrMalformed", name, err)
		}
	}
}

func TestVerifyRejectsNonCanonicalEnvelope(t *testing.T) {
	f := newFixture(t, 1, 1)
	env := f.build(t)
	var e netmapv1.Envelope
	if err := proto.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	// The same two fields, signature first: decodes to the same message.
	swapped := protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), e.GetSignature())
	swapped = protowire.AppendBytes(protowire.AppendTag(swapped, 1, protowire.BytesType), e.GetBody())
	// The body's length as a needlessly long varint.
	l := len(e.GetBody())
	padded := protowire.AppendTag(nil, 1, protowire.BytesType)
	padded = append(padded, byte(l&0x7f|0x80), byte(l>>7&0x7f|0x80), byte(l>>14&0x7f|0x80), 0x00)
	padded = append(padded, e.GetBody()...)
	padded = protowire.AppendBytes(protowire.AppendTag(padded, 2, protowire.BytesType), e.GetSignature())

	for name, b := range map[string][]byte{"fields swapped": swapped, "padded varint length": padded} {
		var check netmapv1.Envelope
		if err := proto.Unmarshal(b, &check); err != nil || !proto.Equal(&check, &e) {
			t.Fatalf("%s: test input doesn't decode to the original envelope: %v", name, err)
		}
		if _, err := Verify(b, f.signingPublic()); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

func TestVerifyRejectsWrongKeys(t *testing.T) {
	f := newFixture(t, 1, 1)
	env := f.build(t)
	body := decodeBody(t, env)

	// Signed with the recovery key, which the header names as the signing key.
	byRecovery, err := Build(f.recovery, Contents{
		SpaceID: f.contents.SpaceID, Version: 2, RecoveryKey: f.signingPublic(), Sections: f.contents.Sections,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The real signing key over the real body, without the map context.
	plainSig := ed25519.Sign(f.signing, marshal(t, body))
	noContext := marshal(t, &netmapv1.Envelope{Body: marshal(t, body), Signature: plainSig})
	// A body naming another signing key, signed by the trusted one.
	other := newKeyPair(t)
	body.Header.SigningPublicKey = other.Public().(ed25519.PublicKey)
	namesOther := signEnvelope(t, f.signing, marshal(t, body))

	tests := []struct {
		name string
		env  []byte
		key  ed25519.PublicKey
		want error
	}{
		{"another signing key", env, other.Public().(ed25519.PublicKey), ErrBadSignature},
		{"the recovery key", env, f.contents.RecoveryKey, ErrBadSignature},
		{"signed by the recovery key", byRecovery, f.signingPublic(), ErrBadSignature},
		{"signature without context", noContext, f.signingPublic(), ErrBadSignature},
		{"header names another key", namesOther, f.signingPublic(), ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Verify(tt.env, tt.key); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
	for _, key := range []ed25519.PublicKey{nil, make([]byte, 31)} {
		if _, err := Verify(env, key); err == nil {
			t.Errorf("Verify accepted a signing key of %d bytes", len(key))
		}
	}
}

func TestVerifyRejectsBadSignedBodies(t *testing.T) {
	f := newFixture(t, 1, 2)
	env := f.build(t)

	tests := []struct {
		name   string
		mutate func(b *netmapv1.Body) []byte // returns the body bytes to sign
		want   error
	}{
		{"format 2", func(b *netmapv1.Body) []byte { b.Format = 2; return marshal(t, b) }, ErrUnsupportedFormat},
		{"format missing", func(b *netmapv1.Body) []byte { b.Format = 0; return marshal(t, b) }, ErrUnsupportedFormat},
		{"format 1 then 2", func(b *netmapv1.Body) []byte {
			return protowire.AppendVarint(protowire.AppendTag(marshal(t, b), 1, protowire.VarintType), 2)
		}, ErrMalformed},
		{"future layout", func(b *netmapv1.Body) []byte {
			// format 2 with field 2 as a varint: unreadable as a v1 body
			out := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 2)
			return protowire.AppendVarint(protowire.AppendTag(out, 2, protowire.VarintType), 7)
		}, ErrUnsupportedFormat},
		{"not protobuf", func(*netmapv1.Body) []byte { return []byte{0xff, 0xff, 0xff} }, ErrMalformed},
		{"no header", func(b *netmapv1.Body) []byte { b.Header = nil; return marshal(t, b) }, ErrMalformed},
		{"zero version", func(b *netmapv1.Body) []byte { b.Header.Version = 0; return marshal(t, b) }, ErrMalformed},
		{"short space id", func(b *netmapv1.Body) []byte { b.Header.SpaceId = b.Header.SpaceId[:15]; return marshal(t, b) }, ErrMalformed},
		{"zero space id", func(b *netmapv1.Body) []byte { b.Header.SpaceId = make([]byte, 16); return marshal(t, b) }, ErrMalformed},
		{"no recovery key", func(b *netmapv1.Body) []byte { b.Header.RecoveryPublicKey = nil; return marshal(t, b) }, ErrMalformed},
		{"recovery key is the signing key", func(b *netmapv1.Body) []byte {
			b.Header.RecoveryPublicKey = b.Header.SigningPublicKey
			return marshal(t, b)
		}, ErrMalformed},
		{"short blob hash", func(b *netmapv1.Body) []byte { b.Header.Blobs[0].Sha256 = []byte{1}; return marshal(t, b) }, ErrMalformed},
		{"repeated blob", func(b *netmapv1.Body) []byte {
			b.Header.Blobs = append(b.Header.Blobs, b.Header.Blobs[0])
			return marshal(t, b)
		}, ErrMalformed},
		{"seven sections", func(b *netmapv1.Body) []byte { b.Sections = b.Sections[:7]; return marshal(t, b) }, ErrMalformed},
		{"nine sections", func(b *netmapv1.Body) []byte {
			b.Sections = append(b.Sections, b.Sections[0])
			return marshal(t, b)
		}, ErrMalformed},
		{"four sections", func(b *netmapv1.Body) []byte { b.Sections = b.Sections[:4]; return marshal(t, b) }, ErrMalformed},
		{"unequal lengths", func(b *netmapv1.Body) []byte {
			b.Sections[3].Sealed = append(b.Sections[3].Sealed, 0)
			return marshal(t, b)
		}, ErrMalformed},
		{"sections below the minimum size", func(b *netmapv1.Body) []byte {
			for _, s := range b.Sections {
				s.Sealed = s.Sealed[:box.AnonymousOverhead+512]
			}
			return marshal(t, b)
		}, ErrMalformed},
		{"sections not a bucket size", func(b *netmapv1.Body) []byte {
			for _, s := range b.Sections {
				s.Sealed = append(s.Sealed, 0)
			}
			return marshal(t, b)
		}, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := signEnvelope(t, f.signing, tt.mutate(decodeBody(t, env)))
			if _, err := Verify(tampered, f.signingPublic()); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerifyRejectsOversizedEnvelope(t *testing.T) {
	f := newFixture(t, 0, 1)
	big := make([]byte, MaxEnvelopeSize+1)
	if _, err := Verify(big, f.signingPublic()); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}

func TestOpenOnlyOwnSection(t *testing.T) {
	f := newFixture(t, 3, 6)
	m := f.verify(t, f.build(t))

	// Each key opens exactly one sealed box, its own; nobody opens a dummy.
	opened := make([]int, len(m.sections))
	for i, key := range f.keys {
		pub := key.Public()
		count := 0
		for j, s := range m.sections {
			if _, ok := box.OpenAnonymous(nil, s, (*[32]byte)(&pub), (*[32]byte)(&key)); ok {
				count++
				opened[j]++
			}
		}
		if count != 1 {
			t.Errorf("node %d opens %d sections, want 1", i, count)
		}
		got, err := Open(m, key)
		if err != nil {
			t.Fatalf("node %d: %v", i, err)
		}
		if got.Node.ID != f.contents.Sections[i].Section.Node.ID {
			t.Errorf("node %d opened the section of node %v", i, got.Node.ID)
		}
	}
	dummies := 0
	for _, n := range opened {
		if n > 1 {
			t.Error("a section opens for more than one node")
		}
		if n == 0 {
			dummies++
		}
	}
	if want := m.SectionCount() - len(f.keys); dummies != want {
		t.Errorf("%d sections open for nobody, want %d dummies", dummies, want)
	}

	// A node using another node's public key with its own private key, or a
	// stranger's key, gets nothing.
	stranger := GenerateNodeKey()
	if _, err := Open(m, stranger); !errors.Is(err, ErrNotRecipient) {
		t.Errorf("stranger: err = %v, want ErrNotRecipient", err)
	}
	pub1 := f.keys[1].Public()
	for _, s := range m.sections {
		if _, ok := box.OpenAnonymous(nil, s, (*[32]byte)(&pub1), (*[32]byte)(&f.keys[0])); ok {
			t.Error("node 0 opened a section with node 1's public key")
		}
	}
}

func TestOpenRejectsBadSections(t *testing.T) {
	f := newFixture(t, 1, 1)
	env := f.build(t)
	key := f.keys[1]
	pub := key.Public()
	sec := f.contents.Sections[1].Section
	space, version := f.contents.SpaceID, f.contents.Version

	plainFor := func(pb *netmapv1.Section) []byte { return pad(marshal(t, pb), minSectionSize) }
	// replace re-signs the envelope with section 0 replaced (and, if extra
	// is set, section 1 too).
	replace := func(first []byte, extra []byte) *Map {
		b := decodeBody(t, env)
		b.Sections[0].Sealed = first
		if extra != nil {
			b.Sections[1].Sealed = extra
		}
		// Drop the real section of key so only the crafted one opens.
		real := -1
		for i, s := range b.Sections {
			if _, ok := box.OpenAnonymous(nil, s.GetSealed(), (*[32]byte)(&pub), (*[32]byte)(&key)); ok && i > 1 {
				real = i
			}
		}
		if real > 0 {
			b.Sections[real].Sealed = seal(t, GenerateNodeKey().Public(), make([]byte, minSectionSize))
		}
		return f.verify(t, signEnvelope(t, f.signing, marshal(t, b)))
	}

	otherSpace := sectionToProto(&sec, NewSpaceID(), version)
	oldVersion := sectionToProto(&sec, space, version-1)
	badAddr := sectionToProto(&sec, space, version)
	badAddr.Node.Ipv6 = "FD12:3456:789A::2"
	invalid := sectionToProto(&sec, space, version)
	invalid.Node.Ipv4Network = "10.0.0.0/8"
	unpadded := marshal(t, sectionToProto(&sec, space, version))
	unpadded = append(unpadded, make([]byte, minSectionSize-len(unpadded))...)
	good := seal(t, pub, plainFor(sectionToProto(&sec, space, version)))

	tests := []struct {
		name string
		m    *Map
	}{
		{"another space", replace(seal(t, pub, plainFor(otherSpace)), nil)},
		{"older version replayed", replace(seal(t, pub, plainFor(oldVersion)), nil)},
		{"non-canonical address", replace(seal(t, pub, plainFor(badAddr)), nil)},
		{"invalid section", replace(seal(t, pub, plainFor(invalid)), nil)},
		{"no padding marker", replace(seal(t, pub, unpadded), nil)},
		{"not protobuf", replace(seal(t, pub, pad([]byte{0xff, 0xff}, minSectionSize)), nil)},
		{"two sections for one key", replace(good, good)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Open(tt.m, key); !errors.Is(err, ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
	// The crafted section on its own does open: the cases above fail for
	// their own reason.
	if _, err := Open(replace(good, nil), key); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// TestPaddingHidesSections checks S6 over many generated maps: the section
// count depends only on its power-of-two bucket, every section of an
// envelope has the same length, dummies have the same structure as real
// sealed boxes, and real sections land in uniformly random positions.
func TestPaddingHidesSections(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(1, 2))
	for range 100 {
		f := newFixture(t, rng.IntN(4), rng.IntN(14))
		m := f.verify(t, f.build(t))
		n := len(f.contents.Sections)
		if got, want := m.SectionCount(), sectionCount(n); got != want {
			t.Fatalf("%d nodes: %d sections, want %d", n, got, want)
		}
		for _, s := range m.sections {
			if len(s) != len(m.sections[0]) {
				t.Fatalf("%d nodes: sections of different lengths", n)
			}
			// A sealed box starts with an X25519 public key, whose top bit is
			// never set; random filler would set it half the time.
			if s[31]&0x80 != 0 {
				t.Fatalf("%d nodes: a section doesn't start with an X25519 public key", n)
			}
		}
	}

	// Positions: three real sections among eight, over many maps.
	const maps = 400
	var hits [minSections]int
	f := newFixture(t, 1, 2)
	for range maps {
		m := f.verify(t, f.build(t))
		for _, key := range f.keys {
			pub := key.Public()
			for j, s := range m.sections {
				if _, ok := box.OpenAnonymous(nil, s, (*[32]byte)(&pub), (*[32]byte)(&key)); ok {
					hits[j]++
				}
			}
		}
	}
	expected := float64(maps*len(f.keys)) / minSections
	chi2 := 0.0
	for _, h := range hits {
		chi2 += math.Pow(float64(h)-expected, 2) / expected
	}
	// 7 degrees of freedom: p = 0.0001 at 29.88.
	if chi2 > 29.88 {
		t.Errorf("real sections are not uniformly placed: hits %v, chi² %.1f", hits, chi2)
	}
}

func TestSectionLengthHidesRole(t *testing.T) {
	// A server's small section and a device's larger one are padded to the
	// same length, and the length depends only on the largest section.
	f := newFixture(t, 2, 5)
	m := f.verify(t, f.build(t))
	if got := len(m.sections[0]) - box.AnonymousOverhead; !isPowerOfTwo(got) || got < minSectionSize {
		t.Fatalf("padded section of %d bytes", got)
	}
	g := newFixture(t, 2, 5)
	g.contents.Sections = g.contents.Sections[2:] // devices only
	gm := g.verify(t, g.build(t))
	if len(gm.sections[0]) != len(m.sections[0]) || len(gm.Bytes()) != len(m.Bytes()) {
		t.Errorf("dropping the servers changed the section or envelope length: %d/%d vs %d/%d",
			len(gm.sections[0]), len(gm.Bytes()), len(m.sections[0]), len(m.Bytes()))
	}
}

func TestBuildSealsAfresh(t *testing.T) {
	f := newFixture(t, 1, 2)
	a := f.verify(t, f.build(t))
	b := f.verify(t, f.build(t))
	seen := map[string]bool{}
	for _, s := range append(append([][]byte{}, a.sections...), b.sections...) {
		if seen[string(s[:32])] {
			t.Fatal("two sections share an ephemeral key")
		}
		seen[string(s[:32])] = true
	}
}

func TestAccept(t *testing.T) {
	f := newFixture(t, 1, 1)
	at := func(t *testing.T, c Contents, signing ed25519.PrivateKey) *Map {
		t.Helper()
		env, err := Build(signing, c)
		if err != nil {
			t.Fatal(err)
		}
		m, err := Verify(env, signing.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	withVersion := func(v uint64) Contents { c := f.contents; c.Version = v; return c }
	current := at(t, withVersion(5), f.signing)

	otherSpace := withVersion(6)
	otherSpace.SpaceID = NewSpaceID()
	otherRecovery := withVersion(6)
	otherRecovery.RecoveryKey = newKeyPair(t).Public().(ed25519.PublicKey)

	tests := []struct {
		name      string
		current   *Map
		candidate *Map
		want      error
	}{
		{"first map", nil, at(t, withVersion(1), f.signing), nil},
		{"next version", current, at(t, withVersion(6), f.signing), nil},
		{"version jump", current, at(t, withVersion(math.MaxUint64), f.signing), nil},
		{"same version", current, at(t, withVersion(5), f.signing), ErrNotNewer},
		{"same map", current, current, ErrNotNewer},
		{"rollback", current, at(t, withVersion(4), f.signing), ErrNotNewer},
		{"rollback to first", current, at(t, withVersion(1), f.signing), ErrNotNewer},
		{"another space", current, at(t, otherSpace, f.signing), ErrOtherSpace},
		{"another signing key", current, at(t, withVersion(6), newKeyPair(t)), ErrKeysChanged},
		{"another recovery key", current, at(t, otherRecovery, f.signing), ErrKeysChanged},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Accept(tt.current, tt.candidate); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
	if err := Accept(current, nil); err == nil {
		t.Error("Accept accepted a nil candidate")
	}
}

func TestBuildRejectsInvalidContents(t *testing.T) {
	f := newFixture(t, 1, 2)
	type mutation func(c *Contents)
	section := func(i int, m func(s *Section)) mutation {
		return func(c *Contents) {
			secs := append([]Recipient(nil), c.Sections...)
			s := secs[i].Section
			s.Node.Listeners = append([]Listener(nil), s.Node.Listeners...)
			s.Peers = append([]Peer(nil), s.Peers...)
			s.Links = append([]Link(nil), s.Links...)
			s.Inbound = append([]InboundLink(nil), s.Inbound...)
			s.RelayTo = append([]NodeID(nil), s.RelayTo...)
			m(&s)
			secs[i].Section = s
			c.Sections = secs
		}
	}
	server := func(m func(s *Section)) mutation { return section(0, m) }
	device := func(m func(s *Section)) mutation { return section(1, m) }
	serverID := f.contents.Sections[0].Section.Node.ID

	tests := []struct {
		name   string
		mutate mutation
	}{
		{"zero space id", func(c *Contents) { c.SpaceID = SpaceID{} }},
		{"zero version", func(c *Contents) { c.Version = 0 }},
		{"no recovery key", func(c *Contents) { c.RecoveryKey = nil }},
		{"recovery key is the signing key", func(c *Contents) { c.RecoveryKey = f.signingPublic() }},
		{"zero blob hash", func(c *Contents) { c.Blobs = []BlobRef{{}} }},
		{"repeated blob", func(c *Contents) { c.Blobs = []BlobRef{{SHA256: [32]byte{9}}, {SHA256: [32]byte{9}}} }},
		{"zero recipient key", func(c *Contents) {
			c.Sections = append([]Recipient(nil), c.Sections...)
			c.Sections[0].Key = NodePublicKey{}
		}},
		{"repeated recipient key", func(c *Contents) {
			c.Sections = append([]Recipient(nil), c.Sections...)
			c.Sections[1].Key = c.Sections[0].Key
		}},
		{"two sections for one node", func(c *Contents) {
			c.Sections = append([]Recipient(nil), c.Sections...)
			c.Sections[1].Section = c.Sections[0].Section
		}},
		{"zero node id", server(func(s *Section) { s.Node.ID = NodeID{} })},
		{"unknown kind", server(func(s *Section) { s.Node.Kind = 7 })},
		{"IPv4 network outside CGNAT", server(func(s *Section) { s.Node.IPv4Network = netip.MustParsePrefix("10.0.0.0/8") })},
		{"IPv4 network wider than CGNAT", server(func(s *Section) { s.Node.IPv4Network = netip.MustParsePrefix("100.0.0.0/8") })},
		{"IPv4 network not masked", server(func(s *Section) { s.Node.IPv4Network = netip.MustParsePrefix("100.100.0.1/16") })},
		{"IPv6 network not ULA", server(func(s *Section) { s.Node.IPv6Network = netip.MustParsePrefix("2001:db8::/48") })},
		{"IPv6 network is IPv4", server(func(s *Section) { s.Node.IPv6Network = netip.MustParsePrefix("100.100.0.0/16") })},
		{"no IPv6 network", server(func(s *Section) { s.Node.IPv6Network = netip.Prefix{} })},
		{"address outside network", server(func(s *Section) { s.Node.IPv4 = netip.MustParseAddr("100.101.0.1") })},
		{"no IPv6 address", server(func(s *Section) { s.Node.IPv6 = netip.Addr{} })},
		{"bad transport name", server(func(s *Section) { s.Node.Listeners[0].Transport = "UDP" })},
		{"transport name starts with a digit", server(func(s *Section) { s.Node.Listeners[0].Transport = "4udp" })},
		{"long transport name", server(func(s *Section) { s.Node.Listeners[0].Transport = string(bytes.Repeat([]byte("a"), 33)) })},
		{"listener without port", server(func(s *Section) { s.Node.Listeners[0].Address = "0.0.0.0" })},
		{"listener port zero", server(func(s *Section) { s.Node.Listeners[0].Address = ":0" })},
		{"listener port too big", server(func(s *Section) { s.Node.Listeners[0].Address = ":65536" })},
		{"listener port with leading zero", server(func(s *Section) { s.Node.Listeners[0].Address = ":04500" })},
		{"inbound from self", server(func(s *Section) { s.Inbound[0].Peer = serverID })},
		{"inbound repeated", server(func(s *Section) { s.Inbound = append(s.Inbound, s.Inbound[0]) })},
		{"inbound without credential", server(func(s *Section) { s.Inbound[0].Credential = nil })},
		{"inbound credential too long", server(func(s *Section) { s.Inbound[0].Credential = make([]byte, maxCredential+1) })},
		{"relay to self", server(func(s *Section) { s.RelayTo = append(s.RelayTo, serverID) })},
		{"relay to zero", server(func(s *Section) { s.RelayTo = append(s.RelayTo, NodeID{}) })},
		{"relay repeated", server(func(s *Section) { s.RelayTo = append(s.RelayTo, s.RelayTo[0]) })},
		{"link repeated", device(func(s *Section) { s.Links = append(s.Links, s.Links[0]) })},
		{"link without endpoints", device(func(s *Section) { s.Links[0] = Link{Peer: s.Links[0].Peer} })},
		{"endpoint without host", device(func(s *Section) {
			s.Links[0] = Link{Peer: s.Links[0].Peer, Endpoints: []Endpoint{{Transport: "udp", Address: ":4500", Credential: []byte{1}}}}
		})},
		{"peer is self", device(func(s *Section) { s.Peers[0].ID = s.Node.ID })},
		{"peer repeated", device(func(s *Section) { s.Peers = append(s.Peers, s.Peers[0]) })},
		{"peer without WireGuard key", device(func(s *Section) { s.Peers[0].WireGuardKey = WireGuardKey{} })},
		{"peer without addresses", device(func(s *Section) { s.Peers[0].Addresses = nil })},
		{"peer address outside overlay", device(func(s *Section) { s.Peers[0].Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.1")} })},
		{"peer without paths", device(func(s *Section) { s.Peers[0].Paths = nil })},
		{"path through the peer itself", device(func(s *Section) { s.Peers[0].Paths = []Path{{Via: []NodeID{s.Peers[0].ID}}} })},
		{"path through self", device(func(s *Section) { s.Peers[0].Paths = []Path{{Via: []NodeID{s.Node.ID}}} })},
		{"path loops", device(func(s *Section) { s.Peers[0].Paths = []Path{{Via: []NodeID{serverID, serverID}}} })},
		{"too many sections", func(c *Contents) { c.Sections = make([]Recipient, maxSections+1) }},
		{"section too large", device(func(s *Section) {
			for i := range 1100 {
				id := NodeID{byte(i), byte(i >> 8), 1}
				s.Links = append(s.Links, Link{Peer: id, Endpoints: []Endpoint{{Transport: "udp", Address: "192.0.2.1:1", Credential: make([]byte, maxCredential)}}})
			}
		})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := f.contents
			tt.mutate(&c)
			if _, err := Build(f.signing, c); !errors.Is(err, ErrInvalidContents) {
				t.Errorf("err = %v, want ErrInvalidContents", err)
			}
		})
	}
	if _, err := Build(f.signing[:10], f.contents); !errors.Is(err, ErrInvalidContents) {
		t.Errorf("short signing key: err = %v, want ErrInvalidContents", err)
	}
	if _, err := Build(f.signing, f.contents); err != nil {
		t.Fatalf("control: the unmodified contents fail: %v", err)
	}
}

// FuzzVerify: no input panics, and nothing but the original envelope
// verifies under its key.
func FuzzVerify(f *testing.F) {
	fx := newFixture(f, 1, 1)
	env := fx.build(f)
	f.Add(env)
	f.Add(env[:len(env)/2])
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x00, 0x12, 0x00})
	pub := fx.signingPublic()
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Verify(data, pub)
		if err != nil {
			return
		}
		if !bytes.Equal(data, env) {
			t.Fatal("an envelope other than the signed one verified")
		}
		for _, k := range fx.keys {
			if _, err := Open(m, k); err != nil {
				t.Fatal(err)
			}
		}
	})
}
