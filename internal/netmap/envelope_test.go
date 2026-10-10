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
	return marshal(t, &netmapv1.Envelope{Body: body, Signature: sig})
}

func marshal(t testing.TB, m proto.Message) []byte {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeEnvelope(t testing.TB, env []byte) *netmapv1.Envelope {
	t.Helper()
	var e netmapv1.Envelope
	if err := proto.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	return &e
}

// decodeBody returns the decoded body of a valid envelope, for tests that
// tamper with it and re-sign.
func decodeBody(t testing.TB, env []byte) *netmapv1.Body {
	t.Helper()
	var b netmapv1.Body
	if err := proto.Unmarshal(decodeEnvelope(t, env).GetBody(), &b); err != nil {
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

func opens(sealed []byte, key NodePrivateKey) bool {
	pub := key.Public()
	_, ok := box.OpenAnonymous(nil, sealed, (*[32]byte)(&pub), (*[32]byte)(&key))
	return ok
}

func appendUnknownField(b []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(b, 99, protowire.BytesType), []byte("from a newer builder"))
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name             string
		servers, devices int
		wantSections     int
	}{
		{"empty space", 0, 0, 8},
		{"one server", 1, 0, 8},
		{"devices without servers", 0, 2, 8},
		{"M0 lab", 1, 2, 8},
		{"entry and exit", 2, 3, 8},
		{"hop group in the middle", 4, 4, 8},
		{"nine pads to sixteen", 4, 5, 16},
		{"PRD scale", 10, 20, 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, tt.servers, tt.devices)
			env := f.build(t)
			m := f.verify(t, env)

			if got := m.SectionCount(); got != tt.wantSections {
				t.Errorf("SectionCount() = %d, want %d", got, tt.wantSections)
			}
			want := Header{
				SpaceID: f.contents.SpaceID, KeyEpoch: f.contents.KeyEpoch, Version: f.contents.Version,
				SigningKey: f.signingPublic(), RecoveryKey: f.contents.RecoveryKey, Blobs: f.contents.Blobs,
			}
			if h := m.Header(); !reflect.DeepEqual(h, want) {
				t.Errorf("Header() = %+v, want %+v", h, want)
			}
			if tr := m.Trust(); !reflect.DeepEqual(tr, f.trust()) {
				t.Errorf("Trust() = %+v, want %+v", tr, f.trust())
			}
			if !bytes.Equal(m.Bytes(), env) {
				t.Error("Bytes() differs from the verified envelope")
			}
			for i, r := range f.contents.Recipients {
				got, err := m.Open(f.keys[i])
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
	tr := m.Trust()
	tr.RecoveryKey[0] ^= 0xff
	b := m.Bytes()
	b[1] ^= 0xff

	if _, err := Verify(m.Bytes(), f.trust()); err != nil {
		t.Fatalf("map changed through a returned or passed slice: %v", err)
	}
	if got := m.Header(); !bytes.Equal(got.SigningKey, f.signingPublic()) || got.Blobs[0].Size != testGeoIP.Size {
		t.Fatal("header changed through a returned slice")
	}
	for i, key := range f.keys {
		if _, err := m.Open(key); err != nil {
			t.Fatalf("node %d: sections changed through the caller's buffer: %v", i, err)
		}
	}
}

func TestUnverifiedMapIsUseless(t *testing.T) {
	f := newFixture(t, 1, 1)
	good := f.verify(t, f.build(t))
	for name, m := range map[string]*Map{"nil": nil, "zero": {}, "hand-made": {raw: good.raw, header: good.header, sections: good.sections}} {
		t.Run(name, func(t *testing.T) {
			if _, err := m.Open(f.keys[0]); !errors.Is(err, ErrUnverified) {
				t.Errorf("Open: err = %v, want ErrUnverified", err)
			}
			if _, err := m.Next(f.build(t)); !errors.Is(err, ErrUnverified) {
				t.Errorf("Next: err = %v, want ErrUnverified", err)
			}
			if m != nil {
				// A nil current map means "no map yet" and accepts good.
				if err := Accept(m, good); !errors.Is(err, ErrUnverified) {
					t.Errorf("Accept(m, good): err = %v, want ErrUnverified", err)
				}
			}
			if err := Accept(good, m); !errors.Is(err, ErrUnverified) {
				t.Errorf("Accept(good, m): err = %v, want ErrUnverified", err)
			}
			if !reflect.DeepEqual(m.Header(), Header{}) || !reflect.DeepEqual(m.Trust(), Trust{}) || m.Bytes() != nil || m.SectionCount() != 0 {
				t.Error("an unverified map gives out its content")
			}
		})
	}
}

// TestVerifyRejectsChangedBytes flips every byte outside the sealed
// sections (framing, header, signature) with three masks, every byte of one
// sealed section, and a random sample of the others. The bytes of all
// sealed sections play the same part (signed body bytes inside a length-
// delimited field), so one section stands for all; FuzzVerify covers the
// rest at random.
func TestVerifyRejectsChangedBytes(t *testing.T) {
	f := newFixture(t, 1, 2)
	env := f.build(t)
	m := f.verify(t, env)
	inSection := make([]int, len(env)) // section index + 1, or 0
	for i, s := range m.sections {
		at := bytes.Index(env, s)
		for j := range s {
			inSection[at+j] = i + 1
		}
	}
	rng := mrand.New(mrand.NewPCG(3, 4))
	checked := 0
	for i := range env {
		masks := []byte{0x01, 0x80, 0xff}
		switch {
		case inSection[i] == 1:
			masks = masks[:1]
		case inSection[i] > 1 && rng.IntN(32) != 0:
			continue
		case inSection[i] > 1:
			masks = []byte{byte(1 + rng.IntN(255))}
		}
		for _, x := range masks {
			tampered := bytes.Clone(env)
			tampered[i] ^= x
			if _, err := Verify(tampered, f.trust()); err == nil {
				t.Fatalf("byte %d xor %#x: Verify accepted a tampered envelope", i, x)
			}
			checked++
		}
	}
	t.Logf("%d tampered envelopes of %d bytes rejected", checked, len(env))
}

func TestVerifyRejectsTruncatedOrExtended(t *testing.T) {
	f := newFixture(t, 1, 2)
	env := f.build(t)
	for n := range len(env) {
		if _, err := Verify(env[:n], f.trust()); err == nil {
			t.Fatalf("Verify accepted the envelope truncated to %d of %d bytes", n, len(env))
		}
	}
	tests := []struct {
		name   string
		suffix []byte
		want   error
	}{
		{"zero byte", []byte{0}, ErrMalformed},
		{"unknown varint field", protowire.AppendVarint(protowire.AppendTag(nil, 15, protowire.VarintType), 1), ErrMalformed},
		{"repeated signature", protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), make([]byte, 64)), ErrMalformed},
		{"repeated body", protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), nil), ErrMalformed},
		{"recovery record", protowire.AppendBytes(protowire.AppendTag(nil, 3, protowire.BytesType), []byte("record")), ErrUnsupportedFormat},
	}
	for _, tt := range tests {
		if _, err := Verify(append(bytes.Clone(env), tt.suffix...), f.trust()); !errors.Is(err, tt.want) {
			t.Errorf("%s appended: err = %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestVerifyRejectsNonCanonicalEnvelope(t *testing.T) {
	f := newFixture(t, 1, 1)
	e := decodeEnvelope(t, f.build(t))
	body, sig := e.GetBody(), e.GetSignature()
	field := func(b []byte, num protowire.Number, v []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(b, num, protowire.BytesType), v)
	}
	l := len(body)

	swapped := field(field(nil, 2, sig), 1, body)
	paddedLength := append([]byte{0x0a}, byte(l&0x7f|0x80), byte(l>>7&0x7f|0x80), byte(l>>14&0x7f|0x80), 0x00)
	paddedLength = field(append(paddedLength, body...), 2, sig)
	paddedTag := append(append([]byte{0x8a, 0x00}, protowire.AppendVarint(nil, uint64(l))...), body...)
	paddedTag = field(paddedTag, 2, sig)
	recoveryBefore := field(field(field(nil, 1, body), 3, []byte("record")), 2, sig)

	tests := []struct {
		name string
		env  []byte
		want error
	}{
		{"fields swapped", swapped, ErrMalformed},
		{"padded varint length", paddedLength, ErrMalformed},
		{"padded tag", paddedTag, ErrMalformed},
		{"short signature", field(field(nil, 1, body), 2, sig[:63]), ErrMalformed},
		{"long signature", field(field(nil, 1, body), 2, append(bytes.Clone(sig), 0)), ErrMalformed},
		{"no signature", field(nil, 1, body), ErrMalformed},
		{"recovery records before the signature", recoveryBefore, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Verify(tt.env, f.trust()); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
	// The first three decode to the same message as the original: only the
	// canonical check rejects them.
	for _, b := range [][]byte{swapped, paddedLength, paddedTag} {
		var check netmapv1.Envelope
		if err := proto.Unmarshal(b, &check); err != nil || !proto.Equal(&check, e) {
			t.Fatalf("test input doesn't decode to the original envelope: %v", err)
		}
	}
}

func TestVerifyChecksTrust(t *testing.T) {
	f := newFixture(t, 1, 1)
	env := f.build(t)
	body := decodeBody(t, env)
	other := newKeyPair(t)
	otherPub := other.Public().(ed25519.PublicKey)

	byRecovery, err := Build(f.recovery, Contents{
		SpaceID: f.contents.SpaceID, Version: 2, RecoveryKey: f.signingPublic(), Recipients: f.contents.Recipients, Blobs: f.contents.Blobs,
	})
	if err != nil {
		t.Fatal(err)
	}
	noContext := marshal(t, &netmapv1.Envelope{Body: marshal(t, body), Signature: ed25519.Sign(f.signing, marshal(t, body))})
	body.Header.SigningPublicKey = otherPub
	namesOther := signEnvelope(t, f.signing, marshal(t, body))

	trust := func(change func(*Trust)) Trust { tr := f.trust(); change(&tr); return tr }
	tests := []struct {
		name  string
		env   []byte
		trust Trust
		want  error
	}{
		{"trusted", env, f.trust(), nil},
		{"any space", env, trust(func(tr *Trust) { tr.SpaceID = SpaceID{} }), nil},
		{"any recovery key", env, trust(func(tr *Trust) { tr.RecoveryKey = nil }), nil},
		{"another space", env, trust(func(tr *Trust) { tr.SpaceID = NewSpaceID() }), ErrOtherSpace},
		{"another recovery key", env, trust(func(tr *Trust) { tr.RecoveryKey = otherPub }), ErrKeysChanged},
		{"another signing key", env, trust(func(tr *Trust) { tr.SigningKey = otherPub }), ErrBadSignature},
		{"the recovery key as signing key", env, trust(func(tr *Trust) { tr.SigningKey = f.contents.RecoveryKey }), ErrBadSignature},
		{"signed by the recovery key", byRecovery, f.trust(), ErrBadSignature},
		{"signature without context", noContext, f.trust(), ErrBadSignature},
		{"header names another key", namesOther, f.trust(), ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Verify(tt.env, tt.trust); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
	for _, key := range []ed25519.PublicKey{nil, make([]byte, 31)} {
		if _, err := Verify(env, Trust{SigningKey: key}); err == nil {
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
			out := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 2)
			return protowire.AppendVarint(protowire.AppendTag(out, 3, protowire.VarintType), 7)
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
		{"blob of size 0", func(b *netmapv1.Body) []byte { b.Header.Blobs[0].Size = 0; return marshal(t, b) }, ErrMalformed},
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
				s.Sealed = s.Sealed[:box.AnonymousOverhead+minSectionSize/2]
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
			if _, err := Verify(tampered, f.trust()); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerifyRejectsOversizedEnvelope(t *testing.T) {
	f := newFixture(t, 0, 1)
	if _, err := Verify(make([]byte, MaxEnvelopeSize+1), f.trust()); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}

// replaceSections re-signs env with every section that opens for key
// replaced by a dummy, then crafted sealed sections laid at the start.
func (f *fixture) replaceSections(t testing.TB, env []byte, key NodePrivateKey, crafted ...[]byte) *Map {
	t.Helper()
	b := decodeBody(t, env)
	size := len(b.Sections[0].GetSealed()) - box.AnonymousOverhead
	for _, s := range b.Sections {
		if opens(s.GetSealed(), key) {
			s.Sealed = seal(t, GenerateNodeKey().Public(), make([]byte, size))
		}
	}
	for i, c := range crafted {
		b.Sections[i].Sealed = c
	}
	return f.verify(t, signEnvelope(t, f.signing, marshal(t, b)))
}

func TestReadersIgnoreUnknownFields(t *testing.T) {
	f := newFixture(t, 1, 1)
	env := f.build(t)
	key := f.keys[1]
	sec := f.contents.Recipients[1].Section
	h := f.verify(t, env).Header()

	b := decodeBody(t, env)
	b.Header.ProtoReflect().SetUnknown(appendUnknownField(nil))
	plain := appendUnknownField(marshal(t, sectionToProto(&sec, &h)))
	b.Sections[0].Sealed = seal(t, key.Public(), pad(plain, minSectionSize))
	for _, s := range b.Sections[1:] {
		if opens(s.GetSealed(), key) {
			s.Sealed = seal(t, GenerateNodeKey().Public(), make([]byte, minSectionSize))
		}
	}
	m, err := Verify(signEnvelope(t, f.signing, appendUnknownField(marshal(t, b))), f.trust())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	got, err := m.Open(key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !reflect.DeepEqual(got, sec) {
		t.Errorf("Open() = %+v, want %+v", got, sec)
	}
}

func TestOpenOnlyOwnSection(t *testing.T) {
	f := newFixture(t, 3, 6)
	m := f.verify(t, f.build(t))

	// Each key opens exactly one sealed box, its own; nobody opens a dummy.
	opened := make([]int, len(m.sections))
	for i, key := range f.keys {
		count := 0
		for j, s := range m.sections {
			if opens(s, key) {
				count++
				opened[j]++
			}
		}
		if count != 1 {
			t.Errorf("node %d opens %d sections, want 1", i, count)
		}
		got, err := m.Open(key)
		if err != nil {
			t.Fatalf("node %d: %v", i, err)
		}
		if got.Node.ID != f.contents.Recipients[i].Section.Node.ID {
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

	if _, err := m.Open(GenerateNodeKey()); !errors.Is(err, ErrNotRecipient) {
		t.Errorf("stranger: err = %v, want ErrNotRecipient", err)
	}
	// Node 0's private key with node 1's public key opens nothing.
	pub1 := f.keys[1].Public()
	for _, s := range m.sections {
		if _, ok := box.OpenAnonymous(nil, s, (*[32]byte)(&pub1), (*[32]byte)(&f.keys[0])); ok {
			t.Error("node 0 opened a section with node 1's public key")
		}
	}
}

func TestOpenChecksOnlyWellFormedness(t *testing.T) {
	f := newFixture(t, 1, 1)
	env := f.build(t)
	key := f.keys[1]
	pub := key.Public()
	h := f.verify(t, env).Header()
	device := f.contents.Recipients[1].Section

	sealedWith := func(change func(pb *netmapv1.Section)) []byte {
		pb := sectionToProto(&device, &h)
		change(pb)
		return seal(t, pub, pad(marshal(t, pb), minSectionSize))
	}
	unpadded := marshal(t, sectionToProto(&device, &h))
	unpadded = append(unpadded, make([]byte, minSectionSize-len(unpadded))...)
	good := sealedWith(func(*netmapv1.Section) {})

	tests := []struct {
		name    string
		crafted [][]byte
		want    error
	}{
		{"control", [][]byte{good}, nil},
		{"builder policy is not the reader's", [][]byte{sealedWith(func(pb *netmapv1.Section) {
			pb.Node.Ipv4Network = "10.0.0.0/8"
			pb.Peers[0].Paths = nil
			pb.Links[0].Endpoints = nil
		})}, nil},
		{"another space", [][]byte{sealedWith(func(pb *netmapv1.Section) { pb.SpaceId = make([]byte, 16) })}, ErrMalformed},
		{"older version replayed", [][]byte{sealedWith(func(pb *netmapv1.Section) { pb.MapVersion-- })}, ErrMalformed},
		{"another key epoch", [][]byte{sealedWith(func(pb *netmapv1.Section) { pb.KeyEpoch++ })}, ErrMalformed},
		{"no reader version", [][]byte{sealedWith(func(pb *netmapv1.Section) { pb.MinReader = 0 })}, ErrMalformed},
		{"newer reader needed", [][]byte{sealedWith(func(pb *netmapv1.Section) { pb.MinReader = SectionReader + 1 })}, ErrUnsupportedFormat},
		{"unknown own node kind", [][]byte{sealedWith(func(pb *netmapv1.Section) { pb.Node.Kind = 7 })}, ErrUnsupportedFormat},
		{"own node kind out of range", [][]byte{sealedWith(func(pb *netmapv1.Section) { pb.Node.Kind = 300 })}, ErrUnsupportedFormat},
		{"unspecified own node kind", [][]byte{sealedWith(func(pb *netmapv1.Section) { pb.Node.Kind = 0 })}, ErrMalformed},
		{"peer is the node itself", [][]byte{sealedWith(func(pb *netmapv1.Section) { pb.Peers[0].Id = pb.Node.Id })}, ErrMalformed},
		{"route repeated", [][]byte{sealedWith(func(pb *netmapv1.Section) {
			pb.Routes = []*netmapv1.Route{{Destination: pb.Peers[0].Id}, {Destination: pb.Peers[0].Id}}
		})}, ErrMalformed},
		{"non-canonical address", [][]byte{sealedWith(func(pb *netmapv1.Section) { pb.Node.Ipv6 = "FD12:3456:789A::2" })}, ErrMalformed},
		{"no padding marker", [][]byte{seal(t, pub, unpadded)}, ErrMalformed},
		{"not protobuf", [][]byte{seal(t, pub, pad([]byte{0xff, 0xff}, minSectionSize))}, ErrMalformed},
		{"two sections for one key", [][]byte{good, good}, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := f.replaceSections(t, env, key, tt.crafted...)
			if _, err := m.Open(key); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestPaddingHidesSections checks S6 over many generated maps: the section
// count depends only on its power-of-two bucket, every section of an
// envelope has the same length, dummies have the same structure as real
// sealed boxes, and real sections land in uniformly random positions.
func TestPaddingHidesSections(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(1, 2))
	for range 60 {
		f := newFixture(t, rng.IntN(5), rng.IntN(14))
		m := f.verify(t, f.build(t))
		n := len(f.contents.Recipients)
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
	const maps = 300
	var hits [minSections]int
	f := newFixture(t, 1, 2)
	for range maps {
		m := f.verify(t, f.build(t))
		for _, key := range f.keys {
			for j, s := range m.sections {
				if opens(s, key) {
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
	// χ² with 7 degrees of freedom exceeds 50 with probability 1.4e-8 for a
	// uniform shuffle, so this fails spuriously about once in 70 million
	// runs; a missing or broken shuffle scores in the hundreds.
	if chi2 > 50 {
		t.Errorf("real sections are not uniformly placed: hits %v, χ² %.1f", hits, chi2)
	}
}

func TestSectionLengthHidesRole(t *testing.T) {
	sealedSize := func(m *Map) int { return len(m.sections[0]) - box.AnonymousOverhead }

	// The PRD's scale fits the smallest bucket, servers and devices alike.
	prd := newFixture(t, 10, 20)
	if got := sealedSize(prd.verify(t, prd.build(t))); got != minSectionSize {
		t.Errorf("a PRD-scale space uses %d-byte sections, want %d", got, minSectionSize)
	}

	// One device section outgrowing the bucket moves every section, the
	// server's small one included, to the next bucket.
	f := newFixture(t, 1, 2)
	server := f.contents.Recipients[0].Section
	h := Header{SpaceID: f.contents.SpaceID, Version: f.contents.Version}
	if n := len(marshal(t, sectionToProto(&server, &h))); n >= minSectionSize/4 {
		t.Fatalf("the server's section is %d bytes, not a small one", n)
	}
	if got := sealedSize(f.verify(t, f.build(t))); got != minSectionSize {
		t.Fatalf("before: %d-byte sections, want %d", got, minSectionSize)
	}
	device := &f.contents.Recipients[1].Section
	for i := range 10 {
		device.Links = append(device.Links, Link{Peer: NodeID{byte(i + 1), 0xee}, Endpoints: []Endpoint{
			{Transport: "udp", Address: netip.MustParseAddrPort("192.0.2.1:4500"), Credential: make([]byte, maxCredential)},
		}})
	}
	m := f.verify(t, f.build(t))
	if got := sealedSize(m); got != 2*minSectionSize {
		t.Fatalf("after: %d-byte sections, want %d", got, 2*minSectionSize)
	}
	for _, s := range m.sections {
		if opens(s, f.keys[0]) && len(s) != len(m.sections[0]) {
			t.Error("the server's section is not padded to the new bucket")
		}
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

func TestAcceptAndNext(t *testing.T) {
	f := newFixture(t, 1, 1)
	envAt := func(t *testing.T, change func(c *Contents), signing ed25519.PrivateKey) []byte {
		t.Helper()
		c := f.contents
		change(&c)
		env, err := Build(signing, c)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	version := func(v uint64) func(c *Contents) { return func(c *Contents) { c.Version = v } }
	verifyAs := func(t *testing.T, env []byte, signing ed25519.PrivateKey) *Map {
		t.Helper()
		m, err := Verify(env, Trust{SigningKey: signing.Public().(ed25519.PublicKey)})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	current := f.verify(t, envAt(t, version(5), f.signing))
	otherSigning := newKeyPair(t)

	tests := []struct {
		name    string
		env     []byte
		signing ed25519.PrivateKey
		want    error // from Accept
		wantErr error // from Next, when it differs
	}{
		{"next version", envAt(t, version(6), f.signing), f.signing, nil, nil},
		{"highest version", envAt(t, version(MaxVersion), f.signing), f.signing, nil, nil},
		{"same version", envAt(t, version(5), f.signing), f.signing, ErrNotNewer, nil},
		{"rollback", envAt(t, version(4), f.signing), f.signing, ErrNotNewer, nil},
		{"rollback to first", envAt(t, version(1), f.signing), f.signing, ErrNotNewer, nil},
		{"another space", envAt(t, func(c *Contents) { c.Version = 6; c.SpaceID = NewSpaceID() }, f.signing), f.signing, ErrOtherSpace, nil},
		{"another recovery key", envAt(t, func(c *Contents) {
			c.Version = 6
			c.RecoveryKey = newKeyPair(t).Public().(ed25519.PublicKey)
		}, f.signing), f.signing, ErrKeysChanged, nil},
		{"another signing key", envAt(t, version(6), otherSigning), otherSigning, ErrKeysChanged, ErrBadSignature},
		{"next key epoch", envAt(t, func(c *Contents) { c.KeyEpoch = 1; c.Version = 1 }, f.signing), f.signing, ErrKeysChanged, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Accept(current, verifyAs(t, tt.env, tt.signing)); !errors.Is(err, tt.want) {
				t.Errorf("Accept: err = %v, want %v", err, tt.want)
			}
			wantNext := tt.want
			if tt.wantErr != nil {
				wantNext = tt.wantErr
			}
			next, err := current.Next(tt.env)
			if !errors.Is(err, wantNext) {
				t.Errorf("Next: err = %v, want %v", err, wantNext)
			}
			if err == nil {
				if !bytes.Equal(next.Bytes(), tt.env) || next.Header().Version <= current.Header().Version {
					t.Error("Next returned another map")
				}
				if _, err := next.Open(f.keys[0]); err != nil {
					t.Errorf("Open on the next map: %v", err)
				}
			}
		})
	}
	if err := Accept(nil, current); err != nil {
		t.Errorf("first map: %v", err)
	}
	// A map at a later epoch can't go back either.
	later := verifyAs(t, envAt(t, func(c *Contents) { c.KeyEpoch = 1; c.Version = 9 }, f.signing), f.signing)
	if err := Accept(later, current); !errors.Is(err, ErrKeysChanged) {
		t.Errorf("back to an older epoch: err = %v, want ErrKeysChanged", err)
	}
}

func TestBuildChecksEnvelopeSizeBeforeSealing(t *testing.T) {
	// 17 recipients pad to 32 sections; one 600 KB section puts them all in
	// the 1 MiB bucket, 32 MiB in all.
	f := newFixture(t, 0, 17)
	s := &f.contents.Recipients[0].Section
	for i := range 560 {
		s.Links = append(s.Links, Link{Peer: NodeID{byte(i), byte(i >> 8), 1}, Endpoints: []Endpoint{
			{Transport: "udp", Address: netip.MustParseAddrPort("192.0.2.1:1"), Credential: make([]byte, maxCredential)},
		}})
	}
	if _, err := Build(f.signing, f.contents); !errors.Is(err, ErrInvalidContents) {
		t.Fatalf("err = %v, want ErrInvalidContents", err)
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
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Verify(data, fx.trust())
		if err != nil {
			return
		}
		if !bytes.Equal(data, env) {
			t.Fatal("an envelope other than the signed one verified")
		}
		for _, k := range fx.keys {
			if _, err := m.Open(k); err != nil {
				t.Fatal(err)
			}
		}
	})
}
