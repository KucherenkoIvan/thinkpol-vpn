package localapi

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// protojson's whitespace differs from build to build; what is written
// doesn't.
func TestJSONIsByteStable(t *testing.T) {
	want := "{\n  \"a\": 1,\n  \"b\": [],\n  \"c\": {\n    \"d\": \"x  y\"\n  }\n}\n"
	for _, in := range []string{`{"a":1,"b":[],"c":{"d":"x  y"}}`, `{"a":  1, "b":  [],  "c":  {"d":  "x  y"}}`, "{\n  \"a\":  1,\n  \"b\":  [],\n  \"c\":  {\n    \"d\":  \"x  y\"\n  }\n}"} {
		got, err := stableJSON([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%s: got %q, %v; want %q", in, got, err, want)
		}
	}
}

// The text view says `connected`; so does the JSON, in status -json and
// in diag's status alike.
func TestJSONSpellsEnumsAsTheTextDoes(t *testing.T) {
	st := &localapiv1.Status{
		Mode:       localapiv1.Mode_MODE_DEVICE,
		Connection: localapiv1.Connection_CONNECTION_CONNECTED,
		Health:     &localapiv1.Health{Level: localapiv1.HealthLevel_HEALTH_LEVEL_DEGRADED, Problems: []string{"no_link_up"}},
		SpaceId:    "CONNECTION_CONNECTED", // a string, not an enum: left as it is
	}
	type status struct {
		Mode       string `json:"mode"`
		Connection string `json:"connection"`
		SpaceID    string `json:"space_id"`
		Health     struct {
			Level string `json:"level"`
		} `json:"health"`
	}
	want := status{Mode: "device", Connection: "connected", SpaceID: "CONNECTION_CONNECTED"}
	want.Health.Level = "degraded"

	var out bytes.Buffer
	if err := WriteJSON(&out, st); err != nil {
		t.Fatal(err)
	}
	var got status
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got != want {
		t.Errorf("status -json: %+v (%v), want %+v:\n%s", got, err, want, out.String())
	}

	out.Reset()
	if err := WriteDiagnostics(&out, &localapiv1.Diagnostics{Status: st}); err != nil {
		t.Fatal(err)
	}
	var d struct {
		Status status `json:"status"`
	}
	if err := json.Unmarshal(out.Bytes(), &d); err != nil || d.Status != want {
		t.Errorf("diag: %+v (%v), want %+v:\n%s", d.Status, err, want, out.String())
	}

	out.Reset()
	if err := WriteJSON(&out, &localapiv1.Status{}); err != nil {
		t.Fatal(err)
	}
	got = status{}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got.Mode != "unspecified" || got.Connection != "unspecified" {
		t.Errorf("unset: %+v (%v):\n%s", got, err, out.String())
	}
}

// The rule is the schema's, not Status's: an enum in a list, as a map's
// value and in a message nested in a list is spelled the same way, and
// the fields keep their order.
func TestJSONSpellsEveryEnumFieldInTheSchema(t *testing.T) {
	md := testEnumMessage(t)
	color := md.Fields().ByName("colors").Enum().Values().ByName("COLOR_DARK_RED").Number()
	m := dynamicpb.NewMessage(md)
	m.Set(md.Fields().ByName("note"), protoreflect.ValueOfString("COLOR_DARK_RED"))
	colors := m.Mutable(md.Fields().ByName("colors")).List()
	colors.Append(protoreflect.ValueOfEnum(color))
	colors.Append(protoreflect.ValueOfEnum(0))
	m.Mutable(md.Fields().ByName("by_name")).Map().Set(protoreflect.ValueOfString("k").MapKey(), protoreflect.ValueOfEnum(color))
	kid := m.Mutable(md.Fields().ByName("kids")).List().NewElement()
	kid.Message().Mutable(md.Fields().ByName("colors")).List().Append(protoreflect.ValueOfEnum(color))
	m.Mutable(md.Fields().ByName("kids")).List().Append(kid)

	var out bytes.Buffer
	if err := WriteJSON(&out, m); err != nil {
		t.Fatal(err)
	}
	compact := new(bytes.Buffer)
	if err := json.Compact(compact, out.Bytes()); err != nil {
		t.Fatal(err)
	}
	want := `{"note":"COLOR_DARK_RED","colors":["dark_red","unspecified"],"by_name":{"k":"dark_red"},"kids":[{"note":"","colors":["dark_red"],"by_name":{},"kids":[],"state":"unspecified"}],"state":"unspecified","schema_version":` + strconv.Itoa(SchemaVersion) + `}`
	if compact.String() != want {
		t.Errorf("got  %s\nwant %s", compact, want)
	}
}

// testEnumMessage is `message M { string note = 1; repeated Color colors
// = 2; map<string, Color> by_name = 3; repeated M kids = 4; IPv6State
// state = 5; }`, the schema's enum and list shapes Status doesn't have.
func testEnumMessage(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	rep := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	field := func(name string, n int32, label descriptorpb.FieldDescriptorProto_Label, typ descriptorpb.FieldDescriptorProto_Type, typeName string) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(n), Label: label.Enum(), Type: typ.Enum(), JsonName: proto.String(name)}
		if typeName != "" {
			f.TypeName = proto.String(typeName)
		}
		return f
	}
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	enum := descriptorpb.FieldDescriptorProto_TYPE_ENUM
	msg := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("enumtest.proto"),
		Package: proto.String("enumtest"),
		Syntax:  proto.String("proto3"),
		EnumType: []*descriptorpb.EnumDescriptorProto{{
			Name: proto.String("Color"),
			Value: []*descriptorpb.EnumValueDescriptorProto{
				{Name: proto.String("COLOR_UNSPECIFIED"), Number: proto.Int32(0)},
				{Name: proto.String("COLOR_DARK_RED"), Number: proto.Int32(1)},
			},
		}, {
			Name: proto.String("IPv6State"),
			Value: []*descriptorpb.EnumValueDescriptorProto{
				{Name: proto.String("IPV6_STATE_UNSPECIFIED"), Number: proto.Int32(0)},
				{Name: proto.String("IPV6_STATE_ON"), Number: proto.Int32(1)},
			},
		}},
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("M"),
			Field: []*descriptorpb.FieldDescriptorProto{
				field("note", 1, opt, str, ""),
				field("colors", 2, rep, enum, ".enumtest.Color"),
				field("by_name", 3, rep, msg, ".enumtest.M.ByNameEntry"),
				field("kids", 4, rep, msg, ".enumtest.M"),
				field("state", 5, opt, enum, ".enumtest.IPv6State"),
			},
			NestedType: []*descriptorpb.DescriptorProto{{
				Name:    proto.String("ByNameEntry"),
				Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
				Field: []*descriptorpb.FieldDescriptorProto{
					field("key", 1, opt, str, ""),
					field("value", 2, opt, enum, ".enumtest.Color"),
				},
			}},
		}},
	}
	fd, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		t.Fatal(err)
	}
	return fd.Messages().ByName("M")
}

// Every value of the status's enums prints as the text view always did
// (the lab reads it); the JSON spells them the same way.
func TestTheTextViewNamesTheStatusEnumsAsBefore(t *testing.T) {
	want := map[protoreflect.FullName]string{
		"thinkpol.localapi.v1.CONNECTION_UNSPECIFIED":   "unspecified",
		"thinkpol.localapi.v1.CONNECTION_DISCONNECTED":  "disconnected",
		"thinkpol.localapi.v1.CONNECTION_CONNECTING":    "connecting",
		"thinkpol.localapi.v1.CONNECTION_CONNECTED":     "connected",
		"thinkpol.localapi.v1.CONNECTION_SERVING":       "serving",
		"thinkpol.localapi.v1.HEALTH_LEVEL_UNSPECIFIED": "unspecified",
		"thinkpol.localapi.v1.HEALTH_LEVEL_OK":          "ok",
		"thinkpol.localapi.v1.HEALTH_LEVEL_DEGRADED":    "degraded",
		"thinkpol.localapi.v1.HEALTH_LEVEL_DOWN":        "down",
		"thinkpol.localapi.v1.MODE_UNSPECIFIED":         "unspecified",
		"thinkpol.localapi.v1.MODE_DEVICE":              "device",
		"thinkpol.localapi.v1.MODE_SERVER":              "server",
	}
	enums := []protoreflect.Enum{localapiv1.Connection(0), localapiv1.HealthLevel(0), localapiv1.Mode(0)}
	seen := 0
	for _, e := range enums {
		values := e.Descriptor().Values()
		for i := range values.Len() {
			v := values.Get(i)
			w, ok := want[v.FullName()]
			if !ok {
				t.Errorf("%s: no expected name; add it", v.FullName())
				continue
			}
			seen++
			if got := displayName(e.Type().New(v.Number())); got != w {
				t.Errorf("%s: %q, want %q", v.FullName(), got, w)
			}
		}
		if got := displayName(e.Type().New(99)); got != "unknown" {
			t.Errorf("%s 99: %q, want unknown", e.Descriptor().FullName(), got)
		}
	}
	if seen != len(want) {
		t.Errorf("checked %d values, want %d", seen, len(want))
	}
}

// A newer service's enum value the client's schema doesn't have is
// "unknown" in the JSON, as in the text view, never a bare number: the
// field's type doesn't change with the service's version.
func TestJSONSpellsAnEnumValueItDoesntKnowUnknown(t *testing.T) {
	md := testEnumMessage(t)
	m := dynamicpb.NewMessage(md)
	m.Mutable(md.Fields().ByName("colors")).List().Append(protoreflect.ValueOfEnum(5))
	m.Set(md.Fields().ByName("state"), protoreflect.ValueOfEnum(7))
	var out bytes.Buffer
	if err := WriteJSON(&out, m); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Colors []string `json:"colors"`
		State  string   `json:"state"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || len(got.Colors) != 1 || got.Colors[0] != "unknown" || got.State != "unknown" {
		t.Errorf("%+v (%v):\n%s", got, err, out.String())
	}
}

// An enum's prefix is its zero value's, which CamelCase can't give for an
// acronym: IPv6State's IPV6_STATE_ON is `on`.
func TestAnAcronymNamedEnumLosesItsWholePrefix(t *testing.T) {
	md := testEnumMessage(t)
	m := dynamicpb.NewMessage(md)
	m.Set(md.Fields().ByName("state"), protoreflect.ValueOfEnum(md.Fields().ByName("state").Enum().Values().ByName("IPV6_STATE_ON").Number()))
	var out bytes.Buffer
	if err := WriteJSON(&out, m); err != nil {
		t.Fatal(err)
	}
	var got struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got.State != "on" {
		t.Errorf("state %q (%v), want on:\n%s", got.State, err, out.String())
	}
}

// Every document says the client's schema_version, whatever the message
// carried: the JSON holds the fields this client's schema knows. A
// document whose message has no such field gets it too.
func TestEveryJSONDocumentSaysTheClientsSchema(t *testing.T) {
	for name, m := range map[string]proto.Message{
		"status":            &localapiv1.Status{},
		"diag":              &localapiv1.Diagnostics{SchemaVersion: 99, Status: &localapiv1.Status{}},
		"diag, old service": &localapiv1.Diagnostics{SchemaVersion: 1},
		"another message":   &localapiv1.Health{},
	} {
		for _, write := range []func(io.Writer, proto.Message) error{WriteJSON, WriteJSONLine} {
			var out bytes.Buffer
			if err := write(&out, m); err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(out.Bytes(), &got); err != nil || got["schema_version"] != float64(SchemaVersion) {
				t.Errorf("%s: schema_version %v (%v), want %d:\n%s", name, got["schema_version"], err, SchemaVersion, out.String())
			}
		}
	}
}

// A response without its status (a nil message) is still a whole
// document: every field, the schema version.
func TestANilStatusIsAnEmptyDocument(t *testing.T) {
	var out bytes.Buffer
	if err := WriteJSON(&out, (*localapiv1.Status)(nil)); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got["schema_version"] != float64(SchemaVersion) || got["connection"] != "unspecified" {
		t.Errorf("%v:\n%s", err, out.String())
	}
}

// One line per document, for line readers.
func TestWriteJSONLineIsOneLine(t *testing.T) {
	var out bytes.Buffer
	st := &localapiv1.Status{Health: &localapiv1.Health{Problems: []string{"no_link_up"}}}
	if err := WriteJSONLine(&out, st); err != nil {
		t.Fatal(err)
	}
	if line := out.String(); strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "}\n") || !json.Valid(out.Bytes()) {
		t.Errorf("not one line:\n%s", line)
	}
}
