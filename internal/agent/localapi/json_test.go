package localapi

import (
	"bytes"
	"encoding/json"
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
	if err := WriteStatusJSON(&out, st); err != nil {
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
	if err := WriteStatusJSON(&out, &localapiv1.Status{}); err != nil {
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
	if err := writeJSON(&out, m); err != nil {
		t.Fatal(err)
	}
	compact := new(bytes.Buffer)
	if err := json.Compact(compact, out.Bytes()); err != nil {
		t.Fatal(err)
	}
	want := `{"note":"COLOR_DARK_RED","colors":["dark_red","unspecified"],"by_name":{"k":"dark_red"},"kids":[{"note":"","colors":["dark_red"],"by_name":{},"kids":[]}]}`
	if compact.String() != want {
		t.Errorf("got  %s\nwant %s", compact, want)
	}
}

// testEnumMessage is `message M { string note = 1; repeated Color colors
// = 2; map<string, Color> by_name = 3; repeated M kids = 4; }`, the
// schema's enum and list shapes Status doesn't have.
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
		}},
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("M"),
			Field: []*descriptorpb.FieldDescriptorProto{
				field("note", 1, opt, str, ""),
				field("colors", 2, rep, enum, ".enumtest.Color"),
				field("by_name", 3, rep, msg, ".enumtest.M.ByNameEntry"),
				field("kids", 4, rep, msg, ".enumtest.M"),
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

func TestEnumValueName(t *testing.T) {
	ed := localapiv1.HealthLevel_HEALTH_LEVEL_OK.Descriptor()
	for in, want := range map[string]string{"HEALTH_LEVEL_OK": "ok", "HEALTH_LEVEL_UNSPECIFIED": "unspecified", "OTHER_NAME": "other_name"} {
		if got := enumValueName(ed, in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
	if got := enumPrefix("HealthLevel"); got != "HEALTH_LEVEL_" {
		t.Errorf("prefix %q", got)
	}
}
