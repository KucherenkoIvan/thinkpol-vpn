package localapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// SchemaVersion is the schema of the JSON the CLI writes (`status -json`,
// `diag`): Status.schema_version and Diagnostics.schema_version. It is
// bumped when a field is removed or renamed or its type or meaning
// changes, not when one is added; `unreadable` texts are free-form, and
// enumerated string values (a health problem, a route's type, an Apply's
// step) may grow without a bump.
//
// 2: enum values are spelled lower snake_case without their type's
// prefix (`connected`, not `CONNECTION_CONNECTED`), as the text view
// spells them; diag's status was 1's only enum-bearing part.
const SchemaVersion = 2

// WriteStatusJSON writes st in the JSON convention, stamped with this
// client's SchemaVersion: the JSON has the fields this client's schema
// knows, whatever the service's.
func WriteStatusJSON(w io.Writer, st *localapiv1.Status) error {
	st = proto.CloneOf(st)
	st.SchemaVersion = SchemaVersion
	return writeJSON(w, st)
}

// writeJSON writes m in the local API's JSON convention (the package
// doc's "JSON"): the schema's own names, every field present, enum values
// in lower snake_case (enumValues), one object and a newline.
func writeJSON(w io.Writer, m proto.Message) error {
	b, err := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}.Marshal(m)
	if err != nil {
		return err
	}
	if b, err = enumValues(b, m.ProtoReflect().Descriptor()); err != nil {
		return err
	}
	if b, err = stableJSON(b); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// enumValues rewrites every enum value in b, protojson's encoding of a
// message described by md, from its full name to enumValueName's
// spelling, keeping the fields' order. The schema says which strings are
// enums: a string field may hold anything, an enum's name included.
func enumValues(b []byte, md protoreflect.MessageDescriptor) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := decodeOrdered(dec)
	if err != nil {
		return nil, err
	}
	rewriteMessage(v, md)
	var out bytes.Buffer
	if err := encodeOrdered(&out, v); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// enumValueName is an enum value's JSON spelling: its name in lower case
// without the prefix its type's name gives it (HealthLevel's
// HEALTH_LEVEL_OK is `ok`, the zero value `unspecified`).
func enumValueName(ed protoreflect.EnumDescriptor, name string) string {
	return strings.ToLower(strings.TrimPrefix(name, enumPrefix(string(ed.Name()))))
}

// enumPrefix is the SCREAMING_SNAKE prefix of an enum named name:
// "HealthLevel" gives "HEALTH_LEVEL_".
func enumPrefix(name string) string {
	var p strings.Builder
	for i, r := range name {
		if i > 0 && r >= 'A' && r <= 'Z' {
			p.WriteByte('_')
		}
		p.WriteString(strings.ToUpper(string(r)))
	}
	p.WriteByte('_')
	return p.String()
}

// object is a JSON object with its keys in order.
type object struct {
	keys []string
	vals map[string]any
}

func rewriteMessage(v any, md protoreflect.MessageDescriptor) {
	obj, ok := v.(*object)
	// The well-known types (Timestamp, Duration, Struct's NullValue) have
	// JSON forms of their own.
	if !ok || md.ParentFile().Package() == "google.protobuf" {
		return
	}
	fields := md.Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		key := fd.TextName()
		val, ok := obj.vals[key]
		if !ok {
			continue
		}
		switch {
		case fd.IsMap():
			if m, ok := val.(*object); ok {
				for _, k := range m.keys {
					m.vals[k] = rewriteValue(m.vals[k], fd.MapValue())
				}
			}
		case fd.IsList():
			if l, ok := val.([]any); ok {
				for j := range l {
					l[j] = rewriteValue(l[j], fd)
				}
			}
		default:
			obj.vals[key] = rewriteValue(val, fd)
		}
	}
}

// rewriteValue rewrites one value of fd's type (a list's element, a map's
// value).
func rewriteValue(v any, fd protoreflect.FieldDescriptor) any {
	switch fd.Kind() {
	case protoreflect.EnumKind:
		if s, ok := v.(string); ok && fd.Enum().FullName() != "google.protobuf.NullValue" {
			return enumValueName(fd.Enum(), s)
		}
	case protoreflect.MessageKind, protoreflect.GroupKind:
		rewriteMessage(v, fd.Message())
	}
	return v
}

func decodeOrdered(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch tok {
	case json.Delim('{'):
		obj := &object{vals: map[string]any{}}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			k, ok := kt.(string)
			if !ok {
				return nil, fmt.Errorf("json: object key %v", kt)
			}
			v, err := decodeOrdered(dec)
			if err != nil {
				return nil, err
			}
			obj.keys = append(obj.keys, k)
			obj.vals[k] = v
		}
		_, err := dec.Token()
		return obj, err
	case json.Delim('['):
		l := []any{}
		for dec.More() {
			v, err := decodeOrdered(dec)
			if err != nil {
				return nil, err
			}
			l = append(l, v)
		}
		_, err := dec.Token()
		return l, err
	}
	return tok, nil
}

func encodeOrdered(out *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case *object:
		out.WriteByte('{')
		for i, k := range v.keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := encodeOrdered(out, k); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := encodeOrdered(out, v.vals[k]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := encodeOrdered(out, e); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case json.Number:
		out.WriteString(string(v))
	default:
		// strings, bools and null; protojson doesn't escape HTML, so
		// neither does this.
		enc := json.NewEncoder(out)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return err
		}
		out.Truncate(out.Len() - 1) // Encode's newline
	}
	return nil
}

// stableJSON is b indented by two spaces, with a newline. protojson
// randomizes its whitespace on purpose, differently from build to build,
// so its output is re-indented to make it byte-stable.
func stableJSON(b []byte) ([]byte, error) {
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
