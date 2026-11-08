package localapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// SchemaVersion is the schema of the JSON the CLI writes (`status -json`,
// `diag`), its top-level `schema_version`. It is bumped when a field is
// removed or renamed or its type or meaning changes, not when one is
// added; `unreadable` texts are free-form, and enumerated string values
// (a health problem, a route's type, an Apply's step) may grow without a
// bump.
//
// 2: enum values are spelled lower snake_case without their type's
// prefix (`connected`, not `CONNECTION_CONNECTED`), as the text view
// spells them; diag's status was 1's only enum-bearing part.
const SchemaVersion = 2

// WriteJSON writes m in the JSON convention (the package doc's "JSON"),
// indented, for a person or a script reading a whole document.
func WriteJSON(w io.Writer, m proto.Message) error {
	b, err := conventionJSON(m)
	if err != nil {
		return err
	}
	if b, err = stableJSON(b); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// WriteJSONLine writes m in the JSON convention as one line, for a stream
// of documents (`status -watch -json`) that line readers split.
func WriteJSONLine(w io.Writer, m proto.Message) error {
	b, err := conventionJSON(m)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// conventionJSON is m in the JSON convention, compact: the schema's own
// names, every field present, enum values as enumValueName spells them,
// and the top-level `schema_version` this client's SchemaVersion. A nil
// message is written as an empty one.
func conventionJSON(m proto.Message) ([]byte, error) {
	if !m.ProtoReflect().IsValid() {
		m = m.ProtoReflect().Type().New().Interface()
	}
	b, err := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}.Marshal(m)
	if err != nil {
		return nil, err
	}
	// Decoded into an ordered tree, not a map[string]any: the fields keep
	// the schema's order, which is what a person reading it expects.
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := decodeOrdered(dec)
	if err != nil {
		return nil, err
	}
	rewriteMessage(v, m.ProtoReflect().Descriptor())
	if obj, ok := v.(*object); ok {
		// The JSON has the fields this client's schema knows, whatever
		// version the message came from.
		obj.set("schema_version", json.Number(strconv.Itoa(SchemaVersion)))
	}
	var out bytes.Buffer
	if err := encodeOrdered(&out, v); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// enumValueName is the name of value n of enum ed as the JSON and the
// text view spell it: lower case without the prefix the type gives its
// values (HealthLevel's HEALTH_LEVEL_OK is `ok`, the zero value
// `unspecified`). A number the schema doesn't know (a newer service's) is
// `unknown`.
func enumValueName(ed protoreflect.EnumDescriptor, n protoreflect.EnumNumber) string {
	v := ed.Values().ByNumber(n)
	if v == nil {
		return "unknown"
	}
	return strings.ToLower(strings.TrimPrefix(string(v.Name()), enumPrefix(ed)))
}

// enumPrefix is the prefix ed's values share: its zero value's name
// without UNSPECIFIED (buf lint has every zero value end so), which
// splitting the type's CamelCase name can't give for acronyms
// (IPv6State's values start IPV6_STATE_).
func enumPrefix(ed protoreflect.EnumDescriptor) string {
	zero := ed.Values().ByNumber(0)
	if zero == nil {
		return ""
	}
	prefix, ok := strings.CutSuffix(string(zero.Name()), "UNSPECIFIED")
	if !ok {
		return ""
	}
	return prefix
}

// object is a JSON object with its keys in order.
type object struct {
	keys []string
	vals map[string]any
}

// set sets key to v, in its place if it is there, else last.
func (o *object) set(key string, v any) {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = v
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
		ed := fd.Enum()
		if ed.FullName() == "google.protobuf.NullValue" {
			return v
		}
		switch v := v.(type) {
		case string:
			if ev := ed.Values().ByName(protoreflect.Name(v)); ev != nil {
				return enumValueName(ed, ev.Number())
			}
		case json.Number:
			// protojson writes a number the schema doesn't know as itself.
			return "unknown"
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
				return nil, fmt.Errorf("localapi: json object key %v", kt)
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
