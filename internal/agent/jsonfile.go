package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// decodeSettings reads a settings file (NodeFile, DeviceFile) into v, a
// pointer to a struct of json-tagged fields. Stricter than encoding/json,
// so a typo never reads as a default: the file must hold one JSON object,
// and an unknown key (keys match exactly, where encoding/json ignores
// case), a key given twice (at any depth) or a value of the wrong type is
// an error naming the key. An empty file is an error too: `{}` is a file
// with no settings.
func decodeSettings(data []byte, v any) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("empty: write {} for a file without settings")
	}
	if err := checkJSONKeys(data, reflect.TypeOf(v).Elem()); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return settingsError(err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("invalid JSON: more after the object")
	}
	return nil
}

// checkJSONKeys checks that data is one JSON object whose keys are typ's
// json tags exactly, in nested objects too, none given twice:
// encoding/json keeps the last of two silently, and takes a key of
// another case.
func checkJSONKeys(data []byte, typ reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	// One per open object or array. An object's keys seen so far, and
	// whether a key comes next; typ is what it decodes into (a struct's
	// keys are checked; nil: anything), elem what its values decode into.
	type level struct {
		object    bool
		keys      map[string]bool
		expectKey bool
		typ       reflect.Type
		elem      reflect.Type
	}
	var stack []*level
	open := func(object bool, t reflect.Type) {
		stack = append(stack, &level{object: object, keys: map[string]bool{}, expectKey: object, typ: deref(t)})
	}
	for first := true; ; first = false {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return settingsError(err)
		}
		if first && tok != json.Delim('{') {
			return errors.New("want a JSON object ({...})")
		}
		var top *level
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.expectKey {
			if key, ok := tok.(string); ok {
				if top.keys[key] {
					return fmt.Errorf("key %q given twice", key)
				}
				top.keys[key] = true
				top.expectKey = false
				top.elem = nil
				if top.typ != nil && top.typ.Kind() == reflect.Struct {
					f, ok := fieldByJSONKey(top.typ, key)
					if !ok {
						return fmt.Errorf("unknown key %q", key)
					}
					top.elem = f
				}
				continue
			}
		}
		// A value: the file's object, the open object's last key's, or an
		// element of the open array.
		t := typ
		if top != nil {
			t = top.elem
			if top.object {
				top.expectKey = true
			}
		}
		switch tok {
		case json.Delim('{'):
			open(true, t)
		case json.Delim('['):
			open(false, t)
			if t := deref(t); t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
				stack[len(stack)-1].elem = t.Elem()
			}
		case json.Delim('}'), json.Delim(']'):
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				// The top object closed; decodeSettings refuses anything
				// after it.
				return nil
			}
		}
	}
}

// fieldByJSONKey is the type of the field of struct t tagged json:"key".
func fieldByJSONKey(t reflect.Type, key string) (reflect.Type, bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name == key {
			return f.Type, true
		}
	}
	return nil, false
}

func deref(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// settingsError says what encoding/json found, in the file's terms: the
// key, the value's type, where the JSON broke.
func settingsError(err error) error {
	var syntax *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax):
		return fmt.Errorf("invalid JSON at byte %d: %s", syntax.Offset, strings.TrimPrefix(syntax.Error(), "json: "))
	case errors.Is(err, io.ErrUnexpectedEOF):
		return errors.New("invalid JSON: it ends too early")
	case errors.As(err, &typ):
		if typ.Field == "" {
			return fmt.Errorf("want a JSON object, not %s", typ.Value)
		}
		return fmt.Errorf("key %q: want %s, not %s", typ.Field, jsonKind(typ.Type.Kind().String()), typ.Value)
	}
	msg := err.Error()
	if key, ok := strings.CutPrefix(msg, "json: unknown field "); ok {
		return fmt.Errorf("unknown key %s", key)
	}
	return errors.New(strings.TrimPrefix(msg, "json: "))
}

// jsonKind names a Go kind as JSON calls it.
func jsonKind(kind string) string {
	switch {
	case kind == "bool":
		return "true or false"
	case kind == "string":
		return "a string"
	case kind == "slice", kind == "array":
		return "a list"
	case kind == "struct", kind == "map":
		return "an object"
	case strings.HasPrefix(kind, "int"), strings.HasPrefix(kind, "uint"):
		return "a whole number"
	case strings.HasPrefix(kind, "float"):
		return "a number"
	}
	return kind
}
