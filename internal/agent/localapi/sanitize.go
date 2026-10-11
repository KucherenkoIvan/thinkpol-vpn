package localapi

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
)

// sanitized disarms every string in m, in place (agent.Sanitize), and
// returns it: whatever the service sends is shown to a person, and a
// worker's or a map's bytes must not act on their terminal.
func sanitized[M proto.Message](m M) M {
	sanitizeMessage(m.ProtoReflect())
	return m
}

func sanitizeMessage(m protoreflect.Message) {
	type field struct {
		fd protoreflect.FieldDescriptor
		v  protoreflect.Value
	}
	var fields []field
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		fields = append(fields, field{fd, v})
		return true
	})
	for _, f := range fields {
		fd, v := f.fd, f.v
		switch {
		case fd.IsMap():
			sanitizeMap(fd, v.Map())
		case fd.IsList():
			l := v.List()
			for i := range l.Len() {
				switch fd.Kind() {
				case protoreflect.StringKind:
					l.Set(i, protoreflect.ValueOfString(agent.Sanitize(l.Get(i).String())))
				case protoreflect.MessageKind, protoreflect.GroupKind:
					sanitizeMessage(l.Get(i).Message())
				}
			}
		case fd.Kind() == protoreflect.StringKind:
			m.Set(fd, protoreflect.ValueOfString(agent.Sanitize(v.String())))
		case fd.Kind() == protoreflect.MessageKind, fd.Kind() == protoreflect.GroupKind:
			sanitizeMessage(v.Message())
		}
	}
}

func sanitizeMap(fd protoreflect.FieldDescriptor, mp protoreflect.Map) {
	type entry struct {
		k protoreflect.MapKey
		v protoreflect.Value
	}
	var entries []entry
	mp.Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
		entries = append(entries, entry{k, v})
		return true
	})
	for _, e := range entries {
		k, v := e.k, e.v
		switch fd.MapValue().Kind() {
		case protoreflect.StringKind:
			v = protoreflect.ValueOfString(agent.Sanitize(v.String()))
		case protoreflect.MessageKind, protoreflect.GroupKind:
			sanitizeMessage(v.Message())
		}
		if fd.MapKey().Kind() == protoreflect.StringKind {
			if s := agent.Sanitize(k.String()); s != k.String() {
				mp.Clear(k)
				k = protoreflect.ValueOfString(s).MapKey()
			}
		}
		mp.Set(k, v)
	}
}
