package localapi

import (
	"bytes"
	"encoding/json"
	"io"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// SchemaVersion is the schema of the JSON the CLI writes (`status -json`,
// `diag`): Status.schema_version and Diagnostics.schema_version. It is
// bumped when a field is removed or renamed or its type or meaning
// changes, not when one is added; `unreadable` texts are free-form, and
// enumerated string values (a health problem, a route's type, an Apply's
// step) may grow without a bump.
const SchemaVersion = 1

// WriteStatusJSON writes st in the JSON convention, stamped with this
// client's SchemaVersion: the JSON has the fields this client's schema
// knows, whatever the service's.
func WriteStatusJSON(w io.Writer, st *localapiv1.Status) error {
	st = proto.CloneOf(st)
	st.SchemaVersion = SchemaVersion
	return writeJSON(w, st)
}

// writeJSON writes m in the local API's JSON convention (the package
// doc's "JSON"): the schema's own names, every field present, one object
// and a newline (stableJSON).
func writeJSON(w io.Writer, m proto.Message) error {
	b, err := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}.Marshal(m)
	if err != nil {
		return err
	}
	if b, err = stableJSON(b); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
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
