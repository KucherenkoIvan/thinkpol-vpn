package localapi

import "testing"

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
