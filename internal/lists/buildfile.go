package lists

import (
	"os"
	"path/filepath"
)

// BuildFile builds the lists of source, a file in format f (empty: from
// its name, FormatFromPath), only those named in only (every list in it
// when empty), and writes each into dir as <name>.geoip. It returns the
// lists built in name order, and the source's format, whose Attribution
// goes with them. It never downloads: the source is a file the operator
// fetched, under its own license.
func BuildFile(source string, f Format, only []string, dir string) (Format, []List, error) {
	if f == "" {
		var err error
		if f, err = FormatFromPath(source); err != nil {
			return "", nil, err
		}
	}
	file, err := os.Open(source)
	if err != nil {
		return "", nil, err
	}
	imported, err := Import(file, f, only)
	_ = file.Close()
	if err != nil {
		return "", nil, err
	}
	built := BuildAll(imported)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, err
	}
	for _, l := range built {
		if err := os.WriteFile(filepath.Join(dir, l.Name+".geoip"), l.Blob, 0o644); err != nil {
			return "", nil, err
		}
	}
	return f, built, nil
}
