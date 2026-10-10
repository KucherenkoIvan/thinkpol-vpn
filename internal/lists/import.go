package lists

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// Format is a source format an importer reads.
type Format string

const (
	// FormatV2flyGeoIP is v2fly's geoip.dat: a GeoIPList protobuf, as
	// published by v2fly/geoip and compatible projects.
	FormatV2flyGeoIP Format = "v2fly"
	// FormatDBIPCSV is DB-IP's "IP to Country Lite" CSV: start,end,country.
	FormatDBIPCSV Format = "dbip"
)

// Attribution is what a source's license asks to show with lists built
// from it, wherever they're shown or passed on.
func (f Format) Attribution() string {
	switch f {
	case FormatDBIPCSV:
		return "IP Geolocation by DB-IP (CC BY 4.0): https://db-ip.com"
	case FormatV2flyGeoIP:
		return "v2fly geoip.dat (CC BY-SA 4.0): https://github.com/v2fly/geoip; its upstream data may carry its own terms (DB-IP Lite: CC BY 4.0; MaxMind GeoLite2: MaxMind's GeoLite2 EULA)"
	}
	return ""
}

// FormatFromPath guesses a source's format from its file name: *.dat is
// v2fly, *.csv is DB-IP, either optionally gzipped (*.gz).
func FormatFromPath(path string) (Format, error) {
	switch filepath.Ext(strings.TrimSuffix(strings.ToLower(path), ".gz")) {
	case ".dat":
		return FormatV2flyGeoIP, nil
	case ".csv":
		return FormatDBIPCSV, nil
	}
	return "", fmt.Errorf("lists: can't tell the format of %q from its name", path)
}

// maxSourceSize caps how much an importer reads, after decompression, and
// maxEntries how many entries (CSV rows, CIDRs of the v2fly lists kept). The
// largest real sources are a few tens of MB and 1.4 million entries (all of
// v2fly's geoip.dat).
var (
	maxSourceSize int64 = 256 << 20
	maxEntries          = 1 << 22
)

var errTooManyEntries = errors.New("lists: too many entries in the source")

// ErrUnknownName is a requested list the source doesn't have.
var ErrUnknownName = errors.New("lists: no such list in the source")

// Import reads a source in format f, gzipped or not, into one Builder per
// list name (a country code, lowercase; v2fly sources also have names such as
// "private"). Entries with the same name merge. IPv6 entries stay IPv6, also
// in IPv4-mapped notation; one overlapping ::ffff:0:0/96 is left out and
// counted in [Stats.Skipped] ([ErrMappedIPv6]): DB-IP's reserved ZZ range
// ::–1fff:… is one. With only non-empty, it keeps
// just those names and fails with [ErrUnknownName] if one is missing; other
// entries are skipped unchecked. Without it, a name [CheckName] rejects fails
// the import.
func Import(r io.Reader, f Format, only []string) (map[string]*Builder, error) {
	keep := func(string) bool { return true }
	if len(only) > 0 {
		for _, name := range only {
			if err := CheckName(name); err != nil {
				return nil, err
			}
		}
		keep = func(name string) bool { return slices.Contains(only, name) }
	}

	br := bufio.NewReader(r)
	var src io.Reader = br
	if magic, _ := br.Peek(2); bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("lists: %w", err)
		}
		defer func() { _ = zr.Close() }()
		src = zr
	}
	src = &capReader{r: src, n: maxSourceSize}

	var out map[string]*Builder
	var err error
	switch f {
	case FormatV2flyGeoIP:
		out, err = importV2fly(src, keep)
	case FormatDBIPCSV:
		out, err = importDBIP(src, keep)
	default:
		return nil, fmt.Errorf("lists: unknown format %q", f)
	}
	if err != nil {
		return nil, err
	}
	for _, name := range only {
		if out[name] == nil {
			return nil, fmt.Errorf("%w: %q (it has %d others)", ErrUnknownName, name, len(out))
		}
	}
	return out, nil
}

// CheckName rejects names a rule can't refer to: 1 to 32 characters of
// a-z, 0-9 and '-', starting with a letter or digit.
func CheckName(name string) error {
	if name == "" || len(name) > 32 || name[0] == '-' {
		return fmt.Errorf("lists: bad list name %q", name)
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return fmt.Errorf("lists: bad list name %q", name)
		}
	}
	return nil
}

// List is one built list: what `thinkpol dev lists build` writes and the map
// references as a blob.
type List struct {
	Name   string
	Set    *Set
	Blob   []byte
	SHA256 [32]byte
	Stats  Stats
}

// BuildAll aggregates every imported list, in name order.
func BuildAll(lists map[string]*Builder) []List {
	out := make([]List, 0, len(lists))
	for _, name := range slices.Sorted(maps.Keys(lists)) {
		set, st := lists[name].Build()
		blob := set.Blob()
		out = append(out, List{Name: name, Set: set, Blob: blob, SHA256: sha256.Sum256(blob), Stats: st})
	}
	return out
}

func builderFor(out map[string]*Builder, name string) *Builder {
	b := out[name]
	if b == nil {
		b = &Builder{}
		out[name] = b
	}
	return b
}

// importV2fly parses the protobuf by hand (protowire) rather than through
// generated code: three tiny third-party messages, not part of our schema.
//
//	message GeoIPList { repeated GeoIP entry = 1; }
//	message GeoIP { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3; }
//	message CIDR { bytes ip = 1; uint32 prefix = 2; }
func importV2fly(r io.Reader, keep func(string) bool) (map[string]*Builder, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("lists: %w", err)
	}
	out := map[string]*Builder{}
	entries := 0
	err = eachField(data, func(num protowire.Number, typ protowire.Type, v []byte) error {
		if num != 1 || typ != protowire.BytesType {
			return nil
		}
		return v2flyEntry(v, keep, out, &entries)
	})
	if err != nil {
		return nil, fmt.Errorf("lists: v2fly: %w", err)
	}
	return out, nil
}

func v2flyEntry(entry []byte, keep func(string) bool, out map[string]*Builder, entries *int) error {
	var code string
	var cidrs [][]byte
	reverse := false
	err := eachField(entry, func(num protowire.Number, typ protowire.Type, v []byte) error {
		switch {
		case num == 1 && typ == protowire.BytesType:
			code = string(v)
		case num == 2 && typ == protowire.BytesType:
			cidrs = append(cidrs, v)
		case num == 3 && typ == protowire.VarintType:
			n, _ := protowire.ConsumeVarint(v)
			reverse = n != 0
		}
		return nil
	})
	if err != nil {
		return err
	}
	name := strings.ToLower(code)
	if !keep(name) {
		return nil
	}
	if err := CheckName(name); err != nil {
		return err
	}
	if reverse {
		return fmt.Errorf("entry %q: reverse_match is not supported", name)
	}
	b := builderFor(out, name)
	for _, c := range cidrs {
		if *entries++; *entries > maxEntries {
			return errTooManyEntries
		}
		var ip []byte
		var bits uint64 // proto3: absent is 0
		err := eachField(c, func(num protowire.Number, typ protowire.Type, v []byte) error {
			switch {
			case num == 1 && typ == protowire.BytesType:
				ip = v
			case num == 2 && typ == protowire.VarintType:
				bits, _ = protowire.ConsumeVarint(v)
			}
			return nil
		})
		if err != nil {
			return err
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok || bits > uint64(addr.BitLen()) {
			return fmt.Errorf("entry %q: bad CIDR %x/%d", name, ip, bits)
		}
		if err := skipMapped(b, b.AddPrefix(netip.PrefixFrom(addr, int(bits)))); err != nil {
			return fmt.Errorf("entry %q: %w", name, err)
		}
	}
	return nil
}

// eachField calls fn with every field of a protobuf message: for varints, v
// is the varint's encoding; for bytes, the contents.
func eachField(msg []byte, fn func(num protowire.Number, typ protowire.Type, v []byte) error) error {
	for len(msg) > 0 {
		num, typ, n := protowire.ConsumeTag(msg)
		if n < 0 {
			return protowire.ParseError(n)
		}
		msg = msg[n:]
		var v []byte
		if typ == protowire.BytesType {
			var m int
			v, m = protowire.ConsumeBytes(msg)
			n = m
		} else {
			n = protowire.ConsumeFieldValue(num, typ, msg)
			if n >= 0 {
				v = msg[:n]
			}
		}
		if n < 0 {
			return protowire.ParseError(n)
		}
		msg = msg[n:]
		if err := fn(num, typ, v); err != nil {
			return err
		}
	}
	return nil
}

func importDBIP(r io.Reader, keep func(string) bool) (map[string]*Builder, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = 3
	cr.ReuseRecord = true
	out := map[string]*Builder{}
	for rows := 1; ; rows++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("lists: dbip: %w", err)
		}
		if rows > maxEntries {
			return nil, errTooManyEntries
		}
		line, _ := cr.FieldPos(0)
		name := strings.ToLower(rec[2])
		if !keep(name) {
			continue
		}
		if err := CheckName(name); err != nil {
			return nil, fmt.Errorf("lists: dbip line %d: %w", line, err)
		}
		first, err1 := netip.ParseAddr(rec[0])
		last, err2 := netip.ParseAddr(rec[1])
		if err := errors.Join(err1, err2); err != nil {
			return nil, fmt.Errorf("lists: dbip line %d: %w", line, err)
		}
		b := builderFor(out, name)
		if err := skipMapped(b, b.AddRange(first, last)); err != nil {
			return nil, fmt.Errorf("lists: dbip line %d: %w", line, err)
		}
	}
}

// skipMapped counts an entry refused with [ErrMappedIPv6] in [Stats.Skipped]
// instead of failing the import.
func skipMapped(b *Builder, err error) error {
	if errors.Is(err, ErrMappedIPv6) {
		b.skipped++
		return nil
	}
	return err
}

var errSourceTooLarge = errors.New("lists: source too large")

// capReader fails once more than n bytes were read, so a decompression
// bomb stops instead of filling memory.
type capReader struct {
	r io.Reader
	n int64 // bytes left before the cap
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.n < 0 {
		return 0, errSourceTooLarge
	}
	if int64(len(p)) > c.n+1 {
		p = p[:c.n+1]
	}
	n, err := c.r.Read(p)
	c.n -= int64(n)
	if c.n < 0 {
		return n, errSourceTooLarge
	}
	return n, err
}
