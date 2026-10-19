package transporttest

import "github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"

// Buckets returns bucket padding to sizes, for tests and tools; it panics
// on more than transport.MaxBuckets sizes or one above 65535.
func Buckets(sizes ...int) transport.Padding {
	p := transport.Padding{Mode: transport.PadToBuckets}
	if len(sizes) > transport.MaxBuckets {
		panic("transporttest: too many buckets")
	}
	for i, size := range sizes {
		if size < 0 || size > 0xffff {
			panic("transporttest: bucket size out of range")
		}
		p.Buckets[i] = uint16(size)
	}
	return p
}
